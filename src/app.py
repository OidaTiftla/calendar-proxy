import os
import socket
import base64
import ipaddress
import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse, HTMLResponse, PlainTextResponse, FileResponse
import aiohttp

# Configure logging based on environment
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
DISABLE_ACCESS_LOG = os.getenv("DISABLE_ACCESS_LOG", "true").lower() in ("true", "1", "yes")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(levelname)s:%(name)s:%(message)s'
)

# Reduce uvicorn access log verbosity in production
if DISABLE_ACCESS_LOG:
    logging.getLogger("uvicorn.access").disabled = True
elif LOG_LEVEL in ("WARNING", "ERROR"):
    # Reduce uvicorn access log level but keep it enabled
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# Optional Redis rate limiting (redis>=4.x with asyncio support)
try:
    import redis.asyncio as aioredis
except Exception:
    aioredis = None

#######################
# Config via env vars #
#######################

# User-Agent that will be used when fetching upstream (server-side only)
UPSTREAM_USER_AGENT = os.getenv("UPSTREAM_USER_AGENT", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15")
# Comma-separated allowed hostnames (empty = only IP checks). Use domains only.
ALLOWED_HOSTS = {h.strip().lower() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()}
# Token(s) accepted (comma-separated) - long random strings. For production, use DB/secret store.
TOKENS = {t.strip() for t in os.getenv("PROXY_TOKENS", "").split(",") if t.strip()}
# Redis connection URL (optional)
REDIS_URL = os.getenv("REDIS_URL", "").strip() or None
# Rate limit: requests per minute per token (default 60)
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))

# Timeouts and response size caps
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "10"))
READ_TIMEOUT = float(os.getenv("READ_TIMEOUT", "20"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", str(5 * 1024 * 1024)))  # 5 MB default

# Allowed content types (comma-separated)
ALLOWED_CONTENT_TYPES = [ct.strip().lower() for ct in os.getenv("ALLOWED_CONTENT_TYPES", "text/calendar,text/plain,application/octet-stream").split(",") if ct.strip()]

#######################
# Logging helpers     #
#######################

def sanitize_url_for_logging(url: str) -> str:
    """
    Sanitize URLs for logging by masking sensitive parts.
    """

    # Bypass masking for non-production environments
    if not DISABLE_ACCESS_LOG:
        return url

    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)

        # Keep scheme and hostname for debugging
        if not parsed.netloc:
            return "***invalid-url***"

        # Mask the path while keeping useful structure
        path = parsed.path
        if path:
            # Mask path that might contain sensitive data
            path = "/***masked***"

        # Remove query parameters and fragments that might contain secrets
        sanitized = urlunparse((parsed.scheme, parsed.netloc, path, '', '', ''))
        return sanitized

    except Exception:
        # If URL parsing fails, return a safe fallback
        return "***invalid-url***"

app = FastAPI(title="Stateless Calendar Proxy")

@app.on_event("startup")
async def startup_event():
    """Initialize any startup tasks."""
    logging.info("Calendar Proxy starting up")
    # Do initial cleanup of in-memory rate limiter
    if not redis_client:
        await _cleanup_inmem_limits()

# Redis client (optional)
redis_client = None
if REDIS_URL:
    if not aioredis:
        raise RuntimeError("REDIS_URL set but redis.asyncio not available. Install redis>=4.x")
    redis_client = aioredis.from_url(REDIS_URL)

# In-memory fallback limiter (not suitable for multi-worker production)
_inmem_limits = {}
_inmem_lock = asyncio.Lock()
_cleanup_counter = 0  # Counter to trigger periodic cleanup

async def _cleanup_inmem_limits():
    """Clean up old entries from in-memory rate limiter to prevent memory leaks."""
    async with _inmem_lock:
        current_time = asyncio.get_event_loop().time()
        current_min = int(current_time // 60)
        # Remove entries older than 2 minutes (120 seconds) to be safe
        # We keep current minute and previous minute, clean up anything older
        cutoff_min = current_min - 1

        keys_to_remove = [
            token for token, (minute, _) in _inmem_limits.items() if minute < cutoff_min
        ]

        for token in keys_to_remove:
            del _inmem_limits[token]

        if keys_to_remove:
            logging.debug(f"Cleaned up {len(keys_to_remove)} old rate limit entries")

def _decode_b64_url(b64s: str) -> str:
    try:
        # Accept urlsafe base64 and missing padding
        s = b64s.replace("-", "+").replace("_", "/")
        padding = "=" * (-len(s) % 4)
        return base64.b64decode(s + padding).decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="bad base64 url")


def _host_allowed(hostname: str) -> bool:
    if not ALLOWED_HOSTS:
        return True
    return hostname.lower() in ALLOWED_HOSTS


async def _resolve_and_check(hostname: str):
    """Resolve hostname to IPs and ensure none are private/loopback/reserved."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except Exception:
        raise HTTPException(status_code=400, detail="cannot resolve hostname")

    ip_addrs = {info[4][0] for info in infos}
    for ip_str in ip_addrs:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast:
            raise HTTPException(status_code=403, detail="resolved IP not allowed")
    # Ok if we reach here
    return list(ip_addrs)


def _require_token(token: str):
    if not TOKENS:
        # In dev, you might allow empty; in prod require tokens
        raise HTTPException(status_code=500, detail="server not configured with tokens")
    if token not in TOKENS:
        raise HTTPException(status_code=401, detail="invalid token")


async def _rate_limit_check(token: str):
    """
    Rate limiting per token. Prefer Redis (atomic across workers) when configured.
    Otherwise uses an in-memory sliding window (not suitable for multi-worker).
    """
    key = f"rl:{token}"
    if redis_client:
        now_min = int(asyncio.get_event_loop().time() // 60)
        k = f"{key}:{now_min}"
        # INCR with expire of 70s -> counts per minute
        count = await redis_client.incr(k)
        if count == 1:
            await redis_client.expire(k, 70)
        if count > RATE_LIMIT_PER_MIN:
            raise HTTPException(status_code=429, detail="rate limit exceeded")
    else:
        # Simple in-memory limiter
        async with _inmem_lock:
            global _cleanup_counter
            now_min = int(asyncio.get_event_loop().time() // 60)
            v = _inmem_limits.get(token)
            if not v or v[0] != now_min:
                _inmem_limits[token] = (now_min, 1)
            else:
                if v[1] + 1 > RATE_LIMIT_PER_MIN:
                    raise HTTPException(status_code=429, detail="rate limit exceeded")
                _inmem_limits[token] = (v[0], v[1] + 1)

            # Increment counter and check for cleanup
            _cleanup_counter += 1
            should_cleanup = _cleanup_counter % 10 == 0 and len(_inmem_limits) > 10

        # Do cleanup outside the lock to avoid blocking other requests
        # Use counter instead of token hash to ensure cleanup always happens eventually
        if should_cleanup:
            await _cleanup_inmem_limits()


# Main subscription endpoint
@app.get("/sub/{token}/{b64url:path}/{name}.ics")
async def sub_calendar(token: str, b64url: str, name: str, request: Request, ua: Optional[str] = None):
    """
    Main subscription endpoint.
    - token: secret token in the URL
    - b64url: URL-safe base64 (no padding) of full upstream URL
    - name: final name (without .ics)
    - optional query param 'ua' to set upstream User-Agent
    """
    # Check token and rate limits
    _require_token(token)
    await _rate_limit_check(token)

    # Decode and validate target URL
    target = _decode_b64_url(b64url)
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="invalid target URL")

    # Validate hostname
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="invalid host")

    # Enforce allowlist if configured
    if not _host_allowed(hostname):
        raise HTTPException(status_code=403, detail="target host not allowed")

    # DNS -> IP resolution & SSRF protection
    await _resolve_and_check(hostname)

    # Build safe upstream headers; do not forward client headers
    upstream_ua = ua if ua else UPSTREAM_USER_AGENT
    headers = {
        "User-Agent": upstream_ua,
        "Accept": "text/calendar, text/plain, */*"
    }

    # Set up session
    timeout = aiohttp.ClientTimeout(sock_connect=CONNECT_TIMEOUT, sock_read=READ_TIMEOUT)
    session = aiohttp.ClientSession(timeout=timeout)
    resp = None
    streaming_started = False

    try:
        # Send upstream request
        logging.debug(f"Making request to upstream: {sanitize_url_for_logging(target)}")
        resp = await session.get(target, headers=headers, allow_redirects=False)
        logging.debug(f"Received response from upstream: status={resp.status}, content_type={resp.headers.get('content-type', 'unknown')}")
        status = resp.status

        # Handle redirects - these usually indicate auth required or wrong URL
        if status in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            sanitized_location = sanitize_url_for_logging(location) if location else "unknown"
            raise HTTPException(
                status_code=400,
                detail=f"Upstream returned redirect (status {status}). This usually means the URL requires authentication or is not a direct calendar feed. Redirect to: {sanitized_location}"
            )

        # Handle client errors
        if status >= 400:
            error_text = ""
            try:
                # Try to read a small amount of error text
                error_bytes = await resp.content.read(1024)
                error_text = error_bytes.decode('utf-8', errors='ignore')[:200]
            except:
                pass

            raise HTTPException(
                status_code=502,
                detail=f"Upstream error {status}: {error_text}" if error_text else f"Upstream returned status {status}"
            )

        # Check content type
        content_type = resp.headers.get("content-type", "").lower()
        if not any(ct in content_type for ct in ALLOWED_CONTENT_TYPES):
            raise HTTPException(
                status_code=400,
                detail=f"Upstream returned unexpected content type: {content_type}. Expected one of: {', '.join(ALLOWED_CONTENT_TYPES)}."
            )

        # Forward only a few safe headers
        response_headers = {}
        if "content-type" in resp.headers:
            response_headers["content-type"] = resp.headers["content-type"]
        if "content-disposition" in resp.headers:
            response_headers["content-disposition"] = resp.headers["content-disposition"]

        logging.debug(f"About to create StreamingResponse with status={status}, headers={response_headers}")

        # Mark that we're starting streaming (cleanup will be handled by stream_generator)
        streaming_started = True

        # Stream with size cap
        sent = 0
        async def stream_generator():
            nonlocal sent
            chunk_size = 16 * 1024
            try:
                logging.debug(f"Starting to stream content, chunk_size={chunk_size}")
                chunk_count = 0
                async for chunk in resp.content.iter_chunked(chunk_size):
                    if not chunk:
                        continue
                    chunk_count += 1
                    sent += len(chunk)
                    logging.debug(f"Streaming chunk {chunk_count}, size={len(chunk)}, total_sent={sent}")
                    if sent > MAX_RESPONSE_BYTES:
                        # Stop streaming - we can't raise HTTPException after response started
                        # Log the error for debugging
                        logging.warning(f"Upstream response too large: {sent} bytes > {MAX_RESPONSE_BYTES}")
                        return
                    yield chunk
                logging.debug(f"Streaming completed successfully, total_chunks={chunk_count}, total_bytes={sent}")
            except aiohttp.ClientConnectionError as e:
                # Connection lost during streaming - log and stop gracefully
                # Can't raise HTTPException after response has started
                logging.warning(f"Connection lost while streaming: {e} (type: {type(e).__name__})")
                return
            except Exception as e:
                # Other errors during streaming - log and stop
                logging.error(f"Error during streaming: {e} (type: {type(e).__name__})")
                return
            finally:
                # Clean up resources when streaming is done
                try:
                    if resp and not resp.closed:
                        await resp.close()
                    if session and not session.closed:
                        await session.close()
                    logging.debug("Cleaned up aiohttp session and response")
                except Exception as e:
                    logging.error(f"Error cleaning up aiohttp resources: {e}")

        return StreamingResponse(stream_generator(), status_code=status, headers=response_headers)
    except aiohttp.ClientError as e:
        raise HTTPException(status_code=502, detail=f"upstream fetch failed: {e}")
    except HTTPException:
        # Re-raise our own HTTPExceptions
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"unexpected error: {e}")
    finally:
        # Clean up resources if streaming hasn't started yet (error conditions)
        # Note: if streaming started successfully, cleanup happens in stream_generator's finally block
        if not streaming_started:
            try:
                if resp and not resp.closed:
                    await resp.close()
                    logging.debug("Cleaned up response in main finally block")
                if session and not session.closed:
                    await session.close()
                    logging.debug("Cleaned up session in main finally block")
            except Exception as e:
                logging.error(f"Error in main cleanup finally block: {e}")
# Health check endpoint
@app.get("/healthz")
def health():
    return {"status": "ok"}


# Serve a small static index.html UI if present (file saved alongside app)
@app.get("/", response_class=HTMLResponse)
async def index():
    try:
        here = os.path.dirname(__file__)
        with open(os.path.join(here, "index.html"), "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return PlainTextResponse("Index not found", status_code=404)

# Serve static files from the 'static' directory
@app.get("/static/{path:path}", response_class=FileResponse)
async def serve_static(path: str):
    here = os.path.dirname(__file__)
    return FileResponse(os.path.join(here, "static", path))
