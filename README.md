# Calendar-Proxy

A tiny proxy to make browser-only calendar links (for example Office 365 `reachcalendar.ics`) usable by calendar clients that can't authenticate or set custom User-Agent headers.

## Self-hosting

Run a single container (secure defaults):

```bash
docker run -d --restart=unless-stopped \
    --name calendar-proxy \
    -p 8000:8000 \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --memory=512m \
    --cpus=0.5 \
    --tmpfs=/tmp:noexec,nosuid,size=100m \
    --tmpfs=/var/tmp:noexec,nosuid,size=50m \
    --env-file .env \
    calendar-proxy
```

`.env` (example, keep this file private):

```
PROXY_TOKENS=longtoken123
ALLOWED_HOSTS=example.com,calendar.example.org
LOG_LEVEL=WARNING
DISABLE_ACCESS_LOG=true
```

Notes:
- Prefer `--env-file` over inline `-e` to avoid leaking secrets in process lists or shell history.
- Container runs as non-root user (UID 1000) for enhanced security.
- Hardened with `--read-only`, capability drops, `no-new-privileges`, resource limits, and temporary filesystems.
- Use `REDIS_URL` when running multiple containers for shared rate-limiting.
- For production, consider using `docker-compose.production.yml` which includes additional security measures.

## Required / recommended env vars

- `PROXY_TOKENS` (required): comma-separated secret tokens used in subscription URLs.
- `ALLOWED_HOSTS` (recommended): comma-separated allowed upstream hostnames.
- `REDIS_URL` (optional): `redis://...` for cross-process rate limiting.
- `RATE_LIMIT_PER_MIN` (default `60`): per-token request limit per minute.
- `UPSTREAM_USER_AGENT` (default: Safari on macOS): User-Agent header sent to upstream servers.
- `MAX_RESPONSE_BYTES` (default: `5242880` bytes / 5MB): maximum response size to prevent memory exhaustion.
- `CONNECT_TIMEOUT` (default: `10` seconds): timeout for establishing upstream connections.
- `READ_TIMEOUT` (default: `20` seconds): timeout for reading upstream response data.
- `ALLOWED_CONTENT_TYPES` (default: `text/calendar,text/plain,application/octet-stream`): comma-separated allowed upstream content types.
- `LOG_LEVEL` (default: `INFO`): application log level (DEBUG, INFO, WARNING, ERROR).
- `DISABLE_ACCESS_LOG` (default: `true`): set to `false` to enable logging of URLs and accesses.

## Build from source

```bash
docker build -t calendar-proxy .
```

## Production deployment

For production use, a hardened `docker-compose.production.yml` is provided:

```bash
# Copy and customize the production compose file
cp docker-compose.production.yml docker-compose.yml

# Create secure environment file
echo "PROXY_TOKENS=$(openssl rand -hex 40)" > .env

# Deploy with enhanced security
docker-compose up -d
```

The production configuration includes:

- **Non-root execution**: Runs as UID/GID 1000
- **Read-only filesystem**: Prevents runtime modifications
- **Capability restrictions**: Drops all capabilities except essential ones
- **Resource limits**: Memory (512MB) and CPU (0.5 cores) constraints
- **No new privileges**: Prevents privilege escalation
- **Temporary filesystems**: Secure `/tmp` and `/var/tmp` mounts
- **Enhanced logging**: Production-ready log levels

## How the proxy works (short)

- Endpoint: `GET /sub/{token}/{b64url}/{name}.ics`
  - `token`: secret in the path.
  - `b64url`: URL-safe base64 (no padding) of the full upstream URL.
  - `name.ics`: final filename for clients.
  - Optional `ua` query param: override User-Agent used to fetch upstream.

Security & runtime behaviour:
- **Container security**: Runs as non-root user, read-only filesystem, dropped capabilities, resource limits.
- Validates `token` against `PROXY_TOKENS`.
- Resolves `b64url` hostname and refuses private/loopback/link-local/multicast/reserved IPs (SSRF protection).
- Enforces `ALLOWED_HOSTS` when set.
- Validates upstream content types against `ALLOWED_CONTENT_TYPES`.
- Per-token rate limiting (Redis if `REDIS_URL` set, otherwise in-process fallback with automatic cleanup).
- Streams upstream response, enforces timeouts and a maximum response byte cap.
- Strips client cookies and Authorization; forwards only safe upstream headers (e.g. `Content-Type`, `Content-Disposition`).
- Sanitizes URLs in logs to prevent exposure of sensitive information (when `DISABLE_ACCESS_LOG=true`).

## Why macOS Calendar can't directly subscribe to Microsoft Office 365 links (very short)

1) Office 365 shared URLs are browser-centric
- Shared `reachcalendar.ics` links are designed to be opened by a browser, which may provide cookies or other auth automatically; macOS Calendar does not.

2) User-Agent restrictions
- Microsoft checks User-Agent and rejects unsupported clients. Requests from macOS `CalendarAgent` often get a "Outlook is not supported on this browser" page instead of an ICS.

3) No auth flow support
- Some shared calendars require Microsoft authentication (cookies/OAuth). macOS Calendar cannot perform those interactive browser flows.

Workarounds: use this proxy (fetch with a browser-like UA), import into a service that fetches server-side, or download & import manually.

## Quick examples

Generate a URL-safe base64 without padding (shell):

```bash
python - <<'PY'
import base64
u='https://example.com/cal.ics'
print(base64.urlsafe_b64encode(u.encode()).decode().rstrip('='))
PY
```

Or without Python (using base64 + tr):

```bash
echo -n 'https://example.com/cal.ics' | base64 -w0 | tr '+/' '-_' | tr -d '='
```

Subscription URL:

```
https://proxy.example.com/sub/<token>/<b64url>/Work.ics
```

Open `http://<host>:8000/` in a browser to use the included `index.html` UI for building links.

## Endpoints

- `GET /sub/{token}/{b64url}/{name}.ics` — subscription proxy endpoint.
- `GET /healthz` — health check JSON response.
- `GET /version` — version information JSON response (includes version, build date, and commit).
- `GET /` — web UI for building calendar subscription URLs.
- `GET /static/{path}` — static files (CSS, etc.) for the web UI.

If you want an admin UI for token management, Redis-backed caching, or a `docker-compose.yml` with Redis, tell me which and I'll add it.
