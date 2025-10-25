# Build stage - for CSS generation using Node.js and Tailwind CLI
FROM --platform=linux/amd64 node:22.21.0-alpine AS builder

WORKDIR /app

# renovate: datasource=npm depName=tailwindcss
ARG TAILWINDCSS_VERSION=4.1.16
# renovate: datasource=npm depName=@tailwindcss/cli
ARG TAILWINDCSS_CLI_VERSION=4.1.16

# Install Tailwind CSS v4 following official documentation
RUN npm install tailwindcss@${TAILWINDCSS_VERSION} @tailwindcss/cli@${TAILWINDCSS_CLI_VERSION}

# Build Tailwind CSS
COPY src/index.html src/input.css ./
RUN mkdir -p static && npx @tailwindcss/cli -i ./input.css --content ./index.html -o ./static/style.css --minify

# Runtime stage - minimal Python environment
FROM python:3.13.7-slim AS runtime

# Build arguments for metadata
ARG VERSION=dev
ARG BUILD_DATE
ARG COMMIT

# OCI Image Labels for better metadata
LABEL org.opencontainers.image.title="Calendar Proxy" \
      org.opencontainers.image.description="A secure proxy service that makes browser-only calendar links (like Office 365 shared calendars) accessible to calendar clients that can't authenticate or handle custom headers" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.vendor="OidaTiftla" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/OidaTiftla/calendar-proxy"

# Set environment variables for runtime access
ENV APP_VERSION=${VERSION} \
    APP_BUILD_DATE=${BUILD_DATE} \
    APP_COMMIT=${COMMIT}

# Create non-root user for security
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

# Install only runtime Python dependencies (no build tools)
COPY src/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt

# Create app directory and set ownership
WORKDIR /app
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Copy application files (as non-root user)
COPY --chown=appuser:appuser src/app.py src/index.html ./

# Copy built CSS from builder stage (as non-root user)
COPY --from=builder --chown=appuser:appuser /app/static ./static

# Runtime configuration
ENV PYTHONUNBUFFERED=1
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=5 \
    CMD curl -f http://localhost:8000/healthz

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
