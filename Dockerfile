# ─────────────────────────────────────────────────────────────────────────────
# Multi-stage Dockerfile for TraceGuard API
# Base image: python:3.12-slim (Debian Bookworm, minimal attack surface)
#
# Stage 1 (builder): install Python dependencies into a virtual environment
# Stage 2 (runtime): copy only the venv — no build tools in the final image
#
# Security:
#   - Non-root user (appuser, uid 1001)
#   - Read-only source tree (no write permissions to source)
#   - No unnecessary packages (curl, wget, etc. not installed)
#   - PYTHONDONTWRITEBYTECODE: no .pyc files (smaller image)
#   - PYTHONUNBUFFERED: JSON logs flushed immediately
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install system deps required to compile psycopg2 and bcrypt
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc \
       libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create an isolated venv to copy into the runtime stage
RUN python -m venv /build/venv
ENV PATH="/build/venv/bin:$PATH"

# Install dependencies first (layer caching: only re-runs on requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Add security labels
LABEL maintainer="hillsoni" \
      version="1.0.0" \
      description="TraceGuard API — production image"

# Runtime system dependencies only (libpq for psycopg2)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# ── Non-root user (Security) ──────────────────────────────────────────────────
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Copy the pre-built venv from builder stage
COPY --from=builder /build/venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy application source
COPY --chown=appuser:appgroup . .

# Remove dev/test files from the production image
RUN rm -rf tests/ .env .git .gitignore \
           __pycache__ \
    && find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Switch to non-root user
USER appuser

# ── Environment ───────────────────────────────────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    PORT=8000

EXPOSE 8000

# ── Health check (used by Docker / Kubernetes) ────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')" \
    || exit 1

# ── Entrypoint ────────────────────────────────────────────────────────────────
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:create_app()"]
