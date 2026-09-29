# gunicorn.conf.py — Production WSGI server configuration.
#
# Run with: gunicorn --config gunicorn.conf.py "app:create_app()"
#
# Worker tuning rationale:
#   workers  = (2 × CPU cores) + 1  — standard formula for I/O-bound apps
#   threads  = 4                     — handles concurrent requests per worker
#   timeout  = 30 s                  — guards against slow MongoDB queries
#   graceful_timeout = 25 s          — allows in-flight requests to complete
#
# Adjust GUNICORN_WORKERS via environment variable for container deployments.

import multiprocessing
import os

# ── Binding ───────────────────────────────────────────────────────────────────
bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"

# ── Workers ───────────────────────────────────────────────────────────────────
workers = int(os.getenv("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "sync"     # Use "gevent" or "gthread" for high-concurrency workloads
threads = int(os.getenv("GUNICORN_THREADS", 4))

# ── Timeouts ─────────────────────────────────────────────────────────────────
timeout = 30
graceful_timeout = 25
keepalive = 5

# ── Logging ───────────────────────────────────────────────────────────────────
# Pipe gunicorn access/error logs to stdout so they flow to the container's
# log driver alongside the app's JSON logs.
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "warning").lower()
access_log_format = (
    '{"time": "%(t)s", "method": "%(m)s", "path": "%(U)s", '
    '"status": %(s)s, "duration_ms": %(D)s, "remote": "%(h)s"}'
)

# ── Security ──────────────────────────────────────────────────────────────────
# Prevent Slowloris attacks. Default: 0 (disabled).
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# ── Process naming ────────────────────────────────────────────────────────────
proc_name = "traceguard-api"

# ── Lifecycle hooks ───────────────────────────────────────────────────────────
def on_starting(server):
    server.log.info("TraceGuard API starting up...")

def worker_abort(worker):
    worker.log.warning(f"Worker {worker.pid} aborted — possible timeout.")
