# TraceGuard API

A production-grade, enterprise-ready REST API built with Flask, providing JWT-authenticated request auditing, structured JSON logging, and a layered clean architecture. Fully containerised and OWASP-hardened.

---

## Architecture Overview

```
+------------------------------------------------------------------+
|                       HTTP Clients                               |
+----------------------------+-------------------------------------+
                             |
                   +---------v----------+
                   |   Gunicorn (WSGI)  |  workers = 2xCPU+1
                   +---------+----------+
                             |
          +------------------v------------------------------------------+
          |                     Flask App                               |
          |                                                             |
          |  +------------+  +------------------+                      |
          |  | Middleware  |  |  Error Handlers  |                      |
          |  | Request ID  |  |  (centralised)   |                      |
          |  | Sec Headers |  +------------------+                      |
          |  | Audit Logs  |                                            |
          |  +------------+                                             |
          |                                                             |
          |  +--------------------------------------------------------+ |
          |  |               Blueprints (Routes)                      | |
          |  |    /auth      /api      /logs      /health             | |
          |  +---------------------------+----------------------------+ |
          |                              |                              |
          |  +---------------------------v----------------------------+ |
          |  |               Service Layer                            | |
          |  |          AuthService        LogService                 | |
          |  +-------+-----------------------+------------------------+ |
          |          |                       |                          |
          |  +-------v--------+    +---------v--------+                |
          |  |  PostgreSQL    |    |    MongoDB        |                |
          |  |  (Users,Tokens)|    |  (Audit Logs)    |                |
          |  +----------------+    +------------------+                |
          |                                                             |
          |                 Redis (Rate Limiter)                       |
          +-------------------------------------------------------------+
```

### Layered Architecture

| Layer | Responsibility |
|---|---|
| Routes / Controllers | HTTP parsing, status codes, JSON serialisation only |
| Schemas | Input validation - raises ValidationError on bad data |
| Service Layer | Business logic, DB operations, token management |
| Models | SQLAlchemy (PostgreSQL) and dataclass (MongoDB) definitions |
| Middleware | Cross-cutting: request ID, security headers, timing |
| Extensions | Flask extension singletons (db, jwt, limiter, mongo) |

---

## Repository Structure

```
traceguard-api/
+-- app/
|   +-- __init__.py          # Application factory (create_app)
|   +-- config.py            # DevelopmentConfig / ProductionConfig / TestingConfig
|   +-- exceptions.py        # Custom exception hierarchy
|   +-- extensions.py        # Flask extension singletons
|   +-- logging_config.py    # Structured JSON logging setup
|   +-- middleware.py        # Request ID, security headers, access logging
|   +-- models/
|   |   +-- user.py          # SQLAlchemy User model (bcrypt)
|   |   +-- revoked_token.py # JWT blocklist model
|   |   +-- log_entry.py     # MongoDB audit log dataclass
|   +-- schemas/
|   |   +-- auth.py          # RegisterSchema / LoginSchema validators
|   +-- services/
|   |   +-- auth_service.py  # Authentication business logic
|   |   +-- log_service.py   # Request audit log persistence & retrieval
|   +-- routes/
|   |   +-- auth.py          # /auth blueprint
|   |   +-- protected.py     # /api blueprint (JWT-gated)
|   |   +-- logs.py          # /logs blueprint (paginated log retrieval)
|   |   +-- health.py        # /health blueprint (liveness + readiness)
|   +-- utils/
|       +-- sanitizer.py     # Log sanitization (CWE-117 prevention)
+-- tests/
|   +-- conftest.py          # Pytest fixtures
|   +-- test_auth.py         # Auth endpoint tests
|   +-- test_sanitizer.py    # Sanitizer unit tests
|   +-- test_health.py       # Health check tests
+-- migrations/              # Alembic migrations
+-- Dockerfile               # Multi-stage production image
+-- docker-compose.yml       # Full stack (API + PG + Mongo + Redis)
+-- .dockerignore
+-- .env.example
+-- gunicorn.conf.py         # Production WSGI configuration
+-- requirements.txt
+-- requirements-dev.txt
+-- config.py                # Root shim (Alembic compatibility)
+-- run.py                   # Development entrypoint
```

---

## Local Manual Setup

### Prerequisites
- Python 3.12+, PostgreSQL 16+, MongoDB 7+, Redis 7+

### Steps

```bash
# 1. Clone and enter the project
git clone https://github.com/hillsoni/traceguard-api.git
cd traceguard-api

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements-dev.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env - fill in DB_PASSWORD, JWT_SECRET_KEY, MONGO_URI, etc.
# Generate a strong JWT key:
python -c "import secrets; print(secrets.token_hex(32))"

# 5. Run database migrations
flask db upgrade

# 6. Start the development server
python run.py
# API available at http://localhost:5000
```

---

## Docker & Docker Compose Setup

```bash
# Copy and fill in the environment template
cp .env.example .env

# Build and start all services (API + PostgreSQL + MongoDB + Redis)
docker compose up --build

# Run migrations inside the running container
docker compose exec api flask db upgrade

# Verify the API is healthy
curl http://localhost:8000/health/ready

# View structured JSON logs
docker compose logs -f api

# Stop all services and remove volumes
docker compose down -v
```

---

## API Reference

All endpoints return JSON. Error responses follow a consistent envelope:

```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable description.",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

The `X-Request-ID` header is returned on every response for distributed tracing.

---

### POST /auth/register

Create a new user account. Rate limit: 5/hour.

**Request body:**
```json
{
  "email": "alice@example.com",
  "username": "alice",
  "password": "SecurePass1",
  "confirm": "SecurePass1"
}
```

**Response 201:**
```json
{
  "message": "Account created successfully.",
  "user": { "id": 1, "email": "alice@example.com", "username": "alice" },
  "access_token": "<JWT>",
  "refresh_token": "<JWT>"
}
```

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","username":"alice","password":"SecurePass1","confirm":"SecurePass1"}'
```

---

### POST /auth/login

Authenticate and receive tokens. Rate limit: 10/hour.

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"SecurePass1"}'
```

**Response 200:**
```json
{ "access_token": "<JWT>", "refresh_token": "<JWT>" }
```

---

### POST /auth/refresh

Exchange a refresh token for a new access token.

```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Authorization: Bearer <refresh_token>"
```

---

### POST /auth/logout

Revoke the current access token.

```bash
curl -X POST http://localhost:8000/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

---

### GET /api/me

Return current user identity. Requires access token.

```bash
curl http://localhost:8000/api/me \
  -H "Authorization: Bearer <access_token>"
```

---

### GET /logs/

Paginated audit log list. Requires access token.

| Query Param | Type | Default | Description |
|---|---|---|---|
| page | int | 1 | Page number |
| page_size | int | 50 | Records per page (max 200) |
| method | string | - | Filter by HTTP method |
| status_code | int | - | Filter by response status |

```bash
curl "http://localhost:8000/logs/?method=POST&page=1&page_size=20" \
  -H "Authorization: Bearer <access_token>"
```

---

### GET /logs/<log_id>

Full detail for a single log entry by MongoDB ObjectId.

```bash
curl http://localhost:8000/logs/64f1abc123... \
  -H "Authorization: Bearer <access_token>"
```

---

### GET /health/live | GET /health/ready

No authentication required. For load balancers and container probes.

```bash
curl http://localhost:8000/health/ready
# {"status": "ok", "checks": {"postgres": "ok", "mongodb": "ok"}}
```

---

## Common Error Codes

| HTTP | error Code | Cause |
|---|---|---|
| 400 | VALIDATION_ERROR | Missing/invalid field |
| 401 | AUTHENTICATION_ERROR | Invalid credentials |
| 401 | TOKEN_EXPIRED | JWT has expired |
| 401 | TOKEN_REVOKED | Token was logged out |
| 401 | AUTHORIZATION_REQUIRED | No token provided |
| 404 | NOT_FOUND | Endpoint or resource missing |
| 409 | CONFLICT | Email/username already registered |
| 429 | RATE_LIMIT_EXCEEDED | Too many requests |
| 500 | INTERNAL_ERROR | Unexpected server error |
| 503 | SERVICE_UNAVAILABLE | Database unreachable |

---

## Security Architecture

| Finding | Severity | Fix Applied |
|---|---|---|
| MD5 password hashing | CRITICAL | bcrypt cost=12 with automatic salting |
| Hardcoded JWT secret in VCS | CRITICAL | Env var, fail-fast at startup |
| Passwords logged to MongoDB | CRITICAL | Sanitizer redacts sensitive fields |
| KeyError crash on bad input | CRITICAL | Schema validators use .get() |
| Missing security headers | HIGH | X-Content-Type-Options, X-Frame-Options, CSP, etc. |
| No CORS configuration | HIGH | Flask-Cors with explicit origins allowlist |
| Duplicate error handler | HIGH | Single centralised AppError handler |
| Dual Limiter instances | HIGH | Single Limiter, per-route decorators |
| 12-char password max | HIGH | Policy: 8-128 chars |
| User enumeration | HIGH | Generic "Invalid email or password" for all auth failures |
| debug=True hardcoded | HIGH | DEBUG driven by config class only |
| No startup secret validation | HIGH | ProductionConfig.validate() at create_app() |
| print() statements | MEDIUM | Structured JSON logging throughout |
| Log injection CWE-117 | MEDIUM | CRLF stripped from all log values |
| No request ID / tracing | MEDIUM | UUID X-Request-ID per request |
| KeyError in to_dict | MEDIUM | LogEntry dataclass + asdict() |
| No DB error handling | MEDIUM | SQLAlchemyError caught, rolled back |
| Wrong dotenv package | LOW | Removed dotenv==0.9.9, kept python-dotenv |
| No log pagination | LOW | page + page_size on GET /logs/ |
| Exception object in MongoDB | LOW | Stored as str(exc) |

---

## Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests with coverage
pytest tests/ -v --cov=app --cov-report=term-missing

# Run a specific file
pytest tests/test_auth.py -v

# Run tests matching a keyword
pytest -k "enumeration or sanitizer" -v

# HTML coverage report
pytest --cov=app --cov-report=html
```

Tests use TestingConfig (SQLite in-memory, rate limits disabled) — no
external services required. MongoDB calls are patched with unittest.mock.

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| FLASK_ENV | No | development | development / testing / production |
| SECRET_KEY | Prod | random | Flask session signing key |
| JWT_SECRET_KEY | Yes | - | JWT signing key (min 32 chars) |
| DB_URL | Yes | - | PostgreSQL connection string |
| MONGO_URI | Yes | mongodb://localhost:27017/flaskdb | MongoDB URI |
| REDIS_URL | No | redis://localhost:6379/0 | Redis for rate limiter |
| CORS_ORIGINS | No | http://localhost:3000 | Comma-separated allowed origins |
| LOG_LEVEL | No | INFO | Python logging level |
| PORT | No | 5000/8000 | Bind port (dev/prod) |
| GUNICORN_WORKERS | No | 2xCPU+1 | Worker count |
| GUNICORN_THREADS | No | 4 | Threads per worker |
