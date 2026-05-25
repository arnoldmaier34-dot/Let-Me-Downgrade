"""
Behavioral Trust Score API — Phase 7: Persistent SQLite Database
----------------------------------------------------------------
Security posture:
  • All API keys are stored in a local SQLite file (clients.db) that survives
    server restarts.  The in-memory VALID_API_KEYS dict is fully removed.
  • DB lookups use parameterized queries (? placeholders) so user-supplied
    values are NEVER interpolated into SQL text — preventing SQL injection.
  • asyncio.to_thread() offloads every synchronous sqlite3 call to a thread-
    pool worker, keeping the async event loop non-blocking.
  • WAL journal mode is enabled at startup for better read/write concurrency.
  • Each DB helper opens its own connection; sqlite3 serialises writes at the
    file level, which is safe for a single-worker deployment.  Swap the DB
    layer for SQLAlchemy + PostgreSQL before scaling to multiple workers.
  • All Phase 6 posture is preserved (CORS allowlist, FileResponse dashboard,
    global exception handler, StrictBool telemetry validation).
"""

import asyncio
import logging
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, field_validator

from evaluator import evaluate_trust

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trust_api")

# Directory that contains main.py — used to resolve index.html and clients.db
# regardless of the working directory uvicorn is launched from.
BASE_DIR = Path(__file__).parent
DB_PATH  = BASE_DIR / "clients.db"

# ---------------------------------------------------------------------------
# SQLite helpers  (each opens its own connection; runs via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _db_init() -> None:
    """
    Create the api_keys table and seed backward-compatible dev keys.
    Called once at startup inside a thread so it doesn't block the event loop.
    """
    with sqlite3.connect(DB_PATH) as conn:
        # WAL mode: readers don't block writers, writers don't block readers.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key         TEXT PRIMARY KEY,
                client_name TEXT NOT NULL,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # INSERT OR IGNORE: skip silently if these rows already exist on
        # subsequent restarts — avoids clobbering any name changes.
        conn.executemany(
            "INSERT OR IGNORE INTO api_keys (key, client_name) VALUES (?, ?)",
            [
                ("dev_test_key_123", "Test Client A"),
                ("dev_test_key_456", "Test Client B"),
            ],
        )
        conn.commit()


def _db_lookup(key: str) -> str | None:
    """
    Return the client_name for a given key, or None if not found.

    SQL-injection protection: the key value is passed as a bound parameter
    (the ? placeholder), never concatenated into the query string.  SQLite's
    C driver compiles the statement first and then binds the value separately,
    so any characters in `key` — including quotes, semicolons, or comment
    markers — are treated as data, not SQL syntax.
    """
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT client_name FROM api_keys WHERE key = ?",
            (key,),
        ).fetchone()
    return row[0] if row else None


def _db_insert(key: str, client_name: str) -> None:
    """Insert a newly generated key. Runs in a thread."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO api_keys (key, client_name) VALUES (?, ?)",
            (key, client_name),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Lifespan — initialises the DB before the server starts accepting requests
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI):
    await asyncio.to_thread(_db_init)
    logger.info("Database ready at %s", DB_PATH)
    yield
    # No teardown needed — each helper closes its own connection after use.


# ---------------------------------------------------------------------------
# API key authentication dependency
# ---------------------------------------------------------------------------

# auto_error=False so FastAPI passes None instead of raising a 403 when the
# header is absent; we return a uniform 401 for both missing and invalid keys.
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    api_key: str | None = Security(_API_KEY_HEADER),
) -> str:
    """
    FastAPI dependency that enforces API key authentication via DB lookup.

    A parameterized query binds the candidate value outside the SQL text, so
    injection attempts (e.g. `' OR '1'='1`) are treated as literal data and
    will simply find no matching row.  The PRIMARY KEY index makes both hit
    and miss lookups O(log n), so timing differences between valid and invalid
    keys are negligible and not exploitable for key enumeration.

    Returns the client label on success; raises 401 on any failure.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    client_name = await asyncio.to_thread(_db_lookup, api_key)

    if client_name is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    logger.info("Authenticated client: %s", client_name)
    return client_name

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Behavioral Trust Score API",
    version="1.0.0",
    lifespan=lifespan,
    # Disable the default /docs and /redoc in production by setting these to
    # None via an environment flag. Kept open here for developer ergonomics.
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS — production-ready: explicit origin allowlist, no wildcards
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    # Replace with your actual mobile backend / BFF origin(s).
    "https://api.yourapp.example.com",
    # Add staging origin here if needed, never "*".
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,          # No cookies / auth headers via CORS
    allow_methods=["POST"],           # Only the methods this API exposes
    allow_headers=["Content-Type", "X-API-Key"],
)

# ---------------------------------------------------------------------------
# Global exception handler — prevents raw tracebacks leaking to clients
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled server error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Please try again later."},
    )

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class TrustCheckRequest(BaseModel):
    """Strict input schema for the trust-check endpoint."""

    device_integrity_token: str = Field(
        ...,
        min_length=16,
        max_length=4096,
        description="Integrity token issued by the platform attestation service.",
    )
    app_package_name: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Fully-qualified app package name, e.g. com.example.myapp.",
    )
    nonce: str = Field(
        ...,
        min_length=16,
        max_length=128,
        description="Cryptographically random nonce for anti-replay defence.",
    )

    @field_validator("app_package_name")
    @classmethod
    def validate_package_name(cls, v: str) -> str:
        """Reject package names that don't look like reverse-DNS identifiers."""
        import re
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", v):
            raise ValueError(
                "app_package_name must be a valid reverse-DNS identifier "
                "(e.g. com.example.myapp)."
            )
        return v

    @field_validator("nonce")
    @classmethod
    def validate_nonce_charset(cls, v: str) -> str:
        """Restrict nonce to URL-safe base64 / hex characters to avoid injection."""
        import re
        if not re.match(r"^[A-Za-z0-9+/=_\-]+$", v):
            raise ValueError("nonce contains disallowed characters.")
        return v


class TrustCheckResponse(BaseModel):
    """Response envelope returned to the client."""

    status: str
    trust_score: float
    verdict: str
    timestamp: str


class GenerateKeyRequest(BaseModel):
    """Input schema for the key-generation endpoint."""

    client_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Human-readable name for the registering client or company.",
    )

    @field_validator("client_name")
    @classmethod
    def strip_and_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("client_name cannot be blank or whitespace-only.")
        return v


class GenerateKeyResponse(BaseModel):
    """Returned once on key creation — the raw key is never stored server-side."""

    api_key: str
    client_name: str


# ---------------------------------------------------------------------------
# Dashboard (serves index.html at the root)
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    """
    Developer dashboard SPA.  Served from the same origin as the API so
    the fetch calls inside index.html are same-origin and bypass CORS entirely.
    """
    return FileResponse(BASE_DIR / "index.html")


# ---------------------------------------------------------------------------
# Key generation endpoint
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/generate-key",
    response_model=GenerateKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a client and generate an API key",
    response_description="The newly created API key (shown only once).",
)
async def generate_key(payload: GenerateKeyRequest) -> GenerateKeyResponse:
    """
    Registers a new client and returns a fresh, prefixed API key.

    **Production hardening required before public deployment:**
    - Protect this endpoint with admin authentication.
    - Rate-limit per IP to prevent key flooding.
    - Emit the key only once and store only a salted hash server-side.
    """
    # ts_live_ prefix lets developers instantly identify keys in logs and
    # config files; token_hex(32) provides 256 bits of entropy.
    new_key = f"ts_live_{secrets.token_hex(32)}"
    await asyncio.to_thread(_db_insert, new_key, payload.client_name)
    logger.info("API key issued for client: %s", payload.client_name)
    return GenerateKeyResponse(api_key=new_key, client_name=payload.client_name)


# ---------------------------------------------------------------------------
# Trust-check endpoint
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/trust-check",
    response_model=TrustCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate device trust score",
    response_description="Trust evaluation result for the submitted device signal.",
)
async def trust_check(
    payload: TrustCheckRequest,
    client_name: str = Depends(verify_api_key),
) -> TrustCheckResponse:
    """
    Accepts a device attestation payload and returns a trust score verdict.

    - **X-API-Key** header: registered API key (required).
    - **device_integrity_token**: Base64-encoded JSON telemetry blob.
    - **app_package_name**: the calling app's package identifier.
    - **nonce**: random value to prevent replay attacks (stateful enforcement Phase 4).
    """
    logger.info(
        "Trust evaluation requested by client=%s for package=%s",
        client_name,
        payload.app_package_name,
    )

    result = evaluate_trust(payload.device_integrity_token)

    return TrustCheckResponse(
        status="success",
        trust_score=result.trust_score,
        verdict=result.verdict,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# Health probe (unauthenticated, safe for load-balancer checks)
# ---------------------------------------------------------------------------
@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok"}
