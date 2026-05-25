"""
Behavioral Trust Score API — Phase 3: Monetization & Access Control
--------------------------------------------------------------------
Security posture:
  • API key authentication via X-API-Key header guards the scored endpoint.
    Missing or unrecognised keys return 401 before any evaluation logic runs.
  • Keys are compared with secrets.compare_digest (constant-time) to prevent
    timing-oracle attacks; all keys in the registry are always checked so the
    iteration count does not reveal whether any key was close to valid.
  • CORS allows X-API-Key in preflight so browser-based clients (Swagger UI,
    web dashboards) can authenticate correctly alongside mobile clients.
  • Remaining posture from Phase 2 is unchanged (allowlist CORS, global
    exception handler, StrictBool telemetry validation, separate evaluator).
"""

import logging
import secrets
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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

# ---------------------------------------------------------------------------
# API key registry (MVP: hardcoded — move to database for production)
# ---------------------------------------------------------------------------
# Keys map  api_key_value → human-readable client label.
# The label is used for audit logging and will drive per-client billing in
# Phase 4.  Never log or return the raw key value itself.
VALID_API_KEYS: dict[str, str] = {
    "dev_test_key_123": "Test Client A",
    "dev_test_key_456": "Test Client B",
}

# auto_error=False so FastAPI passes None instead of raising a 403 when the
# header is absent; we raise our own 401 in verify_api_key below.
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    api_key: str | None = Security(_API_KEY_HEADER),
) -> str:
    """
    FastAPI dependency that enforces API key authentication.

    Iterates every registered key with secrets.compare_digest so the loop
    runs in constant time regardless of which key matches (or doesn't),
    preventing timing-oracle attacks from probing the key space.

    Returns the client label on success; raises 401 on any failure.
    """
    candidate = api_key or ""
    matched_client: str | None = None

    for key, client in VALID_API_KEYS.items():
        # Always compare all entries — no early exit — to keep timing uniform.
        if secrets.compare_digest(candidate.encode(), key.encode()):
            matched_client = client

    if matched_client is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    logger.info("Authenticated client: %s", matched_client)
    return matched_client

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Behavioral Trust Score API",
    version="1.0.0",
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


# ---------------------------------------------------------------------------
# Endpoint
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
