"""
Behavioral Trust Score API — Phase 1: Minimalist Secure Fundament
-----------------------------------------------------------------
Security posture:
  • CORS is restricted to an explicit allowlist; wildcard origins are
    intentionally excluded to prevent cross-origin data leakage.
  • All unhandled exceptions are caught by a global handler that returns
    a generic 500 body so raw tracebacks never reach the client.
  • Pydantic v2 models enforce strict type coercion at the boundary;
    malformed payloads are rejected with a 422 before any business logic runs.
  • The nonce field is present at the model layer (Phase 1 foundation);
    stateful anti-replay enforcement (e.g. Redis TTL set) is wired in Phase 2.
"""

import logging
from datetime import datetime, timezone

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trust_api")

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
    allow_headers=["Content-Type"],
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
# Trust evaluation (mock — Phase 1)
# ---------------------------------------------------------------------------
def _evaluate_trust(payload: TrustCheckRequest) -> TrustCheckResponse:
    """
    Phase 1 mock evaluator.

    In Phase 2+ this function will:
      1. Verify the device_integrity_token against the platform attestation
         service (Google Play Integrity / Apple DeviceCheck).
      2. Enforce nonce uniqueness via a short-lived Redis set to block replays.
      3. Feed behavioural signals into a scoring model.
    """
    logger.info(
        "Trust evaluation requested for package=%s", payload.app_package_name
    )

    return TrustCheckResponse(
        status="success",
        trust_score=1.0,
        verdict="CLEAN_ENVIRONMENT",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


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
async def trust_check(payload: TrustCheckRequest) -> TrustCheckResponse:
    """
    Accepts a device attestation payload and returns a trust score verdict.

    - **device_integrity_token**: platform-issued integrity token.
    - **app_package_name**: the calling app's package identifier.
    - **nonce**: random value to prevent replay attacks.
    """
    return _evaluate_trust(payload)


# ---------------------------------------------------------------------------
# Health probe (unauthenticated, safe for load-balancer checks)
# ---------------------------------------------------------------------------
@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok"}
