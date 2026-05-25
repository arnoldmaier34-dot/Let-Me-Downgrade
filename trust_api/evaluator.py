"""
Trust Score Evaluator — Phase 2
--------------------------------
Decodes a Base64-encoded JSON telemetry token and applies deterministic
scoring rules based on the device's execution environment signals.

Scoring priority (highest severity evaluated first):
  1. sandbox_intact is False          → 0.0  CRITICAL_SYSTEM_COMPROMISE
  2. lsposed_injecting_target is True → 0.1  HIGH_RISK_TAMPERING
  3. zygisk_denylist_active is True   → 0.8  MODIFIED_BUT_SAFE
  4. No risk signals                  → 1.0  CLEAN_ENVIRONMENT

Any token that cannot be decoded or fails schema validation returns
0.0 / INVALID_TELEMETRY so the caller always gets a typed result — never
an uncaught exception.
"""

import base64
import json
import logging
from dataclasses import dataclass

from pydantic import BaseModel, StrictBool, ValidationError

logger = logging.getLogger("trust_api.evaluator")


# ---------------------------------------------------------------------------
# Telemetry schema
# ---------------------------------------------------------------------------
class TelemetryPayload(BaseModel):
    """
    Strict schema for fields extracted from the device telemetry token.

    StrictBool rejects JSON strings ("true") and integers (1) — only
    actual JSON booleans are accepted, preventing coercion-based bypasses.
    """

    sandbox_intact: StrictBool
    zygisk_denylist_active: StrictBool
    lsposed_injecting_target: StrictBool


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class EvaluationResult:
    trust_score: float
    verdict: str


# ---------------------------------------------------------------------------
# Internal decoder
# ---------------------------------------------------------------------------
def _decode_telemetry(token: str) -> TelemetryPayload:
    """
    Decodes a Base64-encoded JSON blob into a validated TelemetryPayload.

    Tolerates missing padding characters (some Base64 encoders omit them).
    Raises ValueError / ValidationError on any malformed input so the
    caller's except block can produce a unified INVALID_TELEMETRY result.
    """
    # Re-add stripped padding; Python's b64decode requires it.
    missing_padding = len(token) % 4
    if missing_padding:
        token += "=" * (4 - missing_padding)

    raw_bytes = base64.b64decode(token, validate=True)
    payload_dict = json.loads(raw_bytes.decode("utf-8"))

    # model_validate raises ValidationError on type mismatches or missing keys.
    return TelemetryPayload.model_validate(payload_dict)


# ---------------------------------------------------------------------------
# Public evaluation entry point
# ---------------------------------------------------------------------------
def evaluate_trust(device_integrity_token: str) -> EvaluationResult:
    """
    Decodes the device telemetry token and scores the execution environment.

    Never raises — all decoding and validation errors are caught and mapped
    to INVALID_TELEMETRY (0.0) so the HTTP layer always receives a typed
    result rather than an unhandled exception.
    """
    try:
        telemetry = _decode_telemetry(device_integrity_token)
    except (ValueError, ValidationError, Exception) as exc:
        # Log the reason server-side; return a safe result to the caller.
        logger.warning("Malformed telemetry token — cannot decode: %s", exc)
        return EvaluationResult(trust_score=0.0, verdict="INVALID_TELEMETRY")

    logger.info(
        "Telemetry decoded | sandbox_intact=%s | zygisk_denylist=%s | lsposed_injecting=%s",
        telemetry.sandbox_intact,
        telemetry.zygisk_denylist_active,
        telemetry.lsposed_injecting_target,
    )

    # --- Rule 1: Sandbox breach is an absolute disqualifier -------------------
    # The app's isolated storage has been compromised. No further analysis is
    # meaningful; the device must be treated as fully untrusted.
    if not telemetry.sandbox_intact:
        return EvaluationResult(
            trust_score=0.0,
            verdict="CRITICAL_SYSTEM_COMPROMISE",
        )

    # --- Rule 2: Active Xposed/LSPosed hooking of this specific app -----------
    # A module is instrumenting the app's runtime right now. This is direct,
    # targeted code manipulation — the highest in-process threat level.
    if telemetry.lsposed_injecting_target:
        return EvaluationResult(
            trust_score=0.1,
            verdict="HIGH_RISK_TAMPERING",
        )

    # --- Rule 3: Rooted device, but app is on the Zygisk denylist ------------
    # The system is modified, yet the app is correctly isolated from root.
    # Acceptable risk posture for many use cases; caller decides the threshold.
    if telemetry.zygisk_denylist_active:
        return EvaluationResult(
            trust_score=0.8,
            verdict="MODIFIED_BUT_SAFE",
        )

    # --- Rule 4: No risk signals detected ------------------------------------
    return EvaluationResult(trust_score=1.0, verdict="CLEAN_ENVIRONMENT")
