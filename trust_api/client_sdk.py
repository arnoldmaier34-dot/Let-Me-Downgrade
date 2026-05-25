#!/usr/bin/env python3
"""
Trust Score API — Client SDK Prototype
---------------------------------------
Simulates the future Android SDK: collects device state, builds a signed
telemetry payload, and submits it to the Trust Score API.

Usage — interactive (prompts for each flag):
    python client_sdk.py

Usage — scripted / CI (all flags provided; no prompts):
    python client_sdk.py --sandbox --no-zygisk --no-lsposed
    python client_sdk.py --sandbox --zygisk   --no-lsposed
    python client_sdk.py --sandbox --no-zygisk --lsposed
"""

import argparse
import base64
import json
import re
import secrets
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is not installed.  Run: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration defaults  (override via CLI flags for other environments)
# ---------------------------------------------------------------------------
DEFAULT_API_URL = "http://127.0.0.1:8000"
DEFAULT_API_KEY = "dev_test_key_123"
DEFAULT_PACKAGE = "com.example.myapp"

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
class _C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

_VERDICT_COLOUR: dict[str, str] = {
    "CLEAN_ENVIRONMENT":          _C.GREEN,
    "MODIFIED_BUT_SAFE":          _C.YELLOW,
    "HIGH_RISK_TAMPERING":        _C.RED,
    "CRITICAL_SYSTEM_COMPROMISE": _C.RED,
    "INVALID_TELEMETRY":          _C.MAGENTA,
}

def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)

def _visible_len(s: str) -> int:
    return len(_strip_ansi(s))

def _pad(content: str, width: int) -> str:
    """Right-pad `content` to exactly `width` *visible* characters."""
    return content + " " * max(0, width - _visible_len(content))

def _score_bar(score: float, width: int = 12) -> str:
    filled = round(score * width)
    return (
        _C.GREEN + "█" * filled
        + _C.DIM   + "░" * (width - filled)
        + _C.RESET
    )

# ---------------------------------------------------------------------------
# Telemetry helpers
# ---------------------------------------------------------------------------
def build_token(sandbox: bool, zygisk: bool, lsposed: bool) -> str:
    """Base64-encodes the telemetry dict — this becomes device_integrity_token."""
    payload = {
        "sandbox_intact":           sandbox,
        "zygisk_denylist_active":   zygisk,
        "lsposed_injecting_target": lsposed,
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()

def generate_nonce() -> str:
    """Cryptographically secure URL-safe nonce (32 visible chars, no padding)."""
    return secrets.token_urlsafe(24)

# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------
def send_request(
    token: str,
    nonce: str,
    package: str,
    api_key: str,
    base_url: str,
) -> tuple[dict, int]:
    """POSTs the trust-check payload. Returns (response_json, elapsed_ms)."""
    url = f"{base_url.rstrip('/')}/api/v1/trust-check"
    t0 = time.perf_counter()
    resp = requests.post(
        url,
        json={
            "device_integrity_token": token,
            "app_package_name":       package,
            "nonce":                  nonce,
        },
        headers={
            "Content-Type": "application/json",
            "X-API-Key":    api_key,
        },
        timeout=10,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000)
    resp.raise_for_status()
    return resp.json(), elapsed_ms

# ---------------------------------------------------------------------------
# Result renderer
# ---------------------------------------------------------------------------
def print_result(
    data: dict,
    elapsed_ms: int,
    sandbox: bool,
    zygisk: bool,
    lsposed: bool,
) -> None:
    W = 52  # inner visible width between the box walls

    verdict = data.get("verdict", "UNKNOWN")
    score   = float(data.get("trust_score", 0.0))
    colour  = _VERDICT_COLOUR.get(verdict, _C.WHITE)

    def box_row(content: str) -> str:
        return f"{_C.CYAN}│{_C.RESET} {_pad(content, W - 1)}{_C.CYAN}│{_C.RESET}"

    def kv(label: str, value: str) -> str:
        label_col = f"{_C.DIM}{label:<20}{_C.RESET}"
        return box_row(f"{label_col} {value}")

    def flag(label: str, value: bool) -> str:
        v = f"{_C.GREEN}✓  True{_C.RESET}" if value else f"{_C.RED}✗  False{_C.RESET}"
        return kv(label, v)

    border   = _C.CYAN + "─" * W + _C.RESET
    sep      = f"{_C.CYAN}├{border}┤{_C.RESET}"
    title    = _pad(f"{_C.BOLD}  TRUST SCORE API — RESULT{_C.RESET}", W + 1)

    print()
    print(f"{_C.CYAN}┌{border}┐{_C.RESET}")
    print(f"{_C.CYAN}│{_C.RESET}{title}{_C.CYAN}│{_C.RESET}")
    print(sep)
    print(kv("Status",    f"{_C.GREEN}{data.get('status', '?')}{_C.RESET}"))
    print(kv("Score",     f"{_score_bar(score)}  {_C.BOLD}{score:.1f}{_C.RESET}"))
    print(kv("Verdict",   f"{colour}{_C.BOLD}{verdict}{_C.RESET}"))
    print(kv("Timestamp", f"{_C.DIM}{data.get('timestamp', '?')}{_C.RESET}"))
    print(kv("Latency",   f"{_C.DIM}{elapsed_ms} ms{_C.RESET}"))
    print(sep)
    print(box_row(f"{_C.DIM}  Telemetry submitted{_C.RESET}"))
    print(sep)
    print(flag("sandbox_intact",           sandbox))
    print(flag("zygisk_denylist_active",   zygisk))
    print(flag("lsposed_injecting_target", lsposed))
    print(f"{_C.CYAN}└{border}┘{_C.RESET}")
    print()

# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------
def _ask_bool(prompt: str) -> bool:
    while True:
        ans = input(f"  {prompt} [y/n]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Please enter 'y' or 'n'.")

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Trust Score API — client SDK prototype",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  Interactive:              python client_sdk.py\n"
            "  Clean environment:        python client_sdk.py --sandbox --no-zygisk --no-lsposed\n"
            "  Rooted but isolated:      python client_sdk.py --sandbox --zygisk   --no-lsposed\n"
            "  Active LSPosed hook:      python client_sdk.py --sandbox --no-zygisk --lsposed\n"
            "  Critical compromise:      python client_sdk.py --no-sandbox --no-zygisk --no-lsposed\n"
        ),
    )
    # sandbox_intact
    g1 = p.add_mutually_exclusive_group()
    g1.add_argument("--sandbox",    dest="sandbox", action="store_true",  help="sandbox_intact = True")
    g1.add_argument("--no-sandbox", dest="sandbox", action="store_false", help="sandbox_intact = False")
    # zygisk_denylist_active
    g2 = p.add_mutually_exclusive_group()
    g2.add_argument("--zygisk",     dest="zygisk",  action="store_true",  help="zygisk_denylist_active = True")
    g2.add_argument("--no-zygisk",  dest="zygisk",  action="store_false", help="zygisk_denylist_active = False")
    # lsposed_injecting_target
    g3 = p.add_mutually_exclusive_group()
    g3.add_argument("--lsposed",    dest="lsposed", action="store_true",  help="lsposed_injecting_target = True")
    g3.add_argument("--no-lsposed", dest="lsposed", action="store_false", help="lsposed_injecting_target = False")

    # Keep defaults explicitly None so we can detect "not set → ask interactively"
    p.set_defaults(sandbox=None, zygisk=None, lsposed=None)

    p.add_argument("--package", default=DEFAULT_PACKAGE, metavar="PKG",
                   help=f"App package name  (default: {DEFAULT_PACKAGE})")
    p.add_argument("--url",     default=DEFAULT_API_URL, metavar="URL",
                   help=f"API base URL      (default: {DEFAULT_API_URL})")
    p.add_argument("--api-key", default=DEFAULT_API_KEY, metavar="KEY",
                   help="Value for X-API-Key header")
    return p

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    args = _build_parser().parse_args()

    # Interactive mode when any boolean flag was not supplied on the CLI.
    interactive = any(v is None for v in (args.sandbox, args.zygisk, args.lsposed))

    if interactive:
        print(f"\n{_C.CYAN}{_C.BOLD}  Trust Score API — Device Simulator{_C.RESET}")
        print(f"{_C.DIM}  Simulating Android device telemetry report{_C.RESET}\n")
        sandbox = args.sandbox if args.sandbox is not None else _ask_bool(
            "Is the sandbox intact?              (sandbox_intact)          "
        )
        zygisk  = args.zygisk  if args.zygisk  is not None else _ask_bool(
            "Is the Zygisk DenyList active?      (zygisk_denylist_active)  "
        )
        lsposed = args.lsposed if args.lsposed is not None else _ask_bool(
            "Is LSPosed injecting this target?   (lsposed_injecting_target)"
        )
    else:
        sandbox, zygisk, lsposed = args.sandbox, args.zygisk, args.lsposed

    token = build_token(sandbox, zygisk, lsposed)
    nonce = generate_nonce()

    if interactive:
        print(f"\n{_C.DIM}  Encoding telemetry …  nonce={nonce[:8]}…{_C.RESET}")
        print(f"{_C.DIM}  Contacting {args.url} …{_C.RESET}")

    try:
        data, elapsed_ms = send_request(token, nonce, args.package, args.api_key, args.url)
    except requests.exceptions.ConnectionError:
        print(f"\n{_C.RED}  ERROR: Cannot reach {args.url}{_C.RESET}")
        print(f"{_C.DIM}  Is the server running?  cd trust_api && uvicorn main:app --reload{_C.RESET}\n")
        sys.exit(1)
    except requests.exceptions.HTTPError as exc:
        print(f"\n{_C.RED}  HTTP {exc.response.status_code}: {exc.response.text.strip()}{_C.RESET}\n")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"\n{_C.RED}  ERROR: Request timed out after 10 s.{_C.RESET}\n")
        sys.exit(1)

    print_result(data, elapsed_ms, sandbox, zygisk, lsposed)


if __name__ == "__main__":
    main()
