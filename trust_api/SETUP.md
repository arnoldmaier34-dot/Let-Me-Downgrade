# Trust Score API — Local Setup Guide

## Prerequisites

- Python 3.10 or newer
- `pip` (bundled with Python)

---

## Step-by-step

### 1. Clone / enter the project directory

```bash
cd trust_api
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate.bat    # Windows CMD
# .venv\Scripts\Activate.ps1   # Windows PowerShell
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the server with Uvicorn

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

`--reload` enables hot-reloading during development. **Remove it in production.**

---

## Verify the API is running

### Health probe

```bash
curl http://127.0.0.1:8000/health
# → {"status":"ok"}
```

### Trust-check endpoint

```bash
curl -X POST http://127.0.0.1:8000/api/v1/trust-check \
  -H "Content-Type: application/json" \
  -d '{
    "device_integrity_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock",
    "app_package_name": "com.example.myapp",
    "nonce": "c2VjdXJlUmFuZG9tTm9uY2UxMjM0"
  }'
```

Expected response:

```json
{
  "status": "success",
  "trust_score": 1.0,
  "verdict": "CLEAN_ENVIRONMENT",
  "timestamp": "2026-05-25T00:00:00.000000+00:00"
}
```

### Interactive API docs

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in your browser.

---

## Production checklist (before going live)

| Item | Action |
|---|---|
| CORS origins | Replace the placeholder list in `main.py → ALLOWED_ORIGINS` |
| Docs endpoints | Set `docs_url=None, redoc_url=None` in `FastAPI(...)` |
| TLS | Run behind a reverse proxy (nginx / Caddy) that terminates HTTPS |
| Uvicorn workers | Use `--workers N` (N = 2 × CPU cores + 1) without `--reload` |
| Secrets | Load tokens / keys from environment variables, never hard-coded |
