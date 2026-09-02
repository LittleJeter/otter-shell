"""
Otter Shell proxy — FastAPI reference implementation.

Spec: migration/03_PROXY_CONTRACT.md
Run:  uv run main.py   (or: uvicorn main:app --port 8080)

Requires env:
    ANTHROPIC_API_KEY                  (required)
    OTTER_SHELL_FRONTEND_ORIGIN        (required in prod; defaults to localhost in dev)
    OTTER_SHELL_DEV                    (set to "1" to allow CORS wildcard for local dev)
    OTTER_SHELL_MAX_TOKENS             (optional, default 1500)
    OTTER_SHELL_MODEL                  (optional, default claude-sonnet-4-5)

Dependencies (pyproject.toml):
    fastapi >= 0.115
    httpx   >= 0.27
    uvicorn >= 0.30
    pydantic >= 2.6
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import defaultdict, deque
from typing import Deque

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------- config ----------
API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not API_KEY:
    raise RuntimeError("ANTHROPIC_API_KEY is required")

FRONTEND_ORIGIN = os.environ.get("OTTER_SHELL_FRONTEND_ORIGIN", "http://localhost:5173")
DEV_MODE = os.environ.get("OTTER_SHELL_DEV", "") == "1"
MAX_TOKENS_CAP = int(os.environ.get("OTTER_SHELL_MAX_TOKENS", "1500"))
MODEL = os.environ.get("OTTER_SHELL_MODEL", "claude-sonnet-4-5")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
WEB_SEARCH_TOOL = {"type": "web_search_20250305", "name": "web_search"}

START_TIME = time.time()

# ---------- logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("otter-shell-proxy")

# ---------- rate limiting (per-IP token bucket, in-memory) ----------
RATE_WINDOWS = [(60, 20), (3600, 200)]  # (seconds, max_requests)
_buckets: dict[str, Deque[float]] = defaultdict(deque)


def _hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def _rate_limited(ip: str) -> tuple[bool, int]:
    key = _hash_ip(ip)
    now = time.time()
    bucket = _buckets[key]
    # prune oldest entries beyond the largest window
    longest = max(w for w, _ in RATE_WINDOWS)
    while bucket and now - bucket[0] > longest:
        bucket.popleft()
    for window, limit in RATE_WINDOWS:
        if sum(1 for t in bucket if now - t <= window) >= limit:
            return True, window
    bucket.append(now)
    return False, 0


# ---------- app ----------
app = FastAPI(title="Otter Shell Proxy", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if DEV_MODE else [FRONTEND_ORIGIN],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)


class ClaudeRequest(BaseModel):
    system: str = Field(..., min_length=1, max_length=8000)
    user: str = Field(..., min_length=1, max_length=8000)
    enableWebSearch: bool = False
    maxTokens: int = Field(1000, ge=1, le=MAX_TOKENS_CAP)


@app.get("/health")
def health() -> dict:
    return {"ok": True, "model": MODEL, "uptime_s": int(time.time() - START_TIME)}


@app.get("/version")
def version() -> dict:
    return {"version": "0.1.0", "spec": "otter-shell/proxy/v1"}


@app.post("/api/claude")
async def claude(req: ClaudeRequest, request: Request, response: Response) -> dict:
    client_ip = request.client.host if request.client else "unknown"

    limited, window = _rate_limited(client_ip)
    if limited:
        response.headers["Retry-After"] = str(window)
        raise HTTPException(status_code=429, detail=f"rate limit ({window}s window)")

    body = {
        "model": MODEL,
        "max_tokens": min(req.maxTokens, MAX_TOKENS_CAP),
        "system": req.system,
        "messages": [{"role": "user", "content": req.user}],
    }
    if req.enableWebSearch:
        body["tools"] = [WEB_SEARCH_TOOL]

    headers = {
        "x-api-key": API_KEY,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }

    t0 = time.time()
    try:
        async with httpx.AsyncClient(timeout=120.0) as http:
            r = await http.post(ANTHROPIC_URL, json=body, headers=headers)
    except httpx.HTTPError as e:
        log.error("upstream error: %s", e)
        raise HTTPException(status_code=502, detail="upstream request failed")

    latency_ms = int((time.time() - t0) * 1000)

    if r.status_code >= 400:
        log.warning(
            "upstream %d ip=%s ws=%s latency=%dms",
            r.status_code, _hash_ip(client_ip), req.enableWebSearch, latency_ms,
        )
        raise HTTPException(status_code=502, detail=f"upstream returned {r.status_code}")

    data = r.json()
    usage = data.get("usage", {})
    log.info(
        "ok ip=%s ws=%s in=%s out=%s latency=%dms",
        _hash_ip(client_ip),
        req.enableWebSearch,
        usage.get("input_tokens"),
        usage.get("output_tokens"),
        latency_ms,
    )
    # Pass through upstream JSON unchanged — frontend already handles this shape.
    return data


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
