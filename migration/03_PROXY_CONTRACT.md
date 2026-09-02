# Proxy Contract

Why this exists, what it does, what it doesn't, and how to deploy it. Reference implementation in `proxy_starter.py`.

## Why

Every AI feature in Otter Shell calls `https://api.anthropic.com/v1/messages` *with no API key*. Inside Claude artifacts, the runtime injects auth. Outside, those calls 401. The proxy is the smallest piece of code that makes the rest of the tool deployable: it holds the Anthropic API key server-side and forwards a tightly-scoped request shape from the frontend.

This is a thin proxy, not an LLM gateway. It does not implement caching, conversation memory, agent loops, tool execution, or model routing.

## What the frontend sends

```
POST /api/claude
Content-Type: application/json

{
  "system": "You are a senior threat-hunt engineer...",   // string, required, <= 8000 chars
  "user": "Generate a hunt for T1059.001...",             // string, required, <= 8000 chars
  "enableWebSearch": true,                                // boolean, optional, default false
  "maxTokens": 1000                                       // number, optional, default 1000, hard cap 1500
}
```

That's the whole API. Three optional knobs (`enableWebSearch`, `maxTokens`, plus future model selection). The frontend does not get to set arbitrary tools, system prompts of unlimited length, message arrays, or the model string.

## What the proxy returns

The Anthropic API's `messages` response body, unmodified — same shape the artifact already handles today:

```json
{
  "id": "msg_...",
  "type": "message",
  "role": "assistant",
  "content": [
    { "type": "text", "text": "{\"hunt\": {...}}" }
  ],
  "model": "claude-sonnet-4-20250514",
  "stop_reason": "end_turn",
  "usage": { "input_tokens": 234, "output_tokens": 412 }
}
```

The frontend extracts `data.content.filter(b => b.type === "text").map(b => b.text).join("\n")` then `JSON.parse(...)`s the embedded object — same as the artifact. Do not transform the response shape; that lets the frontend keep working unchanged.

## What the proxy does on every request

1. **CORS preflight** — `OPTIONS /api/claude` returns the configured allow-origin (the frontend domain in prod, `*` in local dev only).
2. **Request validation** — Pydantic model with strict bounds: `system` and `user` length-capped, `maxTokens` clamped to `[1, 1500]`, `enableWebSearch` boolean.
3. **Rate limiting** — per-IP token bucket. Default: 20 requests/minute, 200 requests/hour. In-memory is fine for v0.1; swap for Redis if multi-instance.
4. **Model construction** — fixed model string (`claude-sonnet-4-5` or whatever the deploy targets). Frontend cannot choose.
5. **Tool construction** — if `enableWebSearch`, attach `[{"type":"web_search_20250305","name":"web_search"}]`; otherwise omit. Frontend cannot attach arbitrary tools.
6. **Forward** — `POST` to `https://api.anthropic.com/v1/messages` with the server's `x-api-key` header.
7. **Pass-through** — return the upstream JSON verbatim with HTTP status 200 on success. On upstream non-2xx, return status `502 Bad Gateway` with a `{ "error": "..." }` body.
8. **Log** — request timestamp, source IP (hashed), `enableWebSearch` flag, input/output token counts, latency, status. **Do not log prompts.** They may contain user IOCs, internal hostnames, or other sensitive triage data.

## What the proxy does NOT do

- It does not accept arbitrary headers from the frontend.
- It does not pass through the frontend's `Authorization` header (if any).
- It does not implement streaming. Otter Shell's generator is request/response.
- It does not authenticate end-users in v0.1. Rate limit by IP. (Add Clerk/Auth0 in front later if needed.)
- It does not retry on upstream failure. Surface the error to the frontend.

## Auth

`ANTHROPIC_API_KEY` environment variable. Never read from a request header, never written to logs, never returned in any response body. The proxy refuses to start if the env var is missing.

## CORS

Single allowed origin via `OTTER_SHELL_FRONTEND_ORIGIN` env var. Local dev uses `http://localhost:5173`. Production uses the frontend's deploy URL. Wildcard is allowed only when `NODE_ENV=development` (or `OTTER_SHELL_DEV=1`).

## Rate limiting

Per-IP token bucket with two tiers:

| Window | Limit |
|--------|-------|
| 60s    | 20    |
| 3600s  | 200   |

When exceeded, return `429 Too Many Requests` with `Retry-After` header. The frontend already has user-friendly error handling for non-2xx responses (the existing generator's `catch` clause).

In-memory dict keyed by `hashlib.sha256(ip.encode()).hexdigest()` is enough for v0.1. The hash is only to avoid plaintext IPs in process memory; the bucket is fully ephemeral and resets on restart.

## Cost guardrails

- `maxTokens` capped at 1500 server-side regardless of what the frontend sends.
- Input length capped at 8000 chars per field (system + user).
- Optional monthly spend cap: track total `output_tokens` in memory (or a sqlite file) and refuse new requests once a configurable threshold is hit. Recommended default: $35/month equivalent (~3M output tokens at Sonnet pricing — verify against current pricing at deploy time).

## Deployment options

Pick one. All three work; recommendations in order of simplicity:

**Vercel serverless function** — drop `proxy/api/claude.py` (or `.ts`) into a Vercel project, set env vars, done. Best for first deploy and tightest frontend/proxy coupling. Limitation: ephemeral instances mean in-memory rate limiting resets often; use Upstash Redis if you grow.

**Google Cloud Run** — `gcloud run deploy` from the `proxy/` folder. Best for an existing GCP-centric stack. Auto-scaling, generous free tier, simple env-var management via Secret Manager.

**Fly.io** — `fly launch` then `fly deploy`. Best if you want the proxy and frontend co-located in low-latency regions. Slightly more setup than Vercel.

For any of them, set:

```
ANTHROPIC_API_KEY=sk-ant-...
OTTER_SHELL_FRONTEND_ORIGIN=https://otter-shell.yourdomain.com
OTTER_SHELL_MAX_TOKENS=1500
OTTER_SHELL_MONTHLY_TOKEN_CAP=3000000
```

## Health check

`GET /health` returns `{"ok": true, "model": "claude-sonnet-4-5", "uptime_s": 1234}`. Used by deploy platform health probes and by a future "proxy reachable?" indicator in the frontend.

## Versioning

`GET /version` returns `{"version": "0.1.0", "spec": "otter-shell/proxy/v1"}`. The frontend can warn if the spec doesn't match its expectations.

## Security posture

- API key only in env, never in code, never in logs.
- Strict request validation rejects oversized or malformed payloads at 400.
- Prompt content never logged.
- CORS locked to the frontend origin in production.
- No path traversal or file IO surface — the proxy has no file endpoints.
- No SSRF surface — the proxy only talks to `api.anthropic.com`, hard-coded.
- Rate limiting on every endpoint.
- HTTPS terminated by the deploy platform (Vercel/Cloud Run/Fly handle this).
- TLS 1.2+ to the upstream Anthropic API (default for Python `httpx` and Node `fetch`).

See `proxy_starter.py` for the working reference implementation.
