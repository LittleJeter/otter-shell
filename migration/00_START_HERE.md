# Otter Shell — Migration Package

This folder is a complete brief for porting **Otter Shell** from a single-file Claude artifact into a real, publishable repository. It's written to be read by Claude Code (or any engineer) and acted on directly.

## What Otter Shell is

A defensive threat-hunting console: per-platform query authoring across 7 SIEM/EDR products, ATT&CK coverage tracking, CISA KEV exposure scanning, Sigma round-trip, hunt lifecycle, custom enterprise profiles, and a hunt journal with findings, pivots, tuning notes, and IOC enrichment. The full feature inventory is in `../otter-shell-audit.md` (one level up).

## The source artifact

- **File:** `../otter-shell-threat-hunt-console.jsx` (one level up from this folder)
- **Size:** 2,908 lines, single file, JSX + inline CSS
- **Entry:** `export default function OtterShell()` plus two helper components (`EnterpriseBuilder`, `HuntJournal`, `HuntPreview`)
- **Validated:** parses via `@babel/parser` with `plugins:["jsx"]`. Every major pure function has been ad-hoc unit-tested in the chat session that produced it.

Read it before doing anything else. It's the source of truth for behavior.

## Why this port

The artifact has hit its scale ceiling. Three things become possible only after porting:

1. **Real code organization** — split data, lib, and components into modules with proper types, so future features don't keep getting more expensive to add.
2. **A real test suite** — the ad-hoc test harnesses in the chat session catch real bugs; in a repo they'd catch them automatically forever (CI).
3. **Working outside `claude.ai`** — every AI feature relies on the Claude artifact runtime injecting auth into `fetch("https://api.anthropic.com/v1/messages")`. Outside the artifact, this 401s. A tiny backend proxy (FastAPI on Cloud Run, or a Vercel serverless function) holding the key server-side is the unblocker.

## Reading order

| # | File | Purpose |
|---|------|---------|
| 00 | `00_START_HERE.md` | This file. |
| 01 | `01_MIGRATION_PLAN.md` | Phased work plan with acceptance criteria per phase. |
| 02 | `02_ARCHITECTURE.md` | Target file structure, module boundaries, types, state design. |
| 03 | `03_PROXY_CONTRACT.md` | Backend proxy spec — endpoints, auth, rate limiting, deployment. |
|    | `proxy_starter.py`    | Reference FastAPI implementation (~90 lines, working). |
| 04 | `04_TEST_PLAN.md` | Test suite — what to cover on day one, with examples. |
| 05 | `05_DESIGN_PRINCIPLES.md` | The soul. Read this so the honesty layer survives the refactor. |

Start with 05 (it's short and frames every other decision), then read 02, then follow 01 phase by phase, pulling in 03 and 04 as you hit those phases.

## What this brief is not

- It is not a code rewrite. The target structure is specified; producing the actual files is the porting work.
- It is not exhaustive. Where the source artifact's behavior is the spec, the docs point at it rather than redescribing it.
- It is not prescriptive about TypeScript types beyond a recommended starting shape — refine as you go.

## Non-negotiables

These three things must survive the port intact:

1. **The honesty layer.** Every disclaimer, "validated starting point," "best-effort scaffold," "live feed unreachable — model fallback used" message stays. See `05_DESIGN_PRINCIPLES.md`.
2. **The KEV → generate → Sigma loop.** Real CISA feed in, draft detection out, Sigma round-trip. This is the killer chain.
3. **No live SIEM data.** The tool authors and records; it does not run queries or touch production telemetry. That's a deliberate architecture choice — preserve it.

## Day-zero deliverable

By the end of the porting work, a fresh clone should achieve all of:

```bash
git clone <repo>
cd otter-shell
pnpm install
pnpm test       # all green
pnpm dev        # frontend up
cd proxy && uv run main.py   # proxy up
# open http://localhost:5173, generate a hunt, export a Sigma rule
```

…in under 30 minutes on a clean machine.
