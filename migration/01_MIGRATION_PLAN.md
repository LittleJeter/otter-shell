# Migration Plan

Seven phases. Each phase has a goal, the work to do, and a single acceptance criterion that gates moving on. Phases 1–5 produce a feature-complete local app; Phase 6 puts it online; Phase 7 publishes it.

Estimated effort assumes one engineer (or Claude Code) working focused. Phases 1 and 4 are the biggest.

| Phase | What | Acceptance | Effort |
|-------|------|------------|--------|
| 0 | Repo scaffold | `pnpm dev` shows an empty styled shell | ~1h |
| 1 | Extract data + lib | All `lib/` tests in `04_TEST_PLAN.md` green | ~6h |
| 2 | Build proxy | Frontend `claudeMessages()` succeeds against local proxy | ~2h |
| 3 | Build the store | `tests/store/*` green | ~3h |
| 4 | Extract components | Manual smoke test: feature parity with the artifact | ~8h |
| 5 | Tests + CI | CI green on `main` | ~2h |
| 6 | Deploy | Public URL works end-to-end | ~2h |
| 7 | Publish | Fresh clone runs in <30 min | ~2h |

## Phase 0 — Repo scaffold

**Goal:** an empty React + TS + Vite project with the styling system in place.

**Work:**

1. `pnpm create vite@latest otter-shell -- --template react-ts`
2. Add dependencies: `zustand`, `@types/react`, `vitest`, `@testing-library/react`, `@testing-library/jest-dom`, `jsdom`.
3. Configure ESLint + Prettier with sensible defaults (no need to argue over rules).
4. Add `tsconfig.json` with `"strict": true`, `"noUncheckedIndexedAccess": true`.
5. Add path alias `@/*` -> `src/*` in tsconfig and vite config.
6. Create the folder tree from `02_ARCHITECTURE.md` (empty files are fine).
7. Copy the CSS from the artifact's `CSS` const into `src/styles/otter-shell.css`. Import it from `src/main.tsx`.
8. Stub `App.tsx` to render `<div className="qr-root"><h1>Otter Shell</h1></div>`.

**Acceptance:** `pnpm dev` opens at `localhost:5173` and shows the title styled with the design palette (background `#0a0e12`, amber accents).

## Phase 1 — Extract data and lib

**Goal:** every pure constant and helper lives in the right module with proper types and unit tests.

**Work:**

1. Move static data into `src/data/*.ts` per the architecture file map.
2. Define types in `src/types/index.ts` per `02_ARCHITECTURE.md`.
3. Annotate the 18 hunts in `src/data/hunts.ts` to satisfy the `Hunt` type — pre-lifecycle (defaults applied at store creation).
4. Move pure functions into `src/lib/*.ts`. The list, in dependency order:
   - `lib/lifecycle.ts` (`withLifecycle`, `todayISO`)
   - `lib/atomic.ts` (`atomicUrl`, `techIdOf`)
   - `lib/download.ts` (`downloadText`)
   - `lib/sigma/parse.ts` + `lib/sigma/emit.ts` + `lib/sigma/builders.ts`
   - `lib/kev.ts`
   - `lib/nav.ts`
   - `lib/lint.ts`
   - `lib/enrichment.ts`
   - `lib/markdown.ts`
   - `lib/normalize.ts`
5. As each `lib/*.ts` lands, write its test in `tests/lib/*.test.ts` (see `04_TEST_PLAN.md`).
6. Populate fixtures: `tests/fixtures/curated-queries.ts` (from the 18 hunts), `tests/fixtures/kev-rows.ts`, `tests/fixtures/sigma-samples.yml`.

**Acceptance:** `pnpm test` runs every test in `tests/lib/` and they pass. Bonus: `pnpm typecheck` clean.

**Risks:**

- The Sigma YAML subset parser in the artifact (`parseYamlSubset`) is hand-rolled and quirky. Port it verbatim first, then add the round-trip and sample tests to lock its behavior before any refactoring.
- The KEV ransomware regex is `/^known$/i` (anchored). Easy to "clean up" to `/known/i` and silently match "Unknown" — the test in `kev.test.ts` catches this; keep the test.
- The lint literal-stripping order matters (escapes before strings, then strings, then regex). Port verbatim.

## Phase 2 — Build the proxy

**Goal:** a working `/api/claude` endpoint locally so the frontend's generator can call it.

**Work:**

1. Create `proxy/` folder with `pyproject.toml` and `main.py` from `proxy_starter.py`.
2. Add `proxy/README.md` with the run command and required env vars.
3. Create `src/api/claude.ts` per the snippet in `02_ARCHITECTURE.md`.
4. Add `VITE_PROXY_URL` to `.env.local` (default `http://localhost:8080`).
5. Smoke-test: write a tiny throwaway component that calls `claudeMessages({ system: "Reply with 'pong'", user: "ping", maxTokens: 50 })` and renders the response. Confirm it works against local proxy.

**Acceptance:** with `ANTHROPIC_API_KEY` set and `proxy/main.py` running, a hardcoded frontend call returns a real Claude response. Remove the throwaway component.

**Risks:** Anthropic API key in shell history. Use a `.env` file in `proxy/` (gitignored) and source it via `python-dotenv` or `direnv`.

## Phase 3 — Build the store

**Goal:** all mutable state lives in `src/store/hunt-store.ts` with clear actions.

**Work:**

1. Implement the Zustand store per the sketch in `02_ARCHITECTURE.md`.
2. Wire workspace serialize/load (uses `withLifecycle` on rehydrate, applies `builtinMeta` to built-ins).
3. Wire custom-enterprise inherits filtering for `libForEnt()`.
4. Write `tests/store/hunt-store.test.ts` (see `04_TEST_PLAN.md`).

**Acceptance:** `tests/store/hunt-store.test.ts` green. Specifically: workspace round-trip preserves custom hunts, built-in lifecycle, custom enterprises, telemetry; custom enterprises with `inherits=["tech"]` filter correctly; empty inherits falls back to all five sectors.

**Risks:**

- Workspace `customEnts` field name was `customEnterprises` in the JSON (intentional — more readable in the file). Keep the JSON key as `customEnterprises`; only the in-store variable is `customEnts`.
- The KEV scan result is keyed by `entId` (per-enterprise cache). Don't share it across enterprises.

## Phase 4 — Extract components

**Goal:** feature parity with the source artifact, structured as a component tree per the architecture file map.

**Work — order matters:**

1. `<Shell>` (header + tabs + toast + modal mount). Stub the tabs.
2. `<EnterprisePicker>` with the +New button and delete button (gated on `ent.custom`).
3. `<EnterpriseBuilder>` modal — port from the source artifact's `EnterpriseBuilder`.
4. `<ThreatLandscape>` — the landscape tab. Static read of the active enterprise.
5. `<HuntLibrary>` and its children. Start with the rail and list, then the detail panel, then `<HuntJournal>`. Hunt journal must keep its `key={activeHunt.id}` to reset draft state on hunt switch.
6. `<Coverage>` and its children. Start with `<LifecycleSummary>` (already done by the lib), then `<ActivityCard>`, then `<CoverageMatrix>`, then `<TelemetryAudit>`, then `<KevExposure>`.
7. `<Forge>` and its children — generator, sigma import, json import, workspace, sigma export.

**Acceptance:** **manual smoke test** matching feature parity with the source artifact:

- Open the app. The default enterprise (the flagship Regional Energy Utility) shows in the landscape tab with actors, posture, techniques.
- Switch to Hunt Library. Filter by Severity → High. Click a hunt. See lifecycle, query, lint readout, journal.
- Mark a hunt "Validated." Switch tabs and back — status persists.
- Log a finding (disposition "clean", note "no hits"). Switch hunts — draft state should reset. Come back — finding persists in the list.
- Switch to Coverage tab. See lifecycle summary, activity card with the logged finding, ATT&CK matrix.
- Click "↻ Scan KEV catalog." See live feed indicator and CVE rows. Click a "no hunt" row's "Draft hunt →" button — lands you in Forge with the seed populated.
- In Forge, run "Generate" with a technique. Preview shows. Add to library.
- Download workspace. Reload page. Load workspace. All state restored.
- Export a hunt as Sigma. Open the file — well-formed YAML.
- Export the program report. Open the file — markdown renders with all three tables.
- Create a custom enterprise with `inherits=["tech"]`. The library narrows. Delete it.

If all of the above works, Phase 4 is done.

**Risks:**

- Don't drift away from the `qr-*` class names. The CSS and the components are coupled via these classnames; renaming them is a separate refactor and not in scope for the port.
- The hunt list rows must keep `flex:0 0 auto`. The modal body's children must keep `flex-shrink:0`. These are the bug fixes the artifact already shipped — don't lose them.
- The `HuntJournal` component takes its draft state locally. If you lift any of that into the store you'll re-introduce the cross-hunt bleed bug.

## Phase 5 — Tests + CI

**Goal:** every behavior the ad-hoc harnesses covered is now CI-enforced.

**Work:**

1. Round out the lib tests if any were skipped in Phase 1.
2. Add component smoke tests (one per major component, just "renders without crashing").
3. Configure `pnpm typecheck` (`tsc --noEmit`) as a CI step.
4. Add `.github/workflows/ci.yml` (see `04_TEST_PLAN.md`).
5. Verify CI passes on a real push to a feature branch.

**Acceptance:** CI is green on `main` and on a PR. `pnpm test --run`, `pnpm typecheck`, and `pnpm build` all pass locally and in CI.

## Phase 6 — Deploy

**Goal:** a public URL with both frontend and proxy live.

**Work — recommended path:**

1. Push the repo to GitHub.
2. Deploy proxy to Cloud Run:
   - `gcloud run deploy otter-shell-proxy --source proxy/ --region us-east1`
   - Set env vars in the console: `ANTHROPIC_API_KEY` (via Secret Manager), `OTTER_SHELL_FRONTEND_ORIGIN`.
   - Note the assigned URL.
3. Deploy frontend to Vercel:
   - Import the repo.
   - Set `VITE_PROXY_URL` env var to the Cloud Run URL.
   - Deploy.
4. Update the proxy's `OTTER_SHELL_FRONTEND_ORIGIN` to the Vercel URL. Redeploy proxy.
5. End-to-end smoke: visit the Vercel URL, generate a hunt, export Sigma.

**Acceptance:** the smoke test from Phase 4 works against the public URL.

**Cost note:** at Sonnet pricing, individual runs are cents. Set the proxy's `OTTER_SHELL_MONTHLY_TOKEN_CAP` (see `03_PROXY_CONTRACT.md`) to a number you're comfortable spending, and verify it triggers correctly with a one-off test.

## Phase 7 — Publish

**Goal:** a community-ready repo.

**Work:**

1. Pick a license (MIT or Apache 2.0).
2. Add `LICENSE` file.
3. Add ATT&CK attribution to the README (and ideally a footer in the app):
   *"This product uses information from the MITRE ATT&CK® framework, ©2015–2024 The MITRE Corporation. ATT&CK is a registered trademark of The MITRE Corporation."*
4. Add `CONTRIBUTING.md` with: how to add a hunt, how to add a platform, how to add a SIEM-vendor alias for KEV scanning.
5. Add screenshots to README (Hunt Library detail, Coverage activity card, Forge KEV mode, Enterprise builder modal).
6. Add a `Roadmap` section in README listing the known followups (battle-test curated hunts, KEV vendor-alias table, hunt-list search, undo, enterprise edit-in-place, EPSS).
7. Tag `v0.1.0`. Create a GitHub Release with a one-paragraph summary.

**Acceptance:** clone the repo on a clean machine; follow the README; have it running locally in under 30 minutes.

## Known followups (carry-over from artifact)

These are not blockers for v0.1 but should be tracked in the repo as issues from day one so they don't get lost:

1. **Curated-hunt battle-test.** Run all 18 hunts against a real Sigma test corpus or a SIEM sandbox to validate they fire. Document results in `docs/hunt-validation.md`. Highest single trust upgrade available.
2. **KEV vendor-alias table.** Map common stack abbreviations to canonical CISA vendor/product names (M365 → Microsoft Defender for Office, GP → GlobalProtect, etc.). Reduces false negatives in the KEV scan.
3. **Hunt-list search.** Once you've imported 50+ Sigma rules or generated dozens, the sev/source/status filters aren't enough. A name/keyword search box on the rail is cheap and high-value.
4. **Undo / version history.** In-session undo stack for hunt mutations and enterprise edits. Even a 20-step ring buffer would be a meaningful safety net for a tool that's becoming a program record.
5. **Enterprise edit-in-place.** Currently delete-and-recreate. Reuse the builder modal for edit by passing in initial values.
6. **EPSS scores on KEV list.** FIRST.org EPSS API gives an exploitation-likelihood score per CVE. Verify CORS behavior before wiring; if blocked, fetch via the proxy.
7. **All-enterprises activity view.** A toggle on the activity card to show findings across all enterprises (not just the active one), for users who switch profiles often.
8. **Atomic Red Team integration depth.** Instead of just a link, embed the technique's atomic test name and command preview — still no execution, just informational.
9. **Hunt diff/changelog.** Track what changed between versions (hypothesis edits, query edits, threshold changes).
10. **Signed Sigma export.** Optional GPG signature on the bulk Sigma export, for teams who need provenance on detections.
11. **URL-only threat-report import.** The artifact ships a "Report → hunt" mode that takes pasted article text plus an optional source URL (CORS blocks direct browser fetches of arbitrary news/advisory sites, and the in-artifact API only exposes `web_search`, not `web_fetch`). Post-port, the proxy can fetch the URL server-side. Spec for the post-port version:
    - New proxy endpoint `POST /api/scrape` taking `{ url: string }`, returning `{ url, title, text, fetchedAt }`.
    - Domain allowlist (or block list) — start permissive but log every host fetched.
    - Size cap (e.g. 2 MB raw, truncate text extraction to ~12k chars).
    - Timeout (10s).
    - User-Agent set to `OtterShell/0.1 (+repo URL)`.
    - Readability extraction (Python: `readability-lpr` or `trafilatura`; Node: `@mozilla/readability`) to strip nav chrome.
    - Respect `robots.txt` and set `noindex` on the request.
    - Same rate limiting tier as `/api/claude`.
    - Frontend flow: report mode shows a URL input → calls `/api/scrape` → populates the textarea with the extracted text (user can edit before generating) → standard generate flow takes over. The paste fallback stays as Plan B.

## Decision log (things already decided in the artifact — keep these)

So the port doesn't re-litigate settled choices:

- Defensive only — see `05_DESIGN_PRINCIPLES.md`.
- No live SIEM data — see `05_DESIGN_PRINCIPLES.md`.
- 7 platforms (CrowdStrike, XSIAM, Sentinel, Defender, Elastic, SecOps, Splunk). Adding an 8th is a real change; do it deliberately.
- Sigma is the export format of choice. Not OSSEM, not Detection-as-Code DSL.
- ATT&CK Navigator layer is the visualization handoff. Not a custom matrix viewer.
- KEV is the CVE feed of choice. Not NVD, not vendor advisories, not a paid feed.
- Markdown is the report format. Not HTML, not PDF.
- Workspace is a single JSON file. Not a folder, not a database.
- Single user. Not multi-tenant.

If any of these need to change, surface that decision as a discussion before doing it.
