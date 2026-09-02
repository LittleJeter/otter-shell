# Design Principles

Read this first. Every other decision in the port flows from these.

## 1. The honesty layer

Otter Shell is a *defensive* tool that generates queries other people will run against their telemetry. Over-trust is the dominant risk. The single biggest reason analysts get burned by hunt-authoring tools is treating generated output as ground truth instead of a starting point.

Every panel in the source artifact that could overpromise instead labels its limits. **Carry every one of these forward verbatim or with equivalent precision:**

- The disclaimer below each platform query: *"Generated query is a validated-syntax starting point. Field, dataset and index names vary by deployment — confirm against your onboarded log sources and schema, set a sensible lookback window, and tune thresholds before operationalizing."*
- Sigma export scaffold comment: *"Auto-derived abstract detection is not available for this hunt. The native per-platform queries are preserved under 'ottershell_queries' below. Complete this selection, or compile the native query into your platform directly."*
- KEV feed fallback indicator: *"Live CISA feed"* vs *"Best-effort model recall (live feed was unreachable) — verify against cisa.gov/kev"* with a colored provenance dot.
- Sigma import note on imported hunts: *"Imported from Sigma — best-effort translation across platforms. Verify field/dataset names against your deployment."*
- "Validated" status: it's a coordination signal between you and your team, not a verified fact. The Atomic Red Team link helps but is voluntary.
- The hunt-journal next-steps and tuning fields exist *because* the tool can't run queries itself — they're how the user records what would otherwise live only in their head.

If a new feature can't be honestly labeled, it shouldn't ship. If a model fallback or partial result happens, surface it. If a query is a scaffold, mark it.

## 2. Defensive only

Every feature in the tool exists to help detect, hunt, document, or share defense work. The threat-actor descriptions, KEV intel, and CVE drafting all target *detection* of exploitation or post-exploitation — never the exploitation itself. The Mandiant/Unit 42-style intel summaries inform what to hunt; they do not instruct how to attack.

Keep this. Do not add features that produce exploit code, weaponize indicators, or aid offensive operations. Red-team validation links to Atomic Red Team are fine because those test detections; PoC scrapers are not.

## 3. No live SIEM data

The tool authors queries and records what was hunted. It does **not** connect to live telemetry, run queries, fetch real results, or pivot through actual events. This is deliberate:

- Vendor-neutral — works regardless of which SIEM the user runs.
- No privileged log access required — much easier to publish and trust.
- Much smaller attack surface — a credentialed backend would be a different and more dangerous product.

If a feature needs live data to be honest, it doesn't belong here.

## 4. Conservative linting and validation

The per-platform query linter (`src/lib/lint.ts`) was built with a hard rule: **no false positives on the curated library's known-good queries.** A linter that cries wolf on regex-heavy queries is worse than no linter — it teaches the user to ignore it.

Apply the same rule to any future check. If you can't tune it to zero false positives on the current 18 hunts plus the test corpus in `04_TEST_PLAN.md`, the check should be `info`-level (gentle nudge) rather than `warn`-level (real concern), or it shouldn't ship.

## 5. Defaults respect the user's signal

- New hunts default to status `new`, not `validated`. "Validated" means the user said it works in their environment.
- Custom enterprises inherit hunts from *all five* built-in sectors by default, so the library is never empty — the user narrows from there.
- The KEV scan never auto-runs; it's a button. Same for the AI generator. No background API calls.
- Findings default disposition is `clean` — encouraging the documentation of negative results, which is the bit most hunt programs skip.

## 6. Visual identity

The "classified console" aesthetic is part of the product, not decoration. Specifics that should survive:

- **Palette:** background `#0a0e12`, panels `#0f1419` / `#12181f`, lines `#1d242c`, text `#e6edf3`, muted `#74808c`, amber `#f5a623`, teal `#2dd4bf`, severity reds/oranges `#ff3b4e` / `#ff8c2a` / `#ffd23f` / `#4ec9b0`.
- **Type:** Oxanium for display/headings, IBM Plex Mono for code and labels, IBM Plex Sans for body.
- **Geometry:** rounded 7–14px corners, dashed borders on opt-in/empty states, a 3px amber-to-teal gradient bar at the top of modals.
- **Tone:** every uppercase letter-spaced label is a small affordance — `STATUS`, `VERSION`, `AUTHOR`, `NEXT STEPS / PIVOTS`. Don't shed them for "design cleanliness." They make the tool feel like an instrument, not a CRUD app.

## 7. Errors fail closed, in muted color

When something can't work — sandbox blocks a download, the KEV feed is unreachable, a Sigma file won't parse — the tool tells the user clearly and offers the next step (clipboard copy as fallback, model recall as fallback, a parse-error message that names the likely fix). It never silently degrades.

Carry the same pattern: every fetch wrapped in try/catch with a visible error path, every download with a clipboard fallback, every parser raising a useful error message.

## 8. The license

ATT&CK attribution required (LICENSE NOTICE in README), CISA KEV is CC0, Sigma format is open. Original queries and code are MIT or Apache 2.0 — pick one in `01_MIGRATION_PLAN.md` Phase 7. Don't pick GPL; this should be embeddable.
