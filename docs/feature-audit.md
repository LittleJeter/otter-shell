# Otter Shell — Security & Feature Audit

*Threat Hunt Console · single-file React artifact · audit date 2026-05-28*

This audit covers the Otter Shell artifact as it currently stands: a client-side React tool with no backend of its own, which makes calls to the in-artifact Anthropic API (for hunt generation, intel/KEV enrichment, and the KEV catalog scan) and renders queries for seven SIEM/EDR platforms. The scope here is the tool itself — not the security of the hunts it produces, which are separately disclaimed in-app as validated-syntax starting points.

## Summary

Otter Shell is low-risk as an artifact. It holds no secrets, writes nothing persistent, builds no dangerous DOM, and runs entirely in the user's session. The most meaningful issues are about *trust in generated content* and *operational robustness* rather than classic web vulnerabilities. The highest-value work left is feature depth, not security remediation.

Overall posture: **good**. Two robustness gaps were found and fixed during this pass (see Fixed below). The remaining items are hardening niceties and feature gaps.

## What was checked

Static review of the full source for: dangerous DOM (`dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function`), browser storage use, `<form>` tags, user-built regular expressions (ReDoS), external-link handling, how model and user-supplied text reaches the DOM, how imported JSON and model JSON are parsed and trusted, and the API call surface.

## Findings

### 1. No secret handling — good by design
The artifact never takes, stores, or transmits an API key. The in-artifact Anthropic API calls are unauthenticated from the code's perspective (the platform injects credentials), which is the correct pattern for artifacts. There is nothing to leak. No credentials, tokens, or PII are collected anywhere.

### 2. No persistence — good, with a usability cost
The tool uses only React state. Nothing is written to `localStorage`/`sessionStorage` (correctly, since those are unsupported in the artifact sandbox and would break it). The security upside is zero data-at-rest. The cost is that the library, custom hunts, telemetry toggles, and KEV scan results all reset on reload — see Feature Gaps.

### 3. Cross-site scripting — not present
All model output and user input (hunt fields, the intel summary, KEV CVE descriptions, product names) is rendered as JSX children, which React escapes automatically. There is no HTML injection path. The one place untrusted text touches an attribute is the Atomic Red Team link `href`, which is built only from a strict `T####`/`T####.###` regex extraction — a malformed technique string cannot inject a `javascript:` URL or break out of the attribute.

### 4. External links — handled correctly
The single outbound link (Atomic Red Team) uses `target="_blank"` with `rel="noreferrer"`, preventing reverse-tabnabbing and referrer leakage.

### 5. Untrusted JSON ingestion — FIXED this pass
The Sigma/JSON import and the AI/intel/KEV generators all ingest data shaped by an outside source (a pasted file, or model output). Previously these were trusted loosely. Hardened:
- JSON import now validates that `queries` is an object, keeps only known platform keys with string values, clamps each query to 4,000 chars and each text field to sane lengths, validates `industries` against the known set, and refuses payloads over 200 hunts (prevents a giant paste freezing the tab).
- `normalizeHunt` (used for all generated/intel/KEV hunts) now coerces `queries` to an object and clamps every string field, so a malformed model response can't inject unbounded content or crash the render.

### 6. Prompt-injection via web search — residual, low severity
Intel and KEV modes send model output through web search. A poisoned web page could in principle steer the model's JSON. Impact is bounded: the worst case is a misleading hunt or summary shown to the user, never code execution or data exfiltration (output is escaped text and clamped strings). This is inherent to any LLM+search feature and is acceptable, but users should treat generated hunts as drafts — which the in-app notes already say.

### 7. Denial-of-service via input size — partially mitigated
The Sigma parser is a hand-rolled indentation parser. A pathological multi-megabyte paste could be slow. The 200-hunt cap and per-field clamps on the JSON path help; the Sigma path is still unbounded. Low severity (self-inflicted, single user, no server). Optional: cap Sigma input length.

### 8. No regex built from user input — good
The translator uses only static field maps and literal string matching. There is no `new RegExp(userInput)`, so no ReDoS surface.

## Fixed during this audit
- Hardened `importJson` (shape validation, field clamping, platform-key allow-listing, 200-hunt cap).
- Hardened `normalizeHunt` (queries coercion, string clamping) for all generated/intel/KEV hunts.

## Missing features — ranked by value

**High value**
- **Persistence / save + load.** *(Implemented.)* Because nothing survives reload and the sandbox blocks `localStorage`, the tool now offers a true file-based workspace: "Download workspace" writes a JSON file of custom/generated hunts plus telemetry selections, and "Load workspace" restores it via a file picker (built-in hunts are re-merged, deduped). The clipboard library export/import remains for power users. An ephemeral-session reminder is shown.
- **Authoritative KEV feed instead of model recall.** *(Implemented.)* The KEV scan now fetches the authoritative CISA catalog directly from `cisagov/kev-data` (CISA's own CC0 GitHub mirror, served CORS-permissively via raw.githubusercontent.com), filters `vulnerabilities[]` against the enterprise stack client-side, sorts newest-first, and flags ransomware-associated CVEs — exact and current rather than recalled. If the browser can't reach the feed, it falls back to best-effort model recall and labels the result as such. The Forge KEV *generator* still uses the model, correctly, since it must write detection queries the feed doesn't contain.
- **Detection-as-code export (Sigma out).** *(Implemented.)* The tool now exports Sigma both per-hunt (from the Hunt Library) and as a multi-document file for the whole library. Hunts imported from Sigma round-trip faithfully (the raw `detection`/`logsource` is retained and re-emitted); curated/generated hunts export as a fully-formed Sigma scaffold — complete metadata, tags, logsource, falsepositives, level — with the native per-platform queries preserved under a custom `ottershell_queries` field, and the abstract `detection` block honestly marked as needing completion since platform query syntax cannot be losslessly reversed.

**Medium value**
- **Hunt journal — hypothesis → outcome.** *(Implemented.)* Each hunt now has a journal in its detail panel: a dated findings log with a disposition (clean / suspicious / confirmed / inconclusive) and notes, a next-steps/pivots field, a tuning log for the thresholds you actually landed on, and an IOC enrichment helper (paste an indicator → type-detected one-click lookups to VirusTotal, GreyNoise, Shodan, urlscan, AbuseIPDB, MalwareBazaar). A "last run" indicator surfaces on the lifecycle row, and the whole journal persists in the workspace file. This moves the tool from a query generator toward a hunt record — a clean result is captured as coverage, not nothing.
- **Hunt metadata & lifecycle.** Author, created/last-reviewed date, version, confidence/fidelity tier, and a status (new / in-progress / validated / retired). Turns a query library into a managed detection backlog. Pairs naturally with the Atomic Red Team link already added (record "validated on <date>").
- **Custom enterprise builder.** Users can add custom hunts but not custom enterprises. Letting a user define their own org (name, sector, stack, likely actors/techniques) would make the whole tool usable beyond the five built-in profiles.
- **Coverage export beyond Navigator.** A printable/PDF hunt pack and a CSV of the library for reporting to non-Navigator stakeholders.
- **Per-platform query linting.** *(Implemented.)* Every query shown (in the Hunt Library and in the generate/import preview) gets a conservative lint pass: bracket-balance (with string/regex/escape literals stripped first so regex-heavy queries don't false-positive), a placeholder check, a soft time-window nudge, and a lenient base-construct sanity check per platform. The block leads with the warning count (`✓ Lint: no warnings for CrowdStrike · 1 note`) and labels every row `⚠ Warning —` or `ℹ Note —`: a warning is amber and says the query itself looks wrong, a note is muted context for running it. All non-blocking. Validated against the real library to confirm zero false positives on known-good queries.

**Lower value / nice-to-have**
- **Pivot suggestions and run cadence per hunt** ("if this fires, run these next"; "run weekly").
- **More Sigma logsource categories** (registry, file_event, image_load) in the translator's field maps.
- **EPSS enrichment** alongside KEV (likelihood-of-exploitation score) to help prioritize the uncovered-CVE list.
- **Richer SecOps rules** (multi-event correlation) rather than single-event YARA-L scaffolds for the curated hunts.

## Operational notes / caveats (not defects)
- The AI generator, intel mode, KEV mode, and KEV scan all require the in-artifact Anthropic API with web search to be available in the runtime; in environments where it isn't, those features fail gracefully with an error message but won't function.
- Enterprise `stack` values are reasonable per-sector defaults, not a readout of any real org's environment, and will drift as the threat landscape changes. They are one line per profile to update.
- Every generated, imported, or curated query is a validated-syntax starting point. Field, dataset, and index names vary by deployment and must be confirmed against onboarded log sources before operational use. This is stated in-app.

---

# Follow-up pass — 2026-08-30 (pre-publication)

Closing the gaps that mattered for shipping this publicly. Every item was verified in a
real browser via the DevTools protocol, not assumed.

## Fixed

### Horizontal overflow on phones — **[Certain] Fixed. Measured before and after.**

The layout grids already collapsed to one column at their breakpoints, so this looked
handled. It was not. Measured at a true 390 px viewport with device emulation:

```
PRE-FIX:   viewport 390, document scrollWidth 682
           offenders: div.qr-ent-pick w=507, div.qr-ent-row w=507, select w=436
POST-FIX:  viewport 390, document scrollWidth 390, offenders: []
```

Three causes: the header was a non-wrapping flex row, the tab bar's buttons were together
wider than the viewport, and grid children default to `min-width:auto` so a long query line
widened its whole track. Fixed by stacking the header below 820 px, giving the tab strip its
own horizontal scroll instead of the document, and setting `min-width:0` on the grid
children so long queries scroll inside their own `<pre>`.

Verified at 360 px, 390 px and 768 px across all four tabs: `scrollWidth === viewport`,
zero overflowing elements, in every combination.

> A note on method: the first measurement used `--window-size` without device emulation,
> which reports a different viewport than it appears to. The finding held up, but only
> `Emulation.setDeviceMetricsOverride` gives a trustworthy number.

### Everything read zero on first load — **[Certain] Fixed.**

The lifecycle, findings journal and coverage roll-up are what separate this from a query
generator, and a first-time visitor saw none of them working: `0 runs logged`, `0 validated`,
`18 New`. **Load a demo programme** now seeds a worked example — 20 logged findings across
15 built-in hunts plus two custom hunts, with tuning notes, pivots, validation provenance
and a realistic spread of dispositions (12 clean, 3 suspicious, 2 confirmed, 3 inconclusive).

Dates are generated relative to today, so the example never looks stale. It is built as an
ordinary workspace object and loaded through the same `applyWorkspace` path and the same
sanitizers as a real file — the demo gets no privileged route into state.

### No persistence — **[Certain] Fixed.**

Pass 1 recorded that the tool writes nothing to Web Storage, "correctly, since those are
unsupported in the artifact sandbox". That constraint does not exist on a normal deployment.
The workspace now autosaves to `localStorage` (debounced 400 ms) and restores on load.

Every accessor is wrapped: Storage throws outright in some privacy modes and on quota
exhaustion. When a write fails the UI says so — "this browser is blocking local storage …
download your workspace before closing the tab" — rather than silently implying the work is
safe. Restore runs through the same sanitizers as a file load; data sitting in a browser
profile is no more trustworthy than a file off disk. **Forget saved data** clears it.

Verified: after loading the demo, `localStorage` held 13,587 bytes and the state survived a
reload.

### Blank social previews and no favicon — **[Certain] Fixed.**

`index.html` had no description, no Open Graph or Twitter tags, no theme-color and no icon —
a shared link previewed as an empty rectangle. All added, with a 1200×630 card generated from
the hunt-library view. `og:image`, `twitter:image` and `og:url` are rewritten from relative to
absolute at build time when `VITE_SITE_URL` is set, since Open Graph specifies absolute URLs
and not every crawler resolves relative ones.

### The Forge right pane was empty — **[Certain] Fixed.**

Roughly 60% of that tab was a placeholder, and with the AI generator off by default the tab's
hero control is disabled — the weakest screen in the tool. It now carries a three-step
explainer of what the panel does, and when no AI backend is configured the Sigma converter
leads the left column — its sample rule is prefilled, so **Convert Sigma → Hunt** works on a
cold start — with the disabled generator and its backend notice below.

### No accessible semantics — **[Certain] Fixed.**

Zero `aria-` attributes and zero `role`s. Focus styles and `prefers-reduced-motion` were
already handled, so the groundwork was there. Added: a real `tablist`/`tab`/`tabpanel`
relationship with roving `tabIndex` and left/right arrow navigation, a `radiogroup` for the
platform picker, a polite live region for toasts, a labelled enterprise select, `role="dialog"`
with `aria-modal` on the builder, accessible names on every icon-only button, and
`aria-hidden` on decorative emoji.

Verified in-browser: 1 tablist / 4 tabs / 1 panel with correct `aria-selected` and
`aria-controls` wiring, arrow keys move both selection and focus, and **zero** buttons remain
without an accessible name.

### No tests — **[Certain] Fixed.**

`migration/04_TEST_PLAN.md` specified a Vitest suite; none existed. There are now 50 tests
(`npm test`) over the pure logic — sanitizers, library invariants, Sigma round-trip, linter,
ATT&CK helpers, KEV matching, markdown export.

The linter test is the load-bearing one: it asserts zero warnings across all 126 curated
queries (18 hunts × 7 platforms), so a linter false positive or a malformed query fails the
build instead of quietly eroding trust in the amber warnings.

Two of these tests failed on first run and both were *my* assertions being wrong, not the
code: `mdEscape` correctly applies to findings-table cells rather than the H1 title, and
splitting a markdown row on `|` miscounts columns because an escaped `\|` still contains a
pipe. Both corrected to assert the real, correct behaviour.

### Portfolio-review follow-ups (2026-09-01) — **[Certain] Fixed.**

An external review of the portfolio write-up flagged six things in this tool, all of which
were reproduced here:

- **The flagship enterprise profile was a description-level fingerprint of a specific
  employer.** Replaced with a **Regional Energy Utility** — a sector none of the four generic
  profiles already cover, with its own posture, adversaries and internet-facing stack. The
  demo programme's copy moved with it, and the old industry id maps forward so a workspace
  saved under it still loads.
- **The Sigma converter's "sample rule is already in the box" was untrue** — the sample was
  placeholder text only, so **Convert** was disabled on a cold start. It is now the initial
  value, and the card leads the column in an AI-off build (see above).
- **The time-window nudge read as a lint warning** in screenshots, against the README's
  zero-warnings claim. It is raised on 47 of the 126 curated queries and is expected — most
  of them take their lookback from the console's time picker — so the fix was to stop it
  looking like a defect rather than to bolt lookbacks onto the library.
- **The coverage matrix printed the same technique twice** in a tactic column when two hunts
  covered it. `techChips()` now renders one chip per technique with a count; the column header
  still shows the honest hunt count.
- **The demo findings journal showed no clean run** and left the pivots field empty, on the
  one hunt whose caption promised both. Both filled.
- **The README screenshots were recaptured** from the built app against the new profile.

## Still open

- **`style-src 'unsafe-inline'`** — structural to the single-file component; see
  `docs/security-audit.md` §2.2.
- **Google Fonts is a third-party request** — self-hosting the two families would remove the
  availability and privacy dependency.
- **The AI generator is off by default** — deliberate. It needs a proxy holding a key
  server-side, and a public proxy is a public spend endpoint.
- **The TypeScript/Zustand port** — `migration/` still describes work not done here. The
  component is still one file.
