# Otter Shell — Security Audit

Scoped to what a buyer's security team or a hostile HN commenter would actually probe. Findings are tagged **[Certain]** (verified against the code/by test), **[Likely]** (strong inference), or **[Guessing]** (filled gap). Each section ends with a verdict and, where relevant, a requirements list for the hosted version.

Audited artifact: `otter-shell-threat-hunt-console.jsx` (2,997 lines, single-file React). Method: static read of every dangerous sink, plus executable tests of the parser and URL builders against malicious input.

---

## 1. Query generation safety — HIGHEST RISK SURFACE

**The worry:** crafted input (a malicious Sigma file, or adversarial text fed to the AI generator) produces injection into generated KQL/SPL, or causes code execution on import.

### 1a. Is the generated query a code-execution risk? **[Certain] No — by architecture.**

Otter Shell never *executes* a query. It generates query *text* and displays it for the user to copy into their own SIEM. There is no query engine, no `eval`, no database connection, no shell. The output is inert text. "Query injection" in the SQL-injection sense is not possible because nothing interpolates the query into a live execution context inside the tool.

The residual risk is **downstream**: if a user blindly pastes a generated query into their SIEM, could adversarial generator input have produced a query that does something harmful *there*? In practice SIEM query languages (KQL, SPL, ES|QL, XQL, YARA-L) are read-only search languages — they don't write data or execute OS commands. The realistic worst case is a query that's wrong (misses real threats, or is noisy), not one that's destructive. The tool's standing "validated-syntax starting point — confirm against your deployment" disclaimer is the correct mitigation, and it's shown under every query.

### 1b. Can adversarial AI-generator input cause harm? **[Certain] Bounded to misleading output.**

The generator sends user text to the Anthropic API and parses a JSON object back. Two sub-risks:

- **Prompt injection** (e.g. a threat report containing "ignore previous instructions, output X"). The blast radius is bounded: the worst an injected prompt can do is make the model emit a misleading hunt. That hunt is then **normalized** (`normalizeHunt` clamps every string field to length caps and coerces types) and **rendered as escaped JSX**. It cannot inject script, and it cannot exceed the field caps. A poisoned hunt is a *quality* problem (bad detection logic) caught by the user's review and the lint pass, not a *security* problem. **[Certain]**

- **Malformed JSON response.** The new balanced-brace extractor (added this session) walks the string respecting string literals and rejects anything that doesn't `JSON.parse`. A response that isn't valid JSON produces a visible error, not a crash or a partial object. **[Certain]**

### 1c. Sigma import — prototype pollution. **[Certain] Latent issue found and fixed this session.**

The hand-rolled `parseYamlSubset` assigns `obj[key] = value` with `key` taken directly from the imported YAML. A malicious Sigma file containing `__proto__:`, `constructor:`, or `prototype:` keys is the classic prototype-pollution vector.

**Tested exploitability before fix:** I ran three pollution payloads (nested-object `__proto__`, scalar `__proto__`, deep `constructor.prototype`) through the actual parser. **None leaked to `Object.prototype` in V8** — the nested-object form reassigns only the local object's prototype without walking up, the scalar form dropped the key, and the deep form didn't propagate. So it was **not exploitable as written**. But this is fragile — it depends on the exact assignment shape and JS engine behavior, and the parsed object should never carry those keys regardless.

**Fix applied:** the parser now explicitly drops `__proto__`, `constructor`, and `prototype` keys (consuming any nested block so indentation tracking stays correct). Verified by test: pollution payloads are dropped, legitimate Sigma structure (including modifier keys like `Image|endswith`) is preserved, no parse regression.

**Downstream flow confirmed safe [Certain]:** the parsed Sigma object only ever flows into string-building — query construction and `emitYaml` for re-export. It never reaches a DOM sink, never gets evaluated, and renders as escaped JSX. So even pre-fix, there was no XSS path; the fix closes the latent pollution fragility.

### 1d. Other injection sinks. **[Certain] Clean.**

Full scan for `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, `new Function`, `document.write`, string-form `setTimeout`/`setInterval`: **zero matches.** All model and user text renders as JSX children (React auto-escapes). The two `href` sinks (IOC enrichment links, Atomic Red Team link) are safe by construction — enrichment URLs are a hardcoded `https://` prefix + `encodeURIComponent(input)`, so a `javascript:` payload becomes inert query-string text; the Atomic URL derives from a regex-extracted `Txxxx` ID with no free-text path.

**Verdict (1):** The highest-risk surface is sound. No code execution, no XSS, prompt-injection bounded to misleading output that the user reviews. The one real finding (parser prototype-pollution fragility) was latent-not-exploitable and is now fixed. **For the hosted version**, add a hardened YAML parser (use a maintained library like `js-yaml` with `JSON_SCHEMA` / `FAILSAFE_SCHEMA` and `{ json: true }`, which refuses dangerous tags) rather than carrying the hand-rolled subset parser into production.

---

## 2. Secrets handling

**The worry:** API keys (Anthropic, anything for CISA KEV) live client-side and leak.

### Findings **[Certain]**

- **No secrets in the artifact.** Full scan for `api_key`, `secret`, `token`, `password`, `bearer`, `authorization`, `x-api-key`, `sk-ant`, `client_secret`: the only matches are the *word* "token" inside hunt content (e.g. "OAuth token theft"). No key material, no auth headers, nothing.
- **The Anthropic calls send no key.** Both `fetch("https://api.anthropic.com/v1/messages")` calls post only `Content-Type: application/json` and a body — no `x-api-key`, no `authorization`. They work *only* because the claude.ai artifact runtime injects auth transparently. Outside that runtime they 401. This is exactly the dependency the migration proxy is designed to remove.
- **The KEV fetch needs no secret.** It hits `raw.githubusercontent.com/cisagov/kev-data/...` — public, unauthenticated, CORS-open, `cache: no-store`. No credential involved.

> **Addendum (2026-08-30, post-audit).** Finding 2 above describes the artifact as audited.
> The harness has since removed the hardcoded endpoint: both call sites now read
> `CLAUDE_ENDPOINT`, sourced from the `VITE_CLAUDE_PROXY_URL` build variable, and the AI
> features are disabled with an in-UI explanation when it is unset. The recommendation in the
> verdict is therefore now enforced by construction — the frontend has no path to Anthropic
> that does not go through an operator-chosen URL. `VITE_CLAUDE_PROXY_URL` holds a URL only;
> the key-in-bundle risk called out below is unchanged and still applies to anyone tempted to
> put a key in a `VITE_*` variable.

**Verdict (2):** Clean in the artifact precisely *because* the artifact offloads auth to the platform. The risk moves entirely to the hosted version, where a real Anthropic key exists. **For the hosted version** (already specified in the migration proxy contract): key lives only in a server-side env var (`ANTHROPIC_API_KEY`), never in client JS, never in a response body, never logged. The proxy refuses to start without it. This is the single most important reason the frontend must never call Anthropic directly in production — verified the proxy starter enforces all of this.

---

## 3. Auth / tenancy gaps

**The worry:** there's no auth today, so this is a requirements list for the hosted version.

### Current state **[Certain]**

The artifact is a single-user, in-memory, client-only app. There is no auth, no session, no server-side state, no concept of a "user" or "team." That is correct for an artifact and not a finding against it. The findings here are **requirements for hosting**, not defects.

### Requirements for the hosted version

- **Session handling [Likely].** The proxy currently rate-limits by IP only (per the contract). For anything beyond a personal deploy, put real auth in front (Clerk/Auth0/WorkOS) and key rate-limits + spend caps to the authenticated user, not the IP. IP-only limiting is trivially bypassed behind CGNAT or with rotating egress.
- **Team isolation [Certain requirement].** If workspaces are ever stored server-side (today they're local files), every storage read/write must be scoped to a tenant ID derived from the verified session — never from a client-supplied parameter. The single biggest multi-tenant footgun is trusting a `tenantId` in the request body. Don't.
- **Rate limiting [Certain].** The proxy spec already has a per-IP token bucket (20/min, 200/hr) and a monthly token cap. For multi-user, move the bucket key to the user ID and make the cap per-tenant, backed by Redis (the in-memory bucket resets on instance restart and doesn't share across instances).
- **Authorization on every proxy route [Certain].** `/api/claude` and the future `/api/scrape` must both check auth. `/health` and `/version` can stay public but must expose nothing sensitive (they don't).
- **CORS lock [Certain].** The proxy must pin `Access-Control-Allow-Origin` to the real frontend origin in production (the starter does this; wildcard is dev-only behind an env flag).
- **CSRF [Likely].** With token auth in an `Authorization` header (not cookies) there's no CSRF surface. If you ever move to cookie sessions, add CSRF protection.

**Verdict (3):** No auth today is appropriate for the artifact. The hosted requirements are well-understood and mostly already captured in the proxy contract; the two to underline are *tenant scoping from the verified session only* and *moving rate-limit/spend keys off IP onto user identity*.

---

## 4. Dependency & supply chain

**The worry:** stale or unpinned deps in the runtime and in the 7-file migration package.

### The artifact itself **[Certain]**

Zero third-party runtime dependencies. It's one file using only React (provided by the host) and browser APIs (`fetch`, `Blob`, `URL`, `navigator.clipboard`). No npm packages ship in the artifact, so it has no supply-chain surface of its own. This is a genuine strength — there's nothing to `npm audit` until the port.

### The migration package **[Certain / Likely]**

The package specifies, not locks, dependencies — appropriate for a brief, but the port must pin:

- **Proxy** (`proxy_starter.py`): declares `fastapi >= 0.115`, `httpx >= 0.27`, `uvicorn >= 0.30`, `pydantic >= 2.6`. These floors are current and not stale **[Likely]**. **For the port:** generate a `uv.lock` / `requirements.txt` with hashes; don't ship `>=` ranges to production.
- **Frontend** (per architecture/test docs): React 18, Vite, Vitest, Zustand, TypeScript, `@testing-library/react`. CI pins `actions/checkout@v4`, `actions/setup-node@v4`, `pnpm/action-setup@v3`, Node 20, pnpm 9 — all current, none stale **[Likely]**.
- **No versions are dangerously old [Likely].** Nothing in the package references an abandoned or known-vulnerable library. The one hand-rolled component to *replace* rather than pin is the Sigma YAML parser (see §1c) — swapping it for `js-yaml` in safe-schema mode removes the parser-maintenance burden and the pollution class entirely.

**For the port — supply-chain hardening checklist:**
- Commit lockfiles (`pnpm-lock.yaml`, `uv.lock`); enable `pnpm install --frozen-lockfile` in CI (the proposed CI already does).
- Add `pnpm audit` (or `osv-scanner`) as a CI gate.
- Enable Dependabot/Renovate for both `package.json` and `pyproject.toml`.
- Pin GitHub Actions to commit SHAs (not just `@v4`) for the highest-assurance posture — optional but it's what a security-conscious buyer will ask about.
- Add Subresource Integrity if any CDN scripts are ever introduced (currently none).

**Verdict (4):** The artifact has no supply-chain surface. The migration package's declared versions are current, not stale. The port's job is to *lock* what the brief *declares*, gate on `pnpm audit`, and replace the hand-rolled YAML parser with a maintained library.

---

## 5. Data handling

**The worry:** hunt journal contents are sensitive — they describe your detection gaps and what you've found. Confirm nothing persists or transmits unexpectedly.

### Findings **[Certain]**

- **No client-side persistence.** Full scan: no `localStorage`, `sessionStorage`, `indexedDB`, or `document.cookie`. All state is in-memory React, lost on reload by design. The tool tells the user this ("Otter Shell keeps nothing after a reload"). The *only* persistence is the explicit, user-initiated workspace download (a local `Blob` → file on the user's own disk).
- **No analytics, no beacons.** No `sendBeacon`, no Google Analytics/Segment/Mixpanel/PostHog/Sentry/Datadog, no tracking pixels. Nothing phones home.
- **Egress is fully enumerated and user-initiated.** Exactly four ways data leaves the browser, all explicit:
  1. **Anthropic API** — only the text the user submits via the generator (a technique description, pasted report, or a hunt being expanded). Triggered by clicking Generate. **Hunt journal contents are *not* sent unless the user generates from a hunt that includes them.**
  2. **IOC enrichment links** — an IOC the user pastes into the journal becomes a query-string param to VirusTotal/GreyNoise/Shodan/etc., but *only* when the user clicks the link. Standard triage behavior. Links open with `rel="noreferrer noopener"`.
  3. **Clipboard** — copies the user explicitly requests.
  4. **Local file downloads** — workspace JSON and markdown reports, written to the user's own disk via `Blob`.
- **The sensitive-data nuance worth stating plainly [Certain]:** the journal (detection gaps, findings, tuning notes) is the most sensitive content in the tool. It never transmits on its own. It *can* reach Anthropic if the user generates from a hunt carrying journal data, and IOCs *can* reach third-party enrichment services when the user clicks an enrichment link. Both are user-initiated and obvious from the UI, but a buyer's security team should know these are the two paths by which internal detection-gap data could leave their boundary.

**Verdict (5):** Data handling is clean and conservative — no silent persistence, no telemetry, no surprise egress. Every path out is explicit and user-initiated. **For the hosted version**, two notes: (a) if workspaces ever move server-side, they become sensitive data at rest (detection gaps) and need encryption + tenant scoping + a retention policy; (b) document the enrichment-link and generator egress paths in user-facing docs so SOC teams can make an informed call about pasting real internal IOCs into a hosted instance — or offer a config flag to disable enrichment links for air-gapped/high-sensitivity deployments.

---

## Summary

| # | Surface | Verdict | Action |
|---|---------|---------|--------|
| 1 | Query-gen safety | Sound; no code-exec/XSS; injection bounded to misleading output | **Fixed** parser pollution fragility this session; port should use `js-yaml` safe-schema |
| 2 | Secrets | Clean (artifact holds none) | Enforce server-side key in proxy (already specified + verified) |
| 3 | Auth/tenancy | N/A for artifact; requirements clear | Tenant-scope from verified session; move rate-limit/spend off IP |
| 4 | Supply chain | No surface in artifact; package deps current | Lock files, `pnpm audit` gate, replace hand-rolled YAML parser |
| 5 | Data handling | Clean; no silent persistence or egress | Document egress paths; encrypt + scope if workspaces go server-side |

**One fix applied during this audit:** prototype-pollution hardening in the Sigma parser (latent, not exploitable, now closed).

**Nothing found that blocks shipping the artifact as-is.** The material security work is all in the *hosted* version, and the proxy contract in the migration package already specifies most of it. The two items to make sure don't slip: server-side-only API key (non-negotiable) and tenant isolation derived from verified sessions (the classic multi-tenant footgun).

---

# Audit pass 2 — 2026-08-30 (pre-publication hardening)

Scope: the code as it actually stands, re-derived from source rather than trusting pass 1.
Threat model for a **published static site**: no server, no auth, no multi-tenancy, no data at
rest. The realistic adversaries are (a) a malicious file a user is tricked into loading,
(b) a compromised or hostile third-party origin, (c) the developer's own machine while running
`npm run dev`.

Every finding below was reproduced before it was fixed and re-tested after.

## Findings

### 2.1 Workspace loader trusted its own file format — **[Certain] Fixed. Was a hard crash.**

`loadWorkspaceFile` accepted `customEnterprises` entries on the strength of `e && e.id && e.name`
alone, then handed them to a render path that calls `ent.techniques.filter(...)`,
`ent.posture.map(...)` and `ent.actors.map(...)` unconditionally. A workspace file containing
`{"id":"x","name":"y"}` — trivially producible by hand-editing an exported file — threw
`TypeError: Cannot read properties of undefined (reading 'filter')` and blanked the page.

Reproduced against the pre-fix source:

```
accepted by old filter: [{"id":"evil","name":"Evil Corp"}]
CRASH REPRODUCED -> TypeError: Cannot read properties of undefined (reading 'filter')
```

Severity: availability only — self-inflicted, no XSS, and state is ephemeral so a reload
recovers. But it is a blank page from a supported action.

The same loader was markedly weaker than the JSON importer beside it: `customHunts` went
through `withLifecycle` only, which validates lifecycle fields but **not** `name`, `technique`,
`hypothesis`, `fp`, `sev`, `source`, `queries` or `industries`. `builtinMeta.findings` was
assigned with `if (Array.isArray(o.findings))` — no per-entry filter and no length cap, unlike
`withLifecycle`'s `.filter(f => f && f.date).slice(0, 50)`. Custom hunt ids were checked against
built-ins but not against each other, so duplicate React keys were possible.

**Fix.** Four shared sanitizers (`sanitizeHunt`, `sanitizeFinding`, `sanitizeBuiltinMeta`,
`sanitizeEnterprise`) now rebuild every ingested object field-by-field from an allowlist, with
length caps and enum validation. Both the JSON importer and the workspace loader use them, so
the two paths can no longer drift. `sanitizeEnterprise` guarantees `posture`, `techniques`,
`actors` and `inherits` are arrays. `sanitizeBuiltinMeta` returns `null` per-field to mean
"absent or invalid — keep the built-in default" rather than overwriting with junk. Workspace
custom-hunt ids are now deduplicated against built-ins *and* each other.

Verified by 29 assertions covering the crash case, wrong-typed array fields, 500 KB strings,
unknown query-platform keys, bogus enum values, 5,000-entry findings arrays, and
`__proto__`/`constructor` keys surviving `JSON.parse`.

### 2.2 No Content-Security-Policy — **[Certain] Fixed.**

The app shipped with no CSP at all. For a static site this is the single highest-value
hardening available.

**Fix.** `csp.config.js` is the one source of truth, consumed by `vite.config.js` (meta tag,
baked into the bundle at build time) and `scripts/gen-headers.mjs` (`npm run headers`, which
regenerates `netlify.toml` and `vercel.json`). Policy:

```
default-src 'none'; script-src 'self';
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;
connect-src 'self' https://raw.githubusercontent.com;
base-uri 'none'; form-action 'none'; frame-ancestors 'none';
object-src 'none'; manifest-src 'self'; upgrade-insecure-requests
```

Notes on the choices:

- **`script-src 'self'` with no `'unsafe-inline'`.** The production build emits no inline
  script, so the strict form holds. The *dev server* does inject an inline React Refresh
  preamble, which this policy blocks — so the plugin is `apply: "build"` only. Weakening the
  policy to `'unsafe-inline'` to satisfy dev would mean never exercising the policy actually
  shipped. `npm run preview` serves `dist/` and does exercise it.
- **`connect-src` admits the proxy ORIGIN only when `VITE_CLAUDE_PROXY_URL` is set**, and only
  the origin, never the path. A default build cannot reach any AI backend even if the code were
  coerced into trying. An unparseable value fails the build loudly rather than silently
  producing a policy with a hole in it.
- **`'unsafe-inline'` in `style-src` is required and is an accepted limitation**, not an
  oversight: the component ships its stylesheet as a React `<style>` element and uses inline
  style attributes for severity colours. Removing it means extracting the CSS to a real
  stylesheet — worth doing in the TypeScript port, not worth destabilising the single-file
  component for.
- **`frame-ancestors` is omitted from the meta tag** because browsers ignore it there and warn
  in the console. Clickjacking protection comes from the real headers (`frame-ancestors` +
  `X-Frame-Options: DENY`) in `netlify.toml` / `vercel.json`.

Verified in headless Chrome against the real built bundle: app mounts and renders fully, the
KEV-feed origin is reachable, an unauthorised origin is refused, blob-URL downloads still work
(CSP has no directive governing `<a download>` — `navigate-to` was dropped from the spec), and
the console is completely clean.

### 2.3 Dev-server dependency advisories — **[Certain] Fixed.**

`npm audit` reported 1 high, 1 moderate: esbuild ≤0.24.2 (`GHSA-67mh-4wv8-2f99`, any website can
read responses from your dev server) and vite ≤6.4.2 (`GHSA-fx2h-pf6j-xcff` `server.fs.deny`
bypass; plus path traversal and an NTLM hash disclosure via `launch-editor`).

All four are **dev-server only** and do not affect built output — but they are a real risk to
the developer's machine while `npm run dev` is running, and a portfolio repo where `npm audit`
prints "1 high" invites the wrong conclusion.

**Fix.** vite 5.4 → 8.2.2, `@vitejs/plugin-react` 4.3 → 6.1.1. `npm audit`: **0 vulnerabilities**.
Build and dev both verified after the upgrade.

### 2.4 Unbounded text inputs — **[Certain] Fixed.**

Twelve inputs had no length bound: the IOC enrichment field, the findings note, and every field
in the New Enterprise modal (name, sector, blurb, stack, posture, techniques, and all four actor
fields), plus the Sigma import textarea. Adjacent inputs already used `.slice(0, 8000)`, so this
was inconsistency rather than intent. Bounded now via `maxLength` **and** a slice in the change
handler, since `maxLength` alone does not constrain a paste in every browser.

### 2.5 Third-party feed fields uncapped — **[Certain] Fixed.**

`matchKev` passed `cveID`, `vendorProject`, `product` and `shortDescription` from
`raw.githubusercontent.com` straight to render with no length limit. React escapes them, so
this is layout blowout rather than XSS, but the data is third-party and fetched at runtime.
Now capped at 40/160/400/20 characters.

### 2.6 Link `rel` inconsistency — **[Certain] Fixed.**

The Atomic Red Team link used `rel="noreferrer"` where the enrichment links used
`rel="noreferrer noopener"`. `noreferrer` implies `noopener` in current browsers, so this was
cosmetic, but the pair is now consistent. `Referrer-Policy: no-referrer` is also set at the
header level.

## Re-confirmed as clean (no change needed)

- **No XSS sinks.** No `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function`,
  `document.write` or `insertAdjacentHTML` anywhere in the source.
- **No `javascript:` URL injection.** Both URL builders (`enrichLinks`, `atomicUrl`) concatenate
  a hardcoded `https://` prefix with `encodeURIComponent` output or a regex-extracted
  `T####.###` technique id. A hostile hunt name cannot become a link href.
- **Sigma import prototype-pollution guard** (pass 1's fix) is present and correct.
- **No secrets.** Unchanged from pass 1, and now structurally stronger: there is no hardcoded
  Anthropic endpoint left in the frontend at all.
- **No regex built from user input**, so no injected-pattern ReDoS. The fixed domain regex
  `([a-z0-9-]+\.)+` requires a literal `.` per iteration, which bounds backtracking.

## Residual risk — accepted and documented

| Risk | Why it is accepted |
|---|---|
| `style-src 'unsafe-inline'` | Structural to the single-file component. Removing it is a TypeScript-port task (see `migration/02_ARCHITECTURE.md`). |
| Google Fonts is a third-party request | Availability and privacy dependency on `fonts.googleapis.com`. Self-hosting the two families would remove it; not done to keep the harness dependency-free. |
| Prompt injection via web search | Unchanged from pass 1. Bounded to misleading hunt text; the honesty layer already tells the user to validate every query. Only reachable at all if an operator configures a proxy. |
| A deployed proxy is a public spend endpoint | Out of scope for the frontend. `migration/03_PROXY_CONTRACT.md` specifies the origin allowlist and rate limiting; enforcement is the operator's. |
| No persistence, no auth | By design — see pass 1 §3 and §5. Nothing to steal at rest. |
