# Architecture

The single source file decomposes naturally into four layers: **data** (static lists), **lib** (pure logic), **components** (UI), and a single **store** (mutable state). Plus a small **proxy** sibling.

## Recommended stack

- **Vite + React 18 + TypeScript (strict)**. The artifact is JSX; types should be added as part of the port, not deferred.
- **Vitest** for tests. JSDOM only where component tests need it; most tests are pure-function.
- **Zustand** for the hunt/enterprise/telemetry store. Prop-drilling will be painful at this scale; Context + reducer is fine but Zustand is less ceremony.
- **No CSS framework.** The artifact's inline CSS string moves to a single `src/styles/otter-shell.css` imported by the root component. Variables (`--amber`, `--teal`, etc.) are already CSS custom properties.
- **pnpm** as package manager (faster, deterministic).

If TypeScript is too heavy on day one, JavaScript with JSDoc types is acceptable — but the port loses one of its biggest wins.

## Target file tree

```
otter-shell/
├── README.md
├── LICENSE
├── package.json
├── pnpm-lock.yaml
├── tsconfig.json
├── vite.config.ts
├── vitest.config.ts
├── .eslintrc.cjs
├── .prettierrc
├── .github/
│   └── workflows/
│       └── ci.yml                  # typecheck + test on PR
├── public/
│   └── favicon.svg
├── src/
│   ├── main.tsx                    # React mount
│   ├── App.tsx                     # the OtterShell root component, slimmed
│   ├── styles/
│   │   └── otter-shell.css         # the CSS string from the artifact
│   ├── data/
│   │   ├── platforms.ts            # PLATFORMS, PLATFORM_IDS
│   │   ├── enterprises.ts          # ENTERPRISES (the 5), ALL_INDUSTRIES
│   │   ├── hunts.ts                # HUNTS (the 18)
│   │   ├── telemetry.ts            # TELEMETRY, REQUIRES
│   │   ├── tactics.ts              # TACTIC_ORDER, TACTIC_MAP, CAT, LEVEL_MAP
│   │   ├── severity.ts             # SEVERITIES, SEV_COLOR
│   │   ├── lifecycle.ts            # STATUSES, STATUS_META, SIGMA_STATUS
│   │   ├── dispositions.ts         # DISPOSITIONS, DISPO_META
│   │   └── kev-feed.ts             # KEV_FEED_URLS, KEV_STOP
│   ├── lib/
│   │   ├── lifecycle.ts            # withLifecycle, todayISO
│   │   ├── sigma/
│   │   │   ├── parse.ts            # parseYamlSubset, sigmaToHunt
│   │   │   ├── emit.ts             # yamlScalar, emitYaml, literalBlock, huntToSigma
│   │   │   └── builders.ts         # buildQuery (per-platform Sigma -> native)
│   │   ├── kev.ts                  # loadKevCatalog, stackKeywords, matchKev
│   │   ├── nav.ts                  # buildNavLayer, techIdOf
│   │   ├── lint.ts                 # stripLiterals, bracketsBalanced, lintQuery
│   │   ├── markdown.ts             # mdEscape, huntToMarkdown, programToMarkdown
│   │   ├── enrichment.ts           # enrichLinks
│   │   ├── atomic.ts               # atomicUrl
│   │   ├── normalize.ts            # normalizeHunt (for generator output)
│   │   └── download.ts             # downloadText (Blob + anchor + clipboard fallback)
│   ├── store/
│   │   └── hunt-store.ts           # Zustand store: hunts, customEnts, telemetry, etc.
│   ├── api/
│   │   └── claude.ts               # the fetch wrapper, hits the proxy
│   ├── components/
│   │   ├── Shell.tsx               # header, tabs, modal mount, toast
│   │   ├── EnterprisePicker.tsx
│   │   ├── Tabs.tsx
│   │   ├── landscape/
│   │   │   ├── ThreatLandscape.tsx
│   │   │   ├── ActorCard.tsx
│   │   │   └── PostureBlock.tsx
│   │   ├── hunts/
│   │   │   ├── HuntLibrary.tsx     # top-level: rail + list + detail layout
│   │   │   ├── HuntRail.tsx
│   │   │   ├── HuntList.tsx
│   │   │   ├── HuntDetail.tsx
│   │   │   ├── LifecyclePanel.tsx
│   │   │   ├── QueryView.tsx
│   │   │   ├── LintReadout.tsx
│   │   │   └── HuntJournal.tsx
│   │   ├── coverage/
│   │   │   ├── Coverage.tsx
│   │   │   ├── ActivityCard.tsx
│   │   │   ├── CoverageMatrix.tsx
│   │   │   ├── LifecycleSummary.tsx
│   │   │   ├── TelemetryAudit.tsx
│   │   │   └── KevExposure.tsx
│   │   ├── forge/
│   │   │   ├── Forge.tsx
│   │   │   ├── Generator.tsx
│   │   │   ├── HuntPreview.tsx
│   │   │   ├── SigmaImport.tsx
│   │   │   ├── JsonImport.tsx
│   │   │   ├── Workspace.tsx
│   │   │   └── SigmaExport.tsx
│   │   └── enterprise/
│   │       └── EnterpriseBuilder.tsx
│   └── types/
│       └── index.ts                # central type re-exports
├── tests/
│   ├── lib/
│   │   ├── sigma.test.ts           # round-trip + scaffold + structural checks
│   │   ├── kev.test.ts             # stackKeywords + matchKev incl. real CVEs
│   │   ├── lint.test.ts            # zero-false-positive corpus
│   │   ├── markdown.test.ts        # huntToMarkdown + programToMarkdown
│   │   ├── enrichment.test.ts      # type detection + encoding
│   │   ├── nav.test.ts             # Navigator layer shape
│   │   ├── lifecycle.test.ts       # withLifecycle defaults
│   │   └── normalize.test.ts       # generator output clamping
│   ├── store/
│   │   └── hunt-store.test.ts      # workspace round-trip, custom ent inherits
│   └── fixtures/
│       ├── curated-queries.ts      # all 18 hunts' queries (linter corpus)
│       ├── kev-rows.ts             # real KEV catalog rows (Ivanti, Citrix Bleed, PAN-OS, control)
│       └── sigma-samples.yml       # round-trip cases
└── proxy/
    ├── README.md
    ├── pyproject.toml
    └── main.py                     # FastAPI proxy, see 03_PROXY_CONTRACT.md
```

## Module boundaries

The **data** layer is pure constants and `.ts` data literals. No functions, no side effects, no React.

The **lib** layer is pure functions with explicit input/output. No React imports, no DOM, no global state. Every file in `lib/` is independently testable with `vitest run tests/lib/*.test.ts`. The one exception is `lib/download.ts` which touches `document` and `URL.createObjectURL` — extract those calls behind an interface so the function is mockable in tests.

The **store** is the single source of mutable state. All hunt mutations, enterprise mutations, telemetry toggles, workspace save/load, KEV scan results, and AI generation results live here. Components subscribe with Zustand selectors. The store imports from `lib/` and `data/` but never from `components/`.

**Components** are presentational. They read from the store via selectors, dispatch via the store's actions, and call `lib/` functions for pure transforms. A component file should have no `useState` for application state — only for local UI ephemera (form drafts, hover states, dropdown open/closed). The hunt journal's draft note/IOC are local; the findings list itself comes from the store.

The **api** layer is a single file that wraps `fetch` to the proxy. It validates the response shape, handles errors, and is the only place that talks to the backend. Components call `generate()`, `intelGenerate()`, `kevGenerate()` — they don't know about the proxy URL.

## Type model

Day-one types — refine as you go but start here.

```ts
// src/types/index.ts

export type PlatformId =
  | "crowdstrike" | "xsiam" | "sentinel"
  | "defender" | "elastic" | "secops" | "splunk";

export type Severity = "Critical" | "High" | "Medium" | "Low";
export type Status = "new" | "in-progress" | "validated" | "retired";
export type Disposition = "clean" | "suspicious" | "confirmed" | "inconclusive";
export type DataSource =
  | "Endpoint / EDR" | "Identity / IdP" | "Cloud / SaaS"
  | "DNS" | "Web Proxy" | "Windows Event Logs";

export interface Finding {
  date: string;          // ISO YYYY-MM-DD
  disposition: Disposition;
  note: string;
}

export interface Hunt {
  id: string;
  custom?: boolean;
  name: string;
  technique: string;
  tactic: string;
  sev: Severity;
  source: DataSource;
  industries: string[];  // enterprise ids
  hypothesis: string;
  fp: string;
  note?: string;
  queries: Partial<Record<PlatformId, string>>;
  // lifecycle
  status: Status;
  version: number;
  author: string;
  created: string;       // ISO YYYY-MM-DD or ""
  reviewed: string;      // ISO YYYY-MM-DD or ""
  // journal
  findings: Finding[];
  pivots: string;
  tuning: string;
  // sigma round-trip
  _sigma?: {
    title: string;
    logsource: Record<string, string>;
    detection: Record<string, unknown>;
    level: string;
    tags: string[];
    description: string;
    falsepositives: string[];
  };
}

export interface Actor {
  name: string;
  origin: string;
  motive: string;
  sev: Severity;
  detail: string;
}

export interface Enterprise {
  id: string;
  custom?: boolean;
  name: string;
  sector: string;
  flag?: boolean;        // flagship badge (only the flagship profile)
  blurb: string;
  stack: string;
  posture: string[];
  techniques: string[];
  actors: Actor[];
  inherits?: string[];   // built-in enterprise ids whose hunts this draws from
}

export interface Workspace {
  schema: "otter-shell-workspace";
  version: 1;
  savedAt: string;
  customHunts: Hunt[];
  builtinMeta: Array<Pick<Hunt, "id" | "status" | "version" | "author" | "created" | "reviewed" | "findings" | "pivots" | "tuning">>;
  customEnterprises: Enterprise[];
  telemetry: string[];
}

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
  dateAdded: string;
  knownRansomwareCampaignUse: string;
}

export interface LintIssue {
  level: "warn" | "info";
  msg: string;
}
```

## State design (Zustand store sketch)

```ts
// src/store/hunt-store.ts (sketch — refine in port)
interface HuntStore {
  // state
  hunts: Hunt[];
  customEnts: Enterprise[];
  entId: string;
  telemetry: Set<string>;  // "have" set
  kevScan: Record<string, KevScanState>;  // by entId
  notice: string;          // toast text

  // selectors
  activeEnt: () => Enterprise;
  libForEnt: () => Hunt[];

  // hunt mutations
  addHunt: (h: Hunt) => void;
  updateHunt: (id: string, patch: Partial<Hunt>) => void;
  removeHunt: (id: string) => void;
  setStatus: (id: string, status: Status) => void;
  markReviewed: (id: string) => void;
  bumpVersion: (id: string, delta: number) => void;
  addFinding: (id: string, disposition: Disposition, note: string) => void;
  removeFinding: (id: string, idx: number) => void;
  setPivots: (id: string, text: string) => void;
  setTuning: (id: string, text: string) => void;

  // enterprise mutations
  addEnterprise: (e: Omit<Enterprise, "id" | "custom">) => void;
  deleteEnterprise: (id: string) => void;
  setEntId: (id: string) => void;

  // telemetry
  toggleTele: (t: string) => void;

  // workspace
  serializeWorkspace: () => Workspace;
  loadWorkspace: (ws: Workspace) => void;

  // notice
  flash: (msg: string) => void;
}
```

A single store keeps things obvious. Selectors (`libForEnt`, `activeEnt`) are derived inside the store using Zustand's `get()`.

## CSS strategy

The artifact's `CSS` string (the huge template literal) moves to `src/styles/otter-shell.css` and is `import`ed at the top of `main.tsx`. No template literal in JS. Custom properties (`--amber`, `--teal`, etc.) stay in `:root` exactly as today. Component-scoped CSS is not needed — the existing classnames (`qr-*`) are already namespaced and used consistently.

## API integration

```ts
// src/api/claude.ts
const PROXY_URL = import.meta.env.VITE_PROXY_URL ?? "http://localhost:8080";

export async function claudeMessages(body: {
  system: string;
  user: string;
  enableWebSearch?: boolean;
  maxTokens?: number;
}): Promise<{ content: Array<{ type: string; text?: string }> }> {
  const res = await fetch(PROXY_URL + "/api/claude", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error("Proxy returned " + res.status);
  return res.json();
}
```

Components don't call `fetch` directly. Generator code calls `claudeMessages({ system, user, enableWebSearch: true })` and extracts the JSON object from the text content the same way the artifact does today.

## What gets dropped on the floor (don't drop these)

The artifact has subtle behaviors that are easy to lose in a refactor. Keep them all:

- `HuntJournal` is `key={activeHunt.id}` so draft state resets when switching hunts.
- The KEV ransomware flag is `/^known$/i` (anchored) — not `/known/i`, which matches "Unknown".
- `.qr-hunt-row` uses `flex:0 0 auto` so rows don't shrink-clip in the scrolling list. Same fix on `.qr-modal-body > *`.
- `withLifecycle` is called at every entry point that adds hunts to the store: initial load, `addHunt`, `importJson`, `sigmaToHunt`, `loadWorkspace`. Don't bypass.
- `inheritsOf(ent)` falls back to `[ent.id]` for built-in enterprises, so the old `industries.includes(entId)` behavior is preserved.
- Workspace `builtinMeta` persists lifecycle *and* journal fields for built-ins (otherwise built-in status changes don't survive reload).
- The Sigma export's `status` field maps lifecycle correctly: `new→experimental`, `in-progress→test`, `validated→stable`, `retired→deprecated`.
- The query linter strips literals *before* counting brackets. Without the strip step, regex-heavy queries false-positive.

Anything not on this list, you can refactor freely.
