# Test Plan

The ad-hoc test harnesses run in the chat session that built this tool already catch real bugs. Codify them. Vitest, JSDOM where needed, fast. Aim for a green suite in under 10 seconds.

## What gets tested

**Tested aggressively:** every pure function in `src/lib/` plus the store's workspace round-trip and inherits filtering. These are deterministic, fast, and exactly the kind of thing that breaks silently in a refactor.

**Tested lightly:** components — one render smoke test per major component, no full interaction matrix. The artifact's UI bugs were almost all CSS-flexbox issues, which unit tests don't catch anyway.

**Not tested:** the AI generator's output content. The shape (JSON parseable, has expected keys) is validated by `normalize`, but what the model actually writes depends on the model and the prompt. Test the plumbing, not the words.

## Fixtures

Centralize in `tests/fixtures/` so every test pulls from the same sources of truth.

### `curated-queries.ts`

Export the full set of curated queries from the 18 hunts — by hunt id, by platform. This is the linter's zero-false-positive corpus. Any change that breaks linting against this fixture is a regression.

```ts
// tests/fixtures/curated-queries.ts
export const CURATED: Array<{ huntId: string; platform: PlatformId; query: string }> = [
  { huntId: "ps-enc", platform: "crowdstrike", query: `#event_simpleName=ProcessRollup2 ImageFileName=/powershell(_ise)?\\.exe$/i
| CommandLine=/(-enc|-encodedcommand|frombase64string)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])` },
  // ... 17 more × 7 platforms = ~126 entries
];
```

### `kev-rows.ts`

The real CVEs used in chat-session validation. These are the integration regression set:

```ts
export const KEV_FIXTURES = {
  ivanti_cve_2025_0282: {
    cveID: "CVE-2025-0282",
    vendorProject: "Ivanti",
    product: "Connect Secure, Policy Secure, and ZTA Gateways",
    vulnerabilityName: "Ivanti Connect Secure Stack-Based Buffer Overflow Vulnerability",
    shortDescription: "...",
    dateAdded: "2025-01-08",
    knownRansomwareCampaignUse: "Unknown",
  },
  citrix_bleed: {
    cveID: "CVE-2023-4966",
    vendorProject: "Citrix",
    product: "NetScaler ADC and NetScaler Gateway",
    vulnerabilityName: "Citrix NetScaler ADC and Gateway Buffer Overflow",
    shortDescription: "...",
    dateAdded: "2023-10-18",
    knownRansomwareCampaignUse: "Known",
  },
  panos_gp: {
    cveID: "CVE-2024-3400",
    vendorProject: "Palo Alto Networks",
    product: "PAN-OS GlobalProtect",
    vulnerabilityName: "Palo Alto Networks PAN-OS Command Injection Vulnerability",
    shortDescription: "...",
    dateAdded: "2024-04-12",
    knownRansomwareCampaignUse: "Unknown",
  },
  acme_control: {
    cveID: "CVE-2099-0000",
    vendorProject: "Acme",
    product: "Widget",
    vulnerabilityName: "Unrelated control row",
    shortDescription: "must not match any real stack",
    dateAdded: "2099-01-01",
    knownRansomwareCampaignUse: "Unknown",
  },
};
```

### `sigma-samples.yml`

A small set of Sigma rules covering: simple selection, list values, modifiers (`|contains`, `|endswith`), nested maps, condition variants. Used for round-trip parse-then-emit tests.

## The day-one test suite

### `tests/lib/lifecycle.test.ts`

```ts
import { withLifecycle, todayISO } from "@/lib/lifecycle";

test("withLifecycle fills defaults on bare hunt", () => {
  const h = withLifecycle({ id: "x", name: "Test" } as any);
  expect(h.status).toBe("new");
  expect(h.version).toBe(1);
  expect(h.author).toBe("Otter Shell");
  expect(h.findings).toEqual([]);
  expect(h.pivots).toBe("");
  expect(h.tuning).toBe("");
});

test("withLifecycle preserves valid existing values", () => {
  const h = withLifecycle({
    id: "x", name: "T", status: "validated", version: 3,
    author: "analyst", findings: [{ date: "2026-05-01", disposition: "clean", note: "" }],
  } as any);
  expect(h.status).toBe("validated");
  expect(h.version).toBe(3);
  expect(h.author).toBe("analyst");
  expect(h.findings).toHaveLength(1);
});

test("withLifecycle rejects invalid status", () => {
  const h = withLifecycle({ id: "x", name: "T", status: "wat" } as any);
  expect(h.status).toBe("new");
});
```

### `tests/lib/sigma.test.ts`

```ts
import { sigmaToHunt } from "@/lib/sigma/parse";
import { huntToSigma } from "@/lib/sigma/emit";

test("Sigma round-trip: imported hunt re-emits with same detection block", () => {
  const input = `title: Suspicious Encoded PowerShell
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: \\powershell.exe
    CommandLine|contains:
      - '-enc'
      - FromBase64String
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001`;
  const hunt = sigmaToHunt(input);
  const out = huntToSigma(hunt);
  expect(out).toContain("Image|endswith: \\powershell.exe");
  expect(out).toContain("CommandLine|contains:");
  expect(out).toContain("- '-enc'");
  expect(out).toContain("- FromBase64String");
  expect(out).toContain("attack.t1059.001");
});

test("Sigma scaffold: curated hunt produces valid Sigma with TODO and native queries preserved", () => {
  const hunt = {
    name: "Encoded PowerShell", technique: "T1059.001", tactic: "Execution",
    source: "Endpoint / EDR", sev: "High", status: "new", version: 1,
    queries: { splunk: 'index=edr command_line="*-enc*"' },
  } as any;
  const out = huntToSigma(hunt);
  expect(out).toMatch(/^title: /m);
  expect(out).toMatch(/^id: '[0-9a-f-]{36}'/m);
  expect(out).toContain("attack.execution");
  expect(out).toContain("attack.t1059.001");
  expect(out).toContain("category: process_creation");
  expect(out).toContain("TODO: replace");
  expect(out).toContain("ottershell_queries:");
  expect(out).toContain("splunk: |");
  expect(out).not.toMatch(/\t/);  // no tabs in YAML
});

test("Sigma export lifecycle mapping: validated -> stable, modified from reviewed", () => {
  const hunt = {
    name: "T", technique: "T1059.001", tactic: "Execution", source: "Endpoint / EDR",
    sev: "High", status: "validated", version: 1, author: "analyst",
    created: "2026-05-01", reviewed: "2026-05-28",
    queries: { splunk: "index=edr" },
  } as any;
  const out = huntToSigma(hunt);
  expect(out).toMatch(/^status: stable/m);
  expect(out).toMatch(/^author: analyst/m);
  expect(out).toMatch(/^date: 2026\/05\/01/m);
  expect(out).toMatch(/^modified: 2026\/05\/28/m);
});
```

### `tests/lib/kev.test.ts`

```ts
import { stackKeywords, matchKev } from "@/lib/kev";
import { KEV_FIXTURES } from "../fixtures/kev-rows";

test("flagship lab stack flags Ivanti CVE-2025-0282", () => {
  const stack = "Ivanti Connect Secure / Palo Alto GlobalProtect VPN, Microsoft Exchange + M365, Cisco edge appliances, VMware vCenter/ESXi";
  const kw = stackKeywords(stack);
  const matched = matchKev([KEV_FIXTURES.ivanti_cve_2025_0282, KEV_FIXTURES.acme_control], kw, 12);
  expect(kw).toContain("ivanti");
  expect(matched.find(m => m.cve === "CVE-2025-0282")).toBeDefined();
  expect(matched.find(m => m.cve === "CVE-2099-0000")).toBeUndefined();
});

test("Citrix Bleed flagged with ransomware=true (anchored regex)", () => {
  const stack = "Citrix NetScaler, F5 BIG-IP";
  const matched = matchKev([KEV_FIXTURES.citrix_bleed], stackKeywords(stack), 12);
  expect(matched[0].ransomware).toBe(true);
});

test("PAN-OS flagged with ransomware=false (Unknown must not match)", () => {
  const stack = "Palo Alto GlobalProtect VPN";
  const matched = matchKev([KEV_FIXTURES.panos_gp], stackKeywords(stack), 12);
  expect(matched[0].ransomware).toBe(false);
});

test("KEV_STOP excludes generic words", () => {
  const kw = stackKeywords("VPN edge appliance gateway");
  expect(kw).not.toContain("vpn");
  expect(kw).not.toContain("edge");
  expect(kw).not.toContain("appliance");
  expect(kw).not.toContain("gateway");
});
```

### `tests/lib/lint.test.ts`

The most important file. Goal: **zero false-positive warnings on the curated corpus.**

```ts
import { lintQuery } from "@/lib/lint";
import { CURATED } from "../fixtures/curated-queries";

describe("zero false positives on curated library", () => {
  for (const { huntId, platform, query } of CURATED) {
    test(`${huntId}/${platform} has no warn-level lint`, () => {
      const issues = lintQuery(platform, query);
      const warns = issues.filter(i => i.level === "warn");
      expect(warns).toEqual([]);
    });
  }
});

test("catches deliberate bracket truncation", () => {
  const issues = lintQuery("splunk", `index=edr (process_name IN ("a.exe","b.exe")
| table _time host`);
  expect(issues.some(i => i.level === "warn" && /bracket/i.test(i.msg))).toBe(true);
});

test("comment-only stub returns info-only (covered elsewhere)", () => {
  const issues = lintQuery("defender", "// not native — see other platforms");
  expect(issues.filter(i => i.level === "warn")).toHaveLength(0);
  expect(issues.some(i => /covered by the other platforms/.test(i.msg))).toBe(true);
});

test("placeholder produces info-only", () => {
  const issues = lintQuery("splunk", `index=dns src_ip="<APPLIANCE_IP>"
| bucket _time span=10m`);
  expect(issues.filter(i => i.level === "warn")).toHaveLength(0);
  expect(issues.some(i => /placeholder/i.test(i.msg))).toBe(true);
});

test("SecOps rule does not get time-window nudge", () => {
  const issues = lintQuery("secops", `rule x {
  meta: description = "y"
  events: $e.metadata.event_type = "NETWORK_DNS"
  condition: $e
}`);
  expect(issues.some(i => /time window/i.test(i.msg))).toBe(false);
});
```

### `tests/lib/markdown.test.ts`

```ts
import { huntToMarkdown, programToMarkdown } from "@/lib/markdown";

const sampleHunt = {
  name: "Citrix Bleed Session Hijack",
  technique: "T1539 — Steal Web Session Cookie", tactic: "Credential Access",
  source: "Identity / IdP", sev: "Critical",
  status: "validated", version: 2, author: "analyst",
  created: "2026-05-01", reviewed: "2026-05-20",
  hypothesis: "Token replayed from a new IP.",
  fp: "Mobile roaming.", pivots: "Pull parent sessions.", tuning: "2 IPs/30m.",
  findings: [
    { date: "2026-05-28", disposition: "clean", note: "Scoped, no hits." },
  ],
  queries: { splunk: "index=netscaler" },
} as any;

test("per-hunt report has H1, metadata, journal sections, fenced queries", () => {
  const md = huntToMarkdown(sampleHunt);
  expect(md).toMatch(/^# Citrix Bleed/);
  expect(md).toContain("**Status:** Validated");
  expect(md).toContain("## Findings");
  expect(md).toContain("| Date | Disposition | Note |");
  expect(md).toContain("```");
  expect(md).toContain("Splunk (SPL)");
});

test("pipe in note is escaped in table cell", () => {
  const h = { ...sampleHunt, findings: [{ date: "2026-05-01", disposition: "clean", note: "a | b" }] };
  expect(huntToMarkdown(h)).toContain("a \\| b");
});

test("program report aggregates lifecycle, recent findings, hunt index", () => {
  const md = programToMarkdown([sampleHunt], "Regional Energy Utility");
  expect(md).toMatch(/^# Otter Shell/);
  expect(md).toContain("| Status | Count |");
  expect(md).toContain("| Date | Hunt | Disposition | Note |");
  expect(md).toContain("| Status | Severity | Hunt |");
});
```

### `tests/lib/enrichment.test.ts`

```ts
import { enrichLinks } from "@/lib/enrichment";

test("IP -> 4 links", () => {
  const l = enrichLinks("8.8.8.8");
  expect(l.map(x => x.label)).toEqual(["VirusTotal", "GreyNoise", "Shodan", "AbuseIPDB"]);
  expect(l[0].url).toBe("https://www.virustotal.com/gui/ip-address/8.8.8.8");
});

test("MD5/SHA1/SHA256 -> file lookup", () => {
  for (const h of ["d".repeat(32), "d".repeat(40), "d".repeat(64)]) {
    expect(enrichLinks(h)[0].url).toMatch(/\/gui\/file\//);
  }
});

test("Domain -> VT + urlscan + Shodan", () => {
  expect(enrichLinks("evil.test").map(x => x.label)).toEqual(["VirusTotal", "urlscan", "Shodan"]);
});

test("URL -> urlscan first", () => {
  expect(enrichLinks("http://x.test/a")[0].label).toBe("urlscan");
});

test("Unknown -> search fallback (1 link)", () => {
  const l = enrichLinks("not an ioc");
  expect(l).toHaveLength(1);
  expect(l[0].url).toMatch(/search/);
});

test("encodes whitespace", () => {
  expect(enrichLinks("a b.com")[0].url).toContain("a%20b.com");
});

test("empty -> []", () => {
  expect(enrichLinks("")).toEqual([]);
});
```

### `tests/lib/normalize.test.ts`

```ts
import { normalizeHunt } from "@/lib/normalize";

test("clamps long strings", () => {
  const h = normalizeHunt({ name: "x".repeat(500), queries: {} });
  expect(h.name.length).toBeLessThanOrEqual(160);
});

test("coerces missing queries to empty object", () => {
  const h = normalizeHunt({ name: "t" });
  expect(h.queries).toEqual({});
});

test("rejects invalid severity, defaults to Medium", () => {
  const h = normalizeHunt({ name: "t", sev: "Catastrophic", queries: {} });
  expect(h.sev).toBe("Medium");
});

test("includes lifecycle defaults", () => {
  const h = normalizeHunt({ name: "t", queries: {} });
  expect(h.status).toBe("new");
  expect(h.version).toBe(1);
  expect(h.findings).toEqual([]);
});
```

### `tests/lib/nav.test.ts`

```ts
import { buildNavLayer } from "@/lib/nav";

test("Navigator layer has correct top-level shape", () => {
  const layer = buildNavLayer([], { name: "Test", sector: "Test" } as any);
  expect(layer.versions).toEqual({ attack: "15", navigator: "4.9.1", layer: "4.5" });
  expect(layer.domain).toBe("enterprise-attack");
  expect(Array.isArray(layer.techniques)).toBe(true);
});

test("technique entries include score and ATT&CK id", () => {
  const hunts = [{ technique: "T1059.001 — PowerShell", name: "x" }] as any;
  const layer = buildNavLayer(hunts, { name: "T", sector: "T" } as any);
  const t = layer.techniques.find((x: any) => x.techniqueID === "T1059.001");
  expect(t).toBeDefined();
  expect(t.score).toBeGreaterThan(0);
});
```

### `tests/store/hunt-store.test.ts`

```ts
import { createHuntStore } from "@/store/hunt-store";

test("workspace serialize/load preserves custom hunts, builtin lifecycle, custom enterprises, telemetry", () => {
  const s = createHuntStore();
  s.addHunt({ name: "Custom", queries: { splunk: "x" } } as any);
  s.setStatus("ps-enc", "validated");
  s.addFinding("ps-enc", "clean", "no hits");
  s.toggleTele("Process Creation (EDR)");

  const ws = s.serializeWorkspace();
  const fresh = createHuntStore();
  fresh.loadWorkspace(ws);

  expect(fresh.hunts.find(h => h.name === "Custom")).toBeDefined();
  expect(fresh.hunts.find(h => h.id === "ps-enc")?.status).toBe("validated");
  expect(fresh.hunts.find(h => h.id === "ps-enc")?.findings).toHaveLength(1);
});

test("custom enterprise with inherits draws hunts from those sectors only", () => {
  const s = createHuntStore();
  s.addEnterprise({ name: "OT Co", sector: "Manufacturing", inherits: ["tech"], stack: "", blurb: "", posture: [], techniques: [], actors: [] } as any);
  const ent = s.customEnts.at(-1)!;
  s.setEntId(ent.id);
  const lib = s.libForEnt();
  expect(lib.every(h => h.industries.includes("tech"))).toBe(true);
});

test("addEnterprise with empty inherits falls back to all built-ins", () => {
  const s = createHuntStore();
  s.addEnterprise({ name: "X", sector: "X", inherits: [], stack: "", blurb: "", posture: [], techniques: [], actors: [] } as any);
  expect(s.customEnts.at(-1)!.inherits).toEqual(["utility", "gov", "tech", "health", "finance"]);
});
```

### `tests/components/*.test.tsx` (smoke tests only)

```tsx
import { render } from "@testing-library/react";
import { describe, test, expect } from "vitest";
import { App } from "@/App";

test("App renders without crashing", () => {
  const { container } = render(<App />);
  expect(container.querySelector("header")).toBeDefined();
});
```

One smoke test per major component is enough — `<HuntLibrary>`, `<Coverage>`, `<Forge>`, `<EnterpriseBuilder>`, `<HuntJournal>`. The artifact's UI bugs were all CSS-flexbox issues that don't surface in JSDOM; deep interaction tests aren't worth the maintenance cost at this size.

## CI

`.github/workflows/ci.yml`:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v3
        with: { version: 9 }
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: pnpm }
      - run: pnpm install --frozen-lockfile
      - run: pnpm typecheck
      - run: pnpm test --run
      - run: pnpm build
```

A green CI run is the acceptance gate for Phase 5 (see `01_MIGRATION_PLAN.md`).

## Coverage targets

Not %. Behaviors:

- Every public lib export has at least one test that calls it.
- Every fixture CVE in `kev-rows.ts` is matched correctly.
- Every curated query in `curated-queries.ts` lints clean.
- Sigma round-trip works for every sample in `sigma-samples.yml`.
- Workspace round-trip is tested.
- Custom enterprise inherits behavior is tested.

If those hold and the smoke tests pass, the suite is doing its job.
