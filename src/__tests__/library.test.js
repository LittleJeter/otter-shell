/**
 * Library invariants, Sigma round-trip, linter behaviour and export shapes.
 * Follows the intent of migration/04_TEST_PLAN.md.
 */
import { describe, it, expect } from "vitest";
import {
  HUNTS, PLATFORM_IDS, SEVERITIES, DATA_SOURCES, ALL_INDUSTRIES,
  withLifecycle, lintQuery, sigmaToHunt, huntToSigma, techIdOf, techChips, atomicUrl,
  enrichLinks, buildNavLayer, matchKev, stackKeywords, huntToMarkdown, sanitizeEnterprise,
} from "../OtterShell.jsx";

describe("curated hunt library", () => {
  it("ships the documented 18 hunts with unique ids", () => {
    expect(HUNTS).toHaveLength(18);
    expect(new Set(HUNTS.map((h) => h.id)).size).toBe(18);
  });

  it("gives every hunt a query for all seven platforms", () => {
    for (const h of HUNTS) {
      for (const p of PLATFORM_IDS) {
        expect(typeof h.queries[p], `${h.id} is missing a ${p} query`).toBe("string");
        expect(h.queries[p].trim().length, `${h.id}/${p} is empty`).toBeGreaterThan(0);
      }
    }
  });

  it("only claims industries that exist", () => {
    for (const h of HUNTS) {
      if (!h.industries) continue;
      for (const i of h.industries) expect(ALL_INDUSTRIES, `${h.id} targets unknown industry ${i}`).toContain(i);
    }
  });

  it("uses only valid severities and data sources", () => {
    for (const h of HUNTS) {
      expect(SEVERITIES).toContain(h.sev);
      expect(DATA_SOURCES).toContain(h.source);
    }
  });

  it("carries a hypothesis and false-positive guidance on every hunt", () => {
    for (const h of HUNTS) {
      expect(h.hypothesis.length, `${h.id} has no hypothesis`).toBeGreaterThan(20);
      expect(h.fp.length, `${h.id} has no FP guidance`).toBeGreaterThan(10);
    }
  });
});

describe("query linter", () => {
  // The linter is only useful if it stays quiet on the curated library. A warning
  // here means either a real query defect or a linter false positive.
  it("raises no warnings against any curated query", () => {
    const warnings = [];
    for (const h of HUNTS) {
      for (const p of PLATFORM_IDS) {
        for (const r of lintQuery(p, h.queries[p])) {
          if (r.level === "warn") warnings.push(`${h.id}/${p}: ${r.msg}`);
        }
      }
    }
    expect(warnings).toEqual([]);
  });

  it("flags unbalanced brackets", () => {
    const out = lintQuery("splunk", 'index=main | stats count by (host');
    expect(out.some((r) => r.level === "warn" && /unbalanced/i.test(r.msg))).toBe(true);
  });

  it("does not false-positive on brackets inside string and regex literals", () => {
    const out = lintQuery("splunk", 'index=main earliest=-24h | regex cmd="\\(foo\\[" | search msg="a)b"');
    expect(out.some((r) => r.level === "warn")).toBe(false);
  });

  it("notes placeholders and a missing time window", () => {
    const out = lintQuery("splunk", "index=main host=<HOSTNAME>");
    expect(out.some((r) => /placeholder/i.test(r.msg))).toBe(true);
    expect(out.some((r) => /time window/i.test(r.msg))).toBe(true);
  });

  it("keeps the time-window nudge informational, not a warning", () => {
    // The README claims zero warnings across the curated library; that claim is only
    // meaningful if the common nudges stay at info level.
    const out = lintQuery("splunk", "index=main | stats count by host");
    const tw = out.find((r) => /time window/i.test(r.msg));
    expect(tw).toBeTruthy();
    expect(tw.level).toBe("info");
  });

  it("returns an informational note rather than throwing on an empty query", () => {
    expect(lintQuery("splunk", "")[0].level).toBe("info");
    expect(lintQuery("splunk", null)[0].level).toBe("info");
  });
});

describe("Sigma round-trip", () => {
  const RULE = `title: Suspicious Encoded PowerShell
status: experimental
description: Detects base64-encoded PowerShell command lines
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
falsepositives:
  - Administrative scripts
level: high
`;

  it("imports a Sigma rule into a hunt with queries for every platform", () => {
    const h = sigmaToHunt(RULE);
    expect(h.name).toBe("Suspicious Encoded PowerShell");
    expect(h.technique).toContain("T1059.001");
    for (const p of PLATFORM_IDS) expect(typeof h.queries[p]).toBe("string");
  });

  it("round-trips back to Sigma preserving title and technique tag", () => {
    const y = huntToSigma(withLifecycle({ ...sigmaToHunt(RULE), custom: true }));
    expect(y).toContain("Suspicious Encoded PowerShell");
    expect(y.toLowerCase()).toContain("t1059.001");
    expect(y).toContain("logsource:");
    expect(y).toContain("detection:");
  });

  it("exports a curated hunt as Sigma with metadata and native queries preserved", () => {
    const y = huntToSigma(withLifecycle(HUNTS[0]));
    expect(y).toContain("title:");
    expect(y).toContain("ottershell_queries");
  });

  it("rejects YAML with no detection block", () => {
    expect(() => sigmaToHunt("title: x\nlogsource:\n  category: process_creation\n")).toThrow();
  });
});

describe("ATT&CK helpers", () => {
  it("extracts a technique id, including sub-techniques", () => {
    expect(techIdOf({ technique: "T1059.001 — PowerShell" })).toBe("T1059.001");
    expect(techIdOf({ technique: "T1486 — Data Encrypted for Impact" })).toBe("T1486");
    expect(techIdOf({ technique: "—" })).toBeFalsy();
  });

  it("renders one coverage chip per technique, counting the hunts behind it", () => {
    // Two hunts on the same technique used to print the id twice in a tactic column,
    // which reads as a duplicate rather than as depth.
    const chips = techChips([
      { name: "Curated cloud exfil", technique: "T1530 — Data from Cloud Storage", sev: "High" },
      { name: "Custom cloud exfil", technique: "T1530 / T1567.002 — Cloud Data", sev: "Critical" },
      { name: "Kerberoasting", technique: "T1558.003 — Kerberoasting", sev: "High" },
    ]);
    expect(chips.map((c) => c.id)).toEqual(["T1530", "T1558.003"]);
    expect(chips[0].count).toBe(2);
    expect(chips[0].sev).toBe("Critical"); // the chip carries the worst severity it covers
    expect(chips[0].hunts).toHaveLength(2);
    expect(chips[1].count).toBe(1);
  });

  it("keeps the coverage chips in tactic-column order and survives a missing technique", () => {
    expect(techChips([{ name: "No id", technique: "—", sev: "Low" }]).map((c) => c.id)).toEqual(["—"]);
    expect(techChips([])).toEqual([]);
  });

  it("builds an Atomic Red Team URL only when a technique id exists", () => {
    expect(atomicUrl({ technique: "T1059.001 — PowerShell" })).toContain("/atomics/T1059.001");
    expect(atomicUrl({ technique: "—" })).toBeNull();
  });

  it("produces a Navigator layer scoring each technique by hunt count", () => {
    const layer = buildNavLayer(HUNTS.map(withLifecycle), { name: "Test Org" });
    expect(layer.domain).toBe("enterprise-attack");
    expect(layer.techniques.length).toBeGreaterThan(0);
    for (const t of layer.techniques) {
      expect(t.techniqueID).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(t.score).toBeGreaterThan(0);
    }
  });
});

describe("IOC enrichment links", () => {
  it("detects an IPv4 address", () => {
    const l = enrichLinks("8.8.8.8").map((x) => x.label);
    expect(l).toContain("GreyNoise");
    expect(l).toContain("AbuseIPDB");
  });

  it("detects hashes by length", () => {
    expect(enrichLinks("a".repeat(64)).map((x) => x.label)).toContain("MalwareBazaar");
    expect(enrichLinks("a".repeat(32)).map((x) => x.label)).toContain("VirusTotal");
  });

  it("detects a domain and a URL", () => {
    expect(enrichLinks("evil.example.com").map((x) => x.label)).toContain("Shodan");
    expect(enrichLinks("https://evil.example.com/x").map((x) => x.label)).toContain("urlscan");
  });

  it("only ever emits https URLs and percent-encodes the indicator", () => {
    // A hostile indicator must not be able to produce a javascript: href.
    for (const l of enrichLinks('javascript:alert(1)//"><img src=x>')) {
      expect(l.url.startsWith("https://")).toBe(true);
      expect(l.url).not.toContain("<");
      expect(l.url).not.toContain('"');
    }
    expect(enrichLinks("")).toEqual([]);
  });
});

describe("CISA KEV matching", () => {
  const CATALOG = [
    { cveID: "CVE-2025-0282", vendorProject: "Ivanti", product: "Connect Secure", shortDescription: "Stack overflow", dateAdded: "2025-01-08", knownRansomwareCampaignUse: "Known" },
    { cveID: "CVE-2024-3400", vendorProject: "Palo Alto Networks", product: "PAN-OS", shortDescription: "Command injection", dateAdded: "2024-04-12", knownRansomwareCampaignUse: "Unknown" },
    { cveID: "CVE-2023-4966", vendorProject: "Citrix", product: "NetScaler ADC", shortDescription: "Buffer overflow", dateAdded: "2023-10-18", knownRansomwareCampaignUse: "Known" },
  ];

  it("matches on stack keywords and sorts newest first", () => {
    const hits = matchKev(CATALOG, stackKeywords("Ivanti Connect Secure, Citrix NetScaler"), 12);
    expect(hits.map((h) => h.cve)).toEqual(["CVE-2025-0282", "CVE-2023-4966"]);
  });

  it("flags ransomware-associated CVEs", () => {
    expect(matchKev(CATALOG, stackKeywords("Ivanti"), 12)[0].ransomware).toBe(true);
    expect(matchKev(CATALOG, stackKeywords("Palo Alto"), 12)[0].ransomware).toBe(false);
  });

  it("respects the limit and returns nothing without keywords", () => {
    // A stack lists its products comma-separated; the words inside one entry are ANDed,
    // so three vendors have to be three entries to match three CVEs.
    expect(matchKev(CATALOG, stackKeywords("Ivanti, Citrix, Palo Alto"), 1)).toHaveLength(1);
    expect(matchKev(CATALOG, [], 12)).toEqual([]);
  });

  it("does not let a bare vendor name select the vendor's whole catalog", () => {
    // The defect this pins: "Microsoft Exchange" used to also emit "microsoft" as a
    // keyword of its own, which matched every Microsoft entry in KEV — 386 of 1,687 in
    // the September 2026 catalog, presented as one org's internet-facing exposure.
    const msft = [
      { cveID: "CVE-A", vendorProject: "Microsoft", product: "Exchange Server", dateAdded: "2025-01-01" },
      { cveID: "CVE-B", vendorProject: "Microsoft", product: "SharePoint", dateAdded: "2025-01-02" },
      { cveID: "CVE-C", vendorProject: "Microsoft", product: "Windows Ancillary Function Driver for WinSock", dateAdded: "2025-01-03" },
    ];
    expect(stackKeywords("Microsoft Exchange")).toEqual(["microsoft exchange"]);
    expect(matchKev(msft, stackKeywords("Microsoft Exchange"), 12).map((h) => h.cve)).toEqual(["CVE-A"]);
  });

  it("matches a vendor+product term whose words are not adjacent in the feed", () => {
    const cisco = [{ cveID: "CVE-D", vendorProject: "Cisco", product: "Secure Firewall Adaptive Security Appliance (ASA) and Threat Defense (FTD)", dateAdded: "2026-08-11" }];
    expect(matchKev(cisco, stackKeywords("Cisco ASA"), 12).map((h) => h.cve)).toEqual(["CVE-D"]);
    // ...but the vendor on its own is not enough.
    expect(matchKev(cisco, stackKeywords("Cisco Firepower"), 12)).toEqual([]);
  });

  it("renders a vendor repeated as its own product only once", () => {
    const dup = [{ cveID: "CVE-E", vendorProject: "Microsoft", product: "Microsoft", vulnerabilityName: "Microsoft Exchange Server Cross-Site Scripting Vulnerability", dateAdded: "2026-05-15" }];
    expect(matchKev(dup, stackKeywords("Microsoft Exchange"), 12)[0].product).toBe("Microsoft");
  });

  it("caps oversized fields from the remote feed", () => {
    const hostile = [{ cveID: "CVE-1", vendorProject: "Ivanti", product: "P".repeat(9999), shortDescription: "D".repeat(9999), dateAdded: "2025-01-01" }];
    const [hit] = matchKev(hostile, stackKeywords("Ivanti"), 12);
    expect(hit.product.length).toBeLessThanOrEqual(160);
    expect(hit.desc.length).toBeLessThanOrEqual(400);
  });

  it("ends a truncated description at a word boundary with an ellipsis", () => {
    const long = "Ivanti Sentry contains an OS command injection vulnerability. " + "word ".repeat(200);
    const [hit] = matchKev([{ cveID: "CVE-2", vendorProject: "Ivanti", product: "Sentry", shortDescription: long, dateAdded: "2025-01-01" }], stackKeywords("Ivanti"), 12);
    expect(hit.desc.length).toBeLessThanOrEqual(400);
    expect(hit.desc.endsWith("\u2026")).toBe(true);
    // the kept text is a prefix of the original that ends where a word ends
    const body = hit.desc.slice(0, -1);
    expect(long.startsWith(body)).toBe(true);
    expect(/\s/.test(long.charAt(body.length))).toBe(true);
  });
});

describe("markdown export", () => {
  it("renders the hunt with a title, metadata and fenced queries", () => {
    const md = huntToMarkdown(withLifecycle(HUNTS[0]));
    expect(md).toContain("# " + HUNTS[0].name);
    expect(md).toContain("**ATT&CK:**");
    expect(md).toContain("```");
  });

  it("escapes pipes and newlines inside findings table cells so the table cannot break", () => {
    const md = huntToMarkdown(withLifecycle({
      ...HUNTS[0],
      findings: [{ date: "2026-01-01", disposition: "clean", note: "pipe | here\nand a newline" }],
    }));
    const row = md.split("\n").find((l) => l.includes("pipe"));
    expect(row).toBeDefined();
    expect(row).toContain("pipe \\| here and a newline");
    // Split on UNESCAPED pipes only — `\|` is a literal pipe to a markdown renderer,
    // so the row must still resolve to exactly three cells.
    expect(row.split(/(?<!\\)\|/).length).toBe(5); // leading + 3 cells + trailing
  });
});

describe("enterprise sanitizer", () => {
  it("maps the pre-rename industry id forward instead of dropping it", () => {
    const e = sanitizeEnterprise({ id: "x", name: "X", inherits: ["natlab", "tech", "nope"] });
    expect(e.inherits).toEqual(["utility", "tech"]);
  });

  it("keeps the demo/flagship industry id in the canonical list", () => {
    expect(ALL_INDUSTRIES).toContain("utility");
    expect(ALL_INDUSTRIES).not.toContain("natlab");
  });
});
