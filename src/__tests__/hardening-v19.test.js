/**
 * October 2026 port: normalization gate, danger/grounding checks, ATT&CK v19,
 * query-edit history round-trip. See docs/CHANGES-2026-10.md.
 */
import { describe, it, expect } from "vitest";
import {
  HUNTS, PLATFORM_IDS, withLifecycle, lintQuery, dangerIssues, groundingIssues, sigmaToHunt,
  atomicUrl, buildNavLayer, huntToMarkdown, sanitizeHunt, sanitizeBuiltinMeta,
} from "../OtterShell.jsx";

describe("normalization gate", () => {
  it("leaves the built-in hunts unchanged", () => {
    for (const raw of HUNTS) {
      const h = withLifecycle(raw);
      for (const k of ["name", "technique", "tactic", "hypothesis", "fp", "sev", "source", "industries"]) {
        expect(h[k], `${raw.id}.${k}`).toEqual(raw[k]);
      }
      expect(h.queries, raw.id).toEqual(raw.queries);
      if (raw.note) expect(h.note, `${raw.id}.note`).toBe(raw.note);
    }
  });

  it("survives a hostile hunt (object queries, missing industries, junk history)", () => {
    const h = withLifecycle({
      id: "x", custom: true, name: "n", queries: { splunk: { evil: 1 }, elastic: "FROM logs-*", bogus: "x" },
      version: -3, findings: [null, { date: 5 }, { date: "2026-01-01", disposition: "nope", note: 7 }],
      queryHistory: [null, { platform: "nope", prev: "x" }, { platform: "splunk", prev: "old", how: "revert" }],
    });
    expect(h.industries.length).toBeGreaterThan(0);
    expect(h.queries).toEqual({ elastic: "FROM logs-*" });
    expect(h.version).toBe(1);
    expect(h.findings).toEqual([{ date: "2026-01-01", disposition: "inconclusive", note: "7" }]);
    expect(h.queryHistory).toHaveLength(1);
    expect(h.queryHistory[0].how).toBe("revert");
  });

  it("keeps edit history through sanitizeHunt and sanitizeBuiltinMeta", () => {
    const hist = [{ date: "2026-10-07", platform: "splunk", version: 1, prev: "index=a", how: "edit", validationWas: "" }];
    const c = sanitizeHunt({ name: "n", queries: { splunk: "index=b" }, edited: true, queryHistory: hist }, "ws");
    expect(c.edited).toBe(true);
    expect(c.queryHistory).toEqual(hist);
    const m = sanitizeBuiltinMeta({ id: HUNTS[0].id, queries: { splunk: "index=b", bogus: 1 }, queryHistory: hist });
    expect(m.queries).toEqual({ splunk: "index=b" });
    expect(withLifecycle({ ...HUNTS[0], queryHistory: m.queryHistory }).queryHistory).toEqual(hist);
  });
});

describe("danger + grounding checks", () => {
  it("flags write/delete/send commands per platform", () => {
    expect(dangerIssues("splunk", "index=a | delete")).toHaveLength(1);
    expect(dangerIssues("splunk", "index=a | outputlookup x.csv")).toHaveLength(1);
    expect(dangerIssues("sentinel", ".set-or-append T <| X")).toHaveLength(1);
    expect(dangerIssues("defender", "externaldata(a:string)[h@'http://x']")).toHaveLength(1);
    expect(dangerIssues("xsiam", "dataset=xdr_data | target type=dataset x")).toHaveLength(1);
    expect(dangerIssues("splunk", "// | delete in a comment only\nindex=a")).toHaveLength(0);
  });

  it("surfaces danger through lintQuery", () => {
    expect(lintQuery("splunk", "index=a | delete").some((i) => i.level === "danger")).toBe(true);
  });

  it("flags unknown tables and column mixups", () => {
    expect(groundingIssues("sentinel", "MadeUpTable | take 1").some((i) => /MadeUpTable/.test(i.msg))).toBe(true);
    expect(groundingIssues("defender", "DeviceProcessEvents | where TimeGenerated > ago(1d)").some((i) => i.level === "warn")).toBe(true);
    expect(groundingIssues("elastic", "FROM logs-* | <VERIFY_FIELD:x>").some((i) => i.level === "warn")).toBe(true);
  });

  it("raises no danger or warnings on the curated library", () => {
    for (const h of HUNTS) for (const p of PLATFORM_IDS) {
      const bad = lintQuery(p, h.queries[p]).filter((i) => i.level === "warn" || i.level === "danger");
      expect(bad, `${h.id}/${p}`).toEqual([]);
    }
  });
});

describe("ATT&CK v19", () => {
  it("no curated hunt uses Defense Evasion or a revoked T1562 id", () => {
    for (const h of HUNTS) {
      expect(h.tactic, h.id).not.toMatch(/Defense Evasion/);
      expect(h.technique, h.id).not.toMatch(/T1562|T1070\.001/);
    }
  });
  it("remaps pre-v19 Sigma tags", () => {
    const y = "title: t\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  sel:\n    Image|endswith: '\\\\a.exe'\n  condition: sel\nlevel: high\ntags:\n  - attack.defense_evasion\n  - attack.t1562.009\n";
    const h = sigmaToHunt(y);
    expect(h.tactic).toBe("Stealth");
    expect(h.technique).toMatch(/^T1688 \(remapped from revoked T1562\.009\)/);
  });
  it("exports Navigator 5.1 / ATT&CK 19 and links legacy ART folders", () => {
    const layer = buildNavLayer(HUNTS, { name: "x" });
    expect(layer.versions).toEqual({ attack: "19", navigator: "5.1.0", layer: "4.5" });
    const h = HUNTS.find((x) => x.id === "cloud-log-tamper");
    expect(h.technique).toMatch(/T1685\.002/);
    expect(atomicUrl(h)).toMatch(/atomics\/T1562\.008$/);
  });
});

describe("markdown report", () => {
  it("uses a longer fence than any backtick run and lists edit history", () => {
    const md = huntToMarkdown({
      name: "n", queries: { secops: "re.regex($e.x, `a```b`)" },
      queryHistory: [{ date: "2026-10-07", platform: "secops", version: 1, prev: "x", how: "edit", validationWas: "" }],
    });
    expect(md).toContain("````\nre.regex");
    expect(md).toContain("## Query edit history");
  });
});
