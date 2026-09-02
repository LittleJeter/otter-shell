/**
 * Untrusted-input sanitizers.
 *
 * These cover the ingestion paths — JSON import, workspace load — that accept data
 * this app did not author. The crash case in `enterprise profile missing array
 * fields` is a regression test for a real defect: a workspace file carrying only
 * {id, name} passed the old acceptance check and then blanked the page, because
 * the render path calls ent.techniques.filter(...) unconditionally.
 * See docs/security-audit.md §2.1.
 */
import { describe, it, expect } from "vitest";
import {
  sanitizeHunt, sanitizeFinding, sanitizeBuiltinMeta, sanitizeEnterprise,
  SEVERITIES, ALL_INDUSTRIES,
} from "../OtterShell.jsx";

const minimalHunt = (over = {}) => ({ name: "H", queries: { splunk: "index=x" }, ...over });

describe("sanitizeEnterprise", () => {
  it("guarantees array fields when a profile is missing them (regression: blank page)", () => {
    const e = sanitizeEnterprise({ id: "x", name: "Evil Corp" });
    expect(Array.isArray(e.posture)).toBe(true);
    expect(Array.isArray(e.techniques)).toBe(true);
    expect(Array.isArray(e.actors)).toBe(true);
    expect(Array.isArray(e.inherits)).toBe(true);
    // The exact call the old render path made, which used to throw.
    expect(() => e.techniques.filter(Boolean)).not.toThrow();
  });

  it("coerces wrong-typed fields to empty arrays rather than passing them through", () => {
    const e = sanitizeEnterprise({ id: "y", name: "N", techniques: "nope", posture: 42, actors: { a: 1 } });
    expect(e.techniques).toEqual([]);
    expect(e.posture).toEqual([]);
    expect(e.actors).toEqual([]);
  });

  it("keeps well-formed actors and defaults an invalid severity", () => {
    const e = sanitizeEnterprise({
      id: "z", name: "N",
      actors: [{ name: "APT-X", origin: "PRC", motive: "IP theft", sev: "Nonsense", detail: "d" }],
    });
    expect(e.actors).toHaveLength(1);
    expect(e.actors[0].name).toBe("APT-X");
    expect(SEVERITIES).toContain(e.actors[0].sev);
  });

  it("drops actors with no name", () => {
    expect(sanitizeEnterprise({ id: "z", name: "N", actors: [{ origin: "x" }] }).actors).toEqual([]);
  });

  it("rejects a profile with no id or no name", () => {
    expect(sanitizeEnterprise({ name: "x" })).toBeNull();
    expect(sanitizeEnterprise({ id: "x" })).toBeNull();
    expect(sanitizeEnterprise(null)).toBeNull();
  });
});

describe("sanitizeHunt", () => {
  it("clamps oversized strings", () => {
    const big = "A".repeat(500_000);
    const h = sanitizeHunt(minimalHunt({ name: big, hypothesis: big, fp: big, author: big }), "t");
    expect(h.name).toHaveLength(160);
    expect(h.hypothesis).toHaveLength(600);
    expect(h.fp).toHaveLength(600);
    expect(h.author).toHaveLength(80);
  });

  it("keeps only known platform keys and clamps query length", () => {
    const h = sanitizeHunt({ name: "H", queries: { splunk: "x".repeat(9999), NOT_A_PLATFORM: "y" } }, "t");
    expect(h.queries.splunk).toHaveLength(4000);
    expect(h.queries).not.toHaveProperty("NOT_A_PLATFORM");
  });

  it("falls back to defaults for out-of-enum values", () => {
    const h = sanitizeHunt(minimalHunt({ sev: "Apocalyptic", source: "made up", status: "??", validation: "??" }), "t");
    expect(h.sev).toBe("Medium");
    expect(h.source).toBe("Endpoint / EDR");
    expect(h.status).toBe("new");
    expect(h.validation).toBe("unverified");
  });

  it("filters unknown industries and falls back to all when none survive", () => {
    expect(sanitizeHunt(minimalHunt({ industries: ["gov", "NOPE"] }), "t").industries).toEqual(["gov"]);
    expect(sanitizeHunt(minimalHunt({ industries: ["NOPE"] }), "t").industries).toEqual(ALL_INDUSTRIES);
  });

  it("caps findings and normalises each entry", () => {
    const many = Array.from({ length: 5000 }, () => ({ date: "2026-01-01", disposition: "hax", note: "n".repeat(9999) }));
    const h = sanitizeHunt(minimalHunt({ findings: [...many, null, { no: "date" }] }), "t");
    expect(h.findings).toHaveLength(50);
    expect(h.findings[0].disposition).toBe("inconclusive");
    expect(h.findings[0].note).toHaveLength(600);
  });

  it("does not let prototype-pollution keys escape the allowlist", () => {
    const poisoned = JSON.parse('{"name":"p","queries":{"splunk":"x"},"__proto__":{"polluted":"yes"},"constructor":{"bad":1}}');
    const h = sanitizeHunt(poisoned, "t");
    expect({}.polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(h, "constructor")).toBe(false);
    expect(h.name).toBe("p");
  });

  it("generates an id when one is absent and preserves a valid one", () => {
    expect(sanitizeHunt(minimalHunt(), "imp").id).toMatch(/^imp/);
    expect(sanitizeHunt(minimalHunt({ id: "keepme" }), "imp").id).toBe("keepme");
  });

  it("rejects anything without a name or a queries object", () => {
    expect(sanitizeHunt(null, "t")).toBeNull();
    expect(sanitizeHunt({ name: "x" }, "t")).toBeNull();
    expect(sanitizeHunt({ queries: {} }, "t")).toBeNull();
  });
});

describe("sanitizeFinding", () => {
  it("drops a finding with no date", () => {
    expect(sanitizeFinding({ note: "x" })).toBeNull();
    expect(sanitizeFinding(null)).toBeNull();
  });
  it("keeps a valid disposition", () => {
    expect(sanitizeFinding({ date: "2026-01-01", disposition: "clean" }).disposition).toBe("clean");
  });
});

describe("sanitizeBuiltinMeta", () => {
  it("returns null per-field for invalid values, meaning 'keep the built-in default'", () => {
    const m = sanitizeBuiltinMeta({ id: "h1", status: "bogus", findings: "not-an-array", validation: "bogus" });
    expect(m.status).toBeNull();
    expect(m.findings).toBeNull();
    expect(m.validation).toBeNull();
  });
  it("passes valid values through", () => {
    const m = sanitizeBuiltinMeta({ id: "h1", status: "validated", version: 3, pivots: "p" });
    expect(m.status).toBe("validated");
    expect(m.version).toBe(3);
    expect(m.pivots).toBe("p");
  });
  it("rejects an entry with no id", () => {
    expect(sanitizeBuiltinMeta({ status: "new" })).toBeNull();
  });
});
