import { describe, it, expect, vi } from "vitest";
import { callClaude, PROXY_LIMITS } from "../OtterShell.jsx";

const ok = (body = {}) => vi.fn(async () => ({ ok: true, status: 200, json: async () => body }));
const EP = "http://proxy.test/api/claude";

describe("callClaude (proxy contract v1.1)", () => {
  it("sends only the contract fields — no model, messages or tools", async () => {
    const f = ok({ content: [] });
    await callClaude({ system: "s", user: "u", search: "docs", maxTokens: 2000, endpoint: EP, fetchImpl: f });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe(EP);
    const body = JSON.parse(init.body);
    expect(Object.keys(body).sort()).toEqual(["enableWebSearch", "maxTokens", "searchScope", "system", "user"]);
    expect(body).toMatchObject({ enableWebSearch: true, searchScope: "docs", maxTokens: 2000 });
  });

  it("omits searchScope when search is off and clamps maxTokens", async () => {
    const f = ok();
    await callClaude({ system: "s", user: "u", maxTokens: 99999, endpoint: EP, fetchImpl: f });
    const body = JSON.parse(f.mock.calls[0][1].body);
    expect(body.enableWebSearch).toBe(false);
    expect("searchScope" in body).toBe(false);
    expect(body.maxTokens).toBe(PROXY_LIMITS.maxTokens);
  });

  it("refuses oversized input before any network call", async () => {
    const f = ok();
    await expect(callClaude({ system: "s", user: "x".repeat(PROXY_LIMITS.user + 1), endpoint: EP, fetchImpl: f })).rejects.toThrow(/proxy accepts/);
    await expect(callClaude({ system: "x".repeat(PROXY_LIMITS.system + 1), user: "u", endpoint: EP, fetchImpl: f })).rejects.toThrow(/proxy accepts/);
    expect(f).not.toHaveBeenCalled();
  });

  it("tolerates a non-JSON error body", async () => {
    const f = vi.fn(async () => ({ ok: false, status: 502, json: async () => { throw new Error("not json"); } }));
    const { res, data } = await callClaude({ system: "s", user: "u", endpoint: EP, fetchImpl: f });
    expect(res.status).toBe(502);
    expect(data).toBeNull();
  });

  it("aborts after the timeout", async () => {
    const f = vi.fn((_, init) => new Promise((_, rej) => init.signal.addEventListener("abort", () => rej(Object.assign(new Error("x"), { name: "AbortError" })))));
    await expect(callClaude({ system: "s", user: "u", endpoint: EP, fetchImpl: f, timeoutMs: 20 })).rejects.toMatchObject({ name: "AbortError" });
  });
});
