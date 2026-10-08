// @vitest-environment jsdom
/**
 * Drives the real component: editor, validation reset, danger gating, search,
 * coverage columns, and a workspace round-trip.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import OtterShell from "../OtterShell.jsx";

let confirmAnswer;
beforeEach(() => {
  localStorage.clear();
  confirmAnswer = true;
  vi.spyOn(window, "confirm").mockImplementation(() => confirmAnswer);
  vi.spyOn(window, "prompt").mockImplementation(() => "Splunk");
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const open = async (u) => { render(<OtterShell />); await u.click(screen.getByText("Hunt Library & Query Builder")); };
const textarea = () => document.querySelector(".qr-qedit-ta");
const version = () => document.querySelector(".qr-ver-n").textContent;
const historyCount = () => { const s = document.querySelector(".qr-qhist summary"); return s ? Number(/\((\d+)\)/.exec(s.textContent)[1]) : 0; };
const append = async (u, text) => { const ta = textarea(); ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); await u.type(ta, text); };

describe("query editor", () => {
  it("saves with Ctrl+Enter, bumps the version, logs history and reverts", async () => {
    const u = userEvent.setup();
    await open(u);
    const v0 = version();
    await u.click(screen.getAllByRole("button", { name: /✎ Edit/ })[0]);
    await append(u, "\n// tuned");
    expect(document.querySelector(".qr-qedit-tag").textContent).toMatch(/UNSAVED/);
    await u.keyboard("{Control>}{Enter}{/Control}");
    expect(version()).toBe("v" + (Number(v0.slice(1)) + 1));
    expect(historyCount()).toBe(1);
    expect(document.querySelector("pre.qr-code").textContent).toContain("// tuned");
    await u.click(document.querySelector(".qr-qhist summary"));
    await u.click(screen.getByRole("button", { name: /Revert to this/ }));
    expect(historyCount()).toBe(2);
    expect(document.querySelector("pre.qr-code").textContent).not.toContain("// tuned");
  });

  it("is a no-op when the draft is unchanged", async () => {
    const u = userEvent.setup();
    await open(u);
    const v0 = version();
    await u.click(screen.getAllByRole("button", { name: /✎ Edit/ })[0]);
    expect(screen.getByRole("button", { name: /✓ Save/ }).disabled).toBe(true);
    await u.click(screen.getByRole("button", { name: /✕ Cancel/ }));
    expect(version()).toBe(v0);
    expect(historyCount()).toBe(0);
  });

  it("asks before discarding unsaved changes (Esc)", async () => {
    const u = userEvent.setup();
    await open(u);
    await u.click(screen.getAllByRole("button", { name: /✎ Edit/ })[0]);
    await append(u, "x");
    confirmAnswer = false;
    await u.keyboard("{Escape}");
    expect(textarea()).not.toBeNull();
    confirmAnswer = true;
    await u.keyboard("{Escape}");
    expect(textarea()).toBeNull();
  });

  it("resets validation to Unverified after confirming", async () => {
    const u = userEvent.setup();
    await open(u);
    await u.click(screen.getByRole("button", { name: "Atomic" }));
    expect(document.querySelector(".qr-val-btn.on").textContent).toBe("Atomic");
    await u.click(screen.getAllByRole("button", { name: /✎ Edit/ })[0]);
    await append(u, "\n// x");
    window.confirm.mockClear();
    await u.keyboard("{Control>}{Enter}{/Control}");
    expect(window.confirm.mock.calls.some(([m]) => /validation will reset/.test(m))).toBe(true);
    expect(document.querySelector(".qr-val-btn.on").textContent).toBe("Unverified");
  });

  it("does not save a validated hunt when the reset is declined", async () => {
    const u = userEvent.setup();
    await open(u);
    await u.click(screen.getByRole("button", { name: "Atomic" }));
    const v0 = version();
    await u.click(screen.getAllByRole("button", { name: /✎ Edit/ })[0]);
    await append(u, "\n// x");
    confirmAnswer = false;
    await u.keyboard("{Control>}{Enter}{/Control}");
    expect(version()).toBe(v0);
    expect(document.querySelector(".qr-val-btn.on").textContent).toBe("Atomic");
  });
});

describe("dangerous-command gating", () => {
  it("flags a typed delete live, and gates save and copy", async () => {
    const u = userEvent.setup();
    const clip = vi.spyOn(navigator.clipboard, "writeText");
    await open(u);
    await u.click(screen.getByRole("radio", { name: /Splunk/ }));
    await u.click(screen.getAllByRole("button", { name: /✎ Edit/ })[0]);
    await append(u, "\n| delete");
    expect(document.querySelector(".qr-lint-row.danger")).not.toBeNull();

    const v0 = version();
    confirmAnswer = false;
    await u.keyboard("{Control>}{Enter}{/Control}");
    expect(version()).toBe(v0); // declined: nothing saved

    confirmAnswer = true;
    await u.keyboard("{Control>}{Enter}{/Control}");
    expect(version()).not.toBe(v0);

    confirmAnswer = false;
    await u.click(within(document.querySelector(".qr-qh-btns")).getByRole("button", { name: /Copy/ }));
    expect(clip).not.toHaveBeenCalled();
    confirmAnswer = true;
    await u.click(within(document.querySelector(".qr-qh-btns")).getByRole("button", { name: /Copy/ }));
    await waitFor(() => expect(clip).toHaveBeenCalled());
  });
});

describe("library search and ATT&CK v19", () => {
  it("filters by ATT&CK id and clears", async () => {
    const u = userEvent.setup();
    await open(u);
    const all = document.querySelectorAll(".qr-hunt-name").length;
    await u.type(screen.getByLabelText("Search hunts"), "T1685");
    const names = [...document.querySelectorAll(".qr-hunt-name")].map((n) => n.textContent);
    expect(names).toHaveLength(1);
    expect(names[0]).toMatch(/Cloud Logging/);
    await u.clear(screen.getByLabelText("Search hunts"));
    expect(document.querySelectorAll(".qr-hunt-name")).toHaveLength(all);
  });

  it("coverage shows Stealth and Defense Impairment, never Defense Evasion", async () => {
    const u = userEvent.setup();
    render(<OtterShell />);
    await u.click(screen.getByText("Coverage & Readiness"));
    const text = document.body.textContent;
    expect(text).toMatch(/Stealth/);
    expect(text).toMatch(/Defense Impairment/);
    expect(text).not.toMatch(/Defense Evasion/);
  });
});

describe("workspace", () => {
  const captureDownload = () => {
    let blob = null;
    URL.createObjectURL = vi.fn((b) => { blob = b; return "blob:test"; });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    return () => new Promise((res) => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.readAsText(blob); });
  };
  const upload = (text) => {
    const input = document.querySelector('input[type="file"]');
    fireEvent.change(input, { target: { files: [new File([text], "w.json", { type: "application/json" })] } });
  };

  it("round-trips an edited built-in query and its history", async () => {
    const u = userEvent.setup();
    const read = captureDownload();
    await open(u);
    await u.click(screen.getAllByRole("button", { name: /✎ Edit/ })[0]);
    await append(u, "\n// roundtrip-marker");
    await u.keyboard("{Control>}{Enter}{/Control}");
    await u.click(screen.getByText("Generate & Import"));
    await u.click(screen.getByRole("button", { name: /Download workspace/ }));
    const ws = JSON.parse(await read());
    const meta = ws.builtinMeta.find((m) => m.edited);
    expect(meta.queries).toBeTruthy();
    expect(meta.queryHistory).toHaveLength(1);

    cleanup(); localStorage.clear();
    render(<OtterShell />);
    await u.click(screen.getByText("Generate & Import"));
    upload(JSON.stringify(ws));
    await u.click(screen.getByText("Hunt Library & Query Builder"));
    await waitFor(() => expect(document.body.textContent).toContain("roundtrip-marker"));
    expect(historyCount()).toBe(1);
  });

  it("survives a crafted file: object queries, bad version, no industries", async () => {
    const u = userEvent.setup();
    render(<OtterShell />);
    await u.click(screen.getByText("Generate & Import"));
    upload(JSON.stringify({
      schema: "otter-shell-workspace", version: 1,
      customHunts: [{ id: "evil", name: "Crafted hunt", version: "NaN", queries: { splunk: { $: 1 }, elastic: "FROM logs-*" }, findings: [null, { date: 5 }] }],
      builtinMeta: [{ id: "cloud-log-tamper", queries: { splunk: { x: 1 } }, queryHistory: [null, 7] }],
    }));
    await u.click(screen.getByText("Hunt Library & Query Builder"));
    await waitFor(() => expect([...document.querySelectorAll(".qr-hunt-name")].some((n) => /Crafted hunt/.test(n.textContent))).toBe(true));
  });
});
