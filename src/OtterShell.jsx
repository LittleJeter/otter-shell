import React, { useState, useMemo, useRef, useEffect } from "react";

/* ============================================================
   OTTER SHELL — Threat Hunt Console  (v3)
   - Industry-aware threat landscape
   - Multi-platform hunt query generator (7 platforms):
       CrowdStrike Falcon LogScale/NG-SIEM · Cortex XSIAM XQL ·
       Microsoft Sentinel KQL · Microsoft Defender XDR (Advanced Hunting) ·
       Elastic Security ES|QL · Google SecOps YARA-L/UDM · Splunk SPL
   - ATT&CK coverage map + Navigator layer export
   - Telemetry-readiness audit (log-source gap analysis)
   - AI hunt generator + live intel -> hunt enrichment (API + web search)
   - Sigma + JSON import / library export
   Flagship enterprise: a generic Regional Energy Utility (electric & gas distribution)
   ============================================================ */


/* ============================================================
   DEMO PROGRAMME

   A worked example of the tool in use, so a first-time visitor sees a hunt
   programme with history rather than a wall of zeros. It is built as an ordinary
   workspace object and loaded through the same `applyWorkspace` path (and the same
   sanitizers) as a real file — the demo gets no privileged route into state.

   Dates are generated relative to today so the example never looks stale.
   ============================================================ */

const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);

const DEMO_BUILTIN = [
  { id: "ps-enc", status: "validated", validation: "atomic", validatedOn: "Atomic Red Team T1059.001-1", ago: 6,
    tuning: "Raised to 3+ encoded invocations/hour per host. SCCM and the packaging build agents baseline at ~40/day — excluded SVC-SCCM and host BLD-07.",
    pivots: "Pull the parent process tree, then the same user's auth events ±4h and any new outbound destinations.",
    findings: [
      { d: 6,  disp: "clean",        note: "Weekly sweep across 4,100 endpoints. 12 hits, all SCCM packaging. Coverage confirmed, no action." },
      { d: 21, disp: "suspicious",   note: "One hit on an engineering workstation outside the change window. Owner confirmed a legitimate vendor install script. Added to baseline." },
      { d: 40, disp: "clean",        note: "Initial validation run after Atomic test fired cleanly. Detection logic confirmed working end to end." },
    ] },
  { id: "mfa-fatigue", status: "validated", validation: "ran", validatedOn: "Sentinel — prod workspace", ago: 3,
    tuning: "Threshold 5 denied pushes in 10 minutes. Helpdesk-assisted enrolments produce bursts of 3–4, so 5 is the floor that avoids paging on them.",
    pivots: "Pull the account's sign-in log ±24h, every device currently enrolled to it, and any mailbox rule or OAuth grant created after the approval.",
    findings: [
      { d: 3,  disp: "confirmed", note: "Field-operations account: 22 denied pushes in 6 min from an ASN we have never seen, then an approval. Escalated to IR, session revoked, credentials reset. Confirmed push-fatigue compromise." },
      { d: 10, disp: "clean",     note: "Fortnightly sweep across the tenant. 3 accounts crossed the threshold, all matched to helpdesk-assisted re-enrolments the same morning. No action — documented coverage." },
      { d: 17, disp: "suspicious", note: "9 denials on a contractor account, no approval. User had a broken phone clock. Closed after contact." },
    ] },
  { id: "impossible-travel", status: "in-progress", validation: "syntax", ago: 2,
    tuning: "VPN egress and the two site NATs need excluding before this is usable — currently ~60% FP from the field-crew VPN pool.",
    pivots: "Correlate with the MFA-fatigue hunt for the same principal before escalating.",
    findings: [
      { d: 2,  disp: "inconclusive", note: "14 hits, 9 explained by the field-crew VPN. Need the egress-IP exclusion list from Networking before this is trustworthy." },
    ] },
  { id: "oauth-consent", status: "validated", validation: "ran", validatedOn: "Entra ID audit logs", ago: 9,
    tuning: "Alert only on non-verified publishers requesting Mail.Read, Files.Read.All or offline_access.",
    findings: [
      { d: 9,  disp: "confirmed", note: "Unverified 'PDF Converter' app granted Mail.Read by 3 users after a phishing wave. App blocked tenant-wide, grants revoked, mailbox rules audited." },
      { d: 28, disp: "clean",     note: "Monthly review. 6 new consents, all verified publishers on the allowlist." },
    ] },
  { id: "vss-delete", status: "validated", validation: "atomic", validatedOn: "Atomic Red Team T1490-1", ago: 12,
    findings: [
      { d: 12, disp: "clean", note: "Atomic test fired and was caught in 40s. Backup agent's scheduled shadow-copy rotation excluded by service account." },
    ] },
  { id: "mass-encrypt", status: "validated", validation: "atomic", validatedOn: "Atomic Red Team T1486-1", ago: 12,
    tuning: "1,200 file modifications in 5 minutes per host. The nightly backup agent peaks near 900, so 1,200 clears it without hiding a real burst.",
    findings: [
      { d: 12, disp: "clean", note: "Validated with the Atomic test against an isolated VM. Alert fired at 1,240 ops." },
    ] },
  { id: "rmm", status: "in-progress", validation: "syntax", ago: 5,
    pivots: "If this fires, check whether the same host also shows a new local account or scheduled task.",
    findings: [
      { d: 5, disp: "suspicious", note: "ScreenConnect found on 4 machines in the metering engineering group. IT confirms 2 are a sanctioned vendor deployment; 2 unexplained and still with the group lead." },
    ] },
  { id: "webshell", status: "validated", validation: "ran", validatedOn: "Splunk — web tier", ago: 15,
    findings: [
      { d: 15, disp: "clean", note: "Swept all public-facing app servers after the Ivanti advisory. No anomalous child processes from web workers." },
    ] },
  { id: "cloud-log-tamper", status: "validated", validation: "ran", validatedOn: "AWS CloudTrail", ago: 30, findings: [
      { d: 30, disp: "clean", note: "No StopLogging or DeleteTrail events in 90 days. Verified the hunt returns rows when run against the test trail." },
    ] },
  { id: "iam-key", status: "in-progress", validation: "syntax", ago: 8, findings: [
      { d: 8, disp: "inconclusive", note: "3 new keys for existing users. Two are documented CI rotations; chasing the third with the platform team." },
    ] },
  { id: "dns-tunnel", status: "in-progress", validation: "unverified" },
  { id: "lolbin-download", status: "validated", validation: "atomic", validatedOn: "Atomic Red Team T1105-2", ago: 19, findings: [
      { d: 19, disp: "clean", note: "certutil and bitsadmin paths both validated. No production hits outside the test." },
    ] },
  { id: "rdp-burst", status: "new", validation: "unverified" },
  { id: "entra-role", status: "validated", validation: "ran", validatedOn: "Entra ID audit logs", ago: 24, findings: [
      { d: 24, disp: "clean", note: "4 privileged role grants in the period, all matched to approved change tickets." },
    ] },
  { id: "linux-cron", status: "retired", validation: "ran", validatedOn: "Elastic — Linux fleet", ago: 60, findings: [
      { d: 60, disp: "clean", note: "Retired: superseded by the platform team's config-management drift detection, which covers cron comprehensively." },
    ] },
];

const DEMO_CUSTOM = [
  {
    id: "demo-kerberoast", name: "Kerberoasting — RC4 TGS-REQ Burst",
    technique: "T1558.003 — Kerberoasting", tactic: "Credential Access",
    sev: "High", source: "Windows Event Logs",
    hypothesis: "An adversary with any domain credential requests service tickets for many SPNs with RC4 encryption (etype 0x17), then cracks them offline to obtain service-account passwords.",
    fp: "Legacy applications and some backup agents still request RC4 tickets. Baseline per-account SPN request volume before alerting; vulnerability scanners also generate bursts.",
    note: "Requires Event ID 4769 with TicketEncryptionType. Confirm the DCs are forwarding Kerberos service-ticket events.",
    status: "validated", validation: "atomic", validatedOn: "Atomic Red Team T1558.003-1",
    author: "Intel-derived", version: 2,
    queries: {
      sentinel: 'SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4769 and TicketEncryptionType == "0x17"\n| summarize SPNs = dcount(ServiceName), Tickets = count() by Account, bin(TimeGenerated, 1h)\n| where SPNs >= 10',
      splunk: 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 earliest=-24h\n| stats dc(Service_Name) as spns count as tickets by Account_Name, _time\n| where spns >= 10',
      crowdstrike: '#event_simpleName=UserLogon earliest=-24h\n| LogonType=3\n| groupBy([UserName], function=count(as=logons))\n| logons > 50',
      defender: 'IdentityLogonEvents\n| where Timestamp > ago(24h)\n| where Protocol == "Kerberos"\n| summarize Services = dcount(TargetDeviceName) by AccountUpn, bin(Timestamp, 1h)\n| where Services >= 10',
      elastic: 'FROM logs-windows.*\n| WHERE @timestamp > NOW() - 24 hours AND event.code == "4769" AND winlog.event_data.TicketEncryptionType == "0x17"\n| STATS spns = COUNT_DISTINCT(winlog.event_data.ServiceName) BY user.name\n| WHERE spns >= 10',
      xsiam: 'dataset = msft_windows_raw\n| filter event_id = 4769 and ticket_encryption_type = "0x17"\n| comp count_distinct(service_name) as spns by account_name\n| filter spns >= 10',
      secops: 'rule otter_kerberoast_rc4 {\n  meta:\n    author = "Otter Shell"\n  events:\n    $e.metadata.event_type = "USER_RESOURCE_ACCESS"\n    $e.security_result.detection_fields["encryption_type"] = "0x17"\n    $user = $e.principal.user.userid\n  match:\n    $user over 1h\n  condition:\n    #e >= 10\n}',
    },
    findings: [
      { d: 11, disp: "clean", note: "Ran against 30 days of 4769 events. One account at 14 SPNs — the Tenable scanner service, expected and baselined." },
      { d: 33, disp: "clean", note: "Atomic test confirmed the detection fires at threshold." },
    ],
  },
  {
    id: "demo-cloud-exfil", name: "Bulk Download from Engineering File Store",
    technique: "T1530 — Data from Cloud Storage", tactic: "Collection",
    sev: "Critical", source: "Cloud / SaaS",
    hypothesis: "A compromised staff or contractor account downloads an anomalous volume of files from OneDrive/SharePoint or S3 in a short window, consistent with staging engineering or customer data for exfiltration.",
    fp: "Legitimate bulk transfers at project milestones and GIS / asset-record migrations produce large volumes. Baseline per-user and per-site; whitelist known migration windows.",
    note: "Requires OneDrive/SharePoint audit logs or S3 data events, which are off by default in many tenants.",
    status: "in-progress", validation: "syntax", author: "Report-derived", version: 1,
    queries: {
      sentinel: 'OfficeActivity\n| where TimeGenerated > ago(7d)\n| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")\n| summarize Files = count(), Sites = dcount(Site_Url) by UserId, bin(TimeGenerated, 1h)\n| where Files > 500',
      splunk: 'index=o365 Operation IN ("FileDownloaded","FileSyncDownloadedFull") earliest=-7d\n| stats count as files dc(Site_Url) as sites by UserId, _time\n| where files > 500',
      crowdstrike: '#event_simpleName=CloudStorageAccess earliest=-7d\n| groupBy([UserName], function=count(as=downloads))\n| downloads > 500',
      defender: 'CloudAppEvents\n| where Timestamp > ago(7d)\n| where ActionType == "FileDownloaded"\n| summarize Files = count() by AccountObjectId, bin(Timestamp, 1h)\n| where Files > 500',
      elastic: 'FROM logs-o365.*\n| WHERE @timestamp > NOW() - 7 days AND event.action == "FileDownloaded"\n| STATS files = COUNT(*) BY user.id\n| WHERE files > 500',
      xsiam: 'dataset = msft_o365_raw\n| filter operation in ("FileDownloaded", "FileSyncDownloadedFull")\n| comp count() as files by user_id\n| filter files > 500',
      secops: 'rule otter_bulk_cloud_download {\n  meta:\n    author = "Otter Shell"\n  events:\n    $e.metadata.event_type = "USER_RESOURCE_ACCESS"\n    $e.principal.user.userid = $user\n  match:\n    $user over 1h\n  condition:\n    #e > 500\n}',
    },
    findings: [
      { d: 4, disp: "inconclusive", note: "Two hits. One is a confirmed GIS dataset migration; the other is a departing contract engineer — referred to HR and Legal." },
    ],
  },
];

function buildDemoWorkspace() {
  const builtinMeta = DEMO_BUILTIN.map((d) => ({
    id: d.id,
    status: d.status,
    version: d.status === "validated" ? 2 : 1,
    author: "Otter Shell",
    created: daysAgo(90),
    reviewed: d.ago != null ? daysAgo(d.ago) : "",
    validation: d.validation,
    validatedOn: d.validatedOn || "",
    validatedDate: d.ago != null && d.validation !== "unverified" ? daysAgo(d.ago) : "",
    pivots: d.pivots || "",
    tuning: d.tuning || "",
    findings: (d.findings || []).map((f) => ({ date: daysAgo(f.d), disposition: f.disp, note: f.note })),
  }));

  const customHunts = DEMO_CUSTOM.map((c) => ({
    ...c,
    custom: true,
    created: daysAgo(45),
    reviewed: daysAgo(c.findings[0].d),
    validatedDate: c.validation !== "unverified" ? daysAgo(c.findings[0].d) : "",
    industries: ALL_INDUSTRIES,
    findings: c.findings.map((f) => ({ date: daysAgo(f.d), disposition: f.disp, note: f.note })),
  }));

  return {
    schema: "otter-shell-workspace", version: 1, savedAt: new Date().toISOString(),
    customHunts, builtinMeta, customEnterprises: [], telemetry: [...TELEMETRY],
  };
}


/* ============================================================
   LOCAL PERSISTENCE

   The tool originally kept nothing across a reload: the claude.ai artifact sandbox
   blocked Web Storage, so avoiding it was correct there. On a normal deployment that
   constraint is gone, so the workspace now autosaves to localStorage.

   Every accessor is wrapped: Storage throws outright in some privacy modes and when a
   quota is exceeded, and a thrown getter at module scope would take the whole app down.
   Restore goes through the same sanitizers as a file load — data that has been sitting
   in a browser profile is no more trustworthy than a file off disk.
   ============================================================ */

const LS_KEY = "otter-shell:workspace:v1";

function lsGet() { try { return window.localStorage.getItem(LS_KEY); } catch { return null; } }
function lsSet(value) { try { window.localStorage.setItem(LS_KEY, value); return true; } catch { return false; } }
function lsClear() { try { window.localStorage.removeItem(LS_KEY); return true; } catch { return false; } }

/* ---- AI backend configuration ------------------------------------------------
   The hunt generator and the KEV model-fallback call the Anthropic Messages API.
   Inside the hosted claude.ai artifact runtime the API key was injected into the
   request transparently, so the frontend could post to api.anthropic.com with no
   credentials. Nowhere else can: local dev and any static deploy have no key, and
   the call fails with an opaque auth/CORS error that reads like a broken app.

   So the AI features are opt-in. Set VITE_CLAUDE_PROXY_URL to a backend that holds
   the key server-side (see migration/03_PROXY_CONTRACT.md and
   migration/proxy_starter.py) and they switch on. Left unset, they are disabled
   with an explanation and every offline feature works unchanged.

   Never put an API key in this frontend — a bundled key is a published key. ---- */
const CLAUDE_ENDPOINT = String(
  (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_CLAUDE_PROXY_URL) || ""
).trim();
const AI_ENABLED = CLAUDE_ENDPOINT.length > 0;
const AI_DISABLED_MSG =
  "AI generation is disabled in this build. It needs a backend that holds an Anthropic API key " +
  "server-side — set VITE_CLAUDE_PROXY_URL to your proxy and rebuild (see the README). " +
  "Every other feature — the 18-hunt library, Sigma import/export, ATT&CK coverage and the live CISA KEV scan — works without it.";

const PLATFORMS = [
  { id: "crowdstrike", label: "CrowdStrike", sub: "Falcon LogScale / NG-SIEM" },
  { id: "xsiam", label: "Cortex XSIAM", sub: "XQL" },
  { id: "sentinel", label: "MS Sentinel", sub: "KQL" },
  { id: "defender", label: "Defender XDR", sub: "Advanced Hunting KQL" },
  { id: "elastic", label: "Elastic Security", sub: "ES|QL" },
  { id: "secops", label: "Google SecOps", sub: "YARA-L / UDM" },
  { id: "splunk", label: "Splunk", sub: "SPL" },
];
export const PLATFORM_IDS = PLATFORMS.map((p) => p.id);

const TABS = [
  { id: "landscape", icon: "▣", label: "Threat Landscape" },
  { id: "hunts", icon: "⌖", label: "Hunt Library & Query Builder" },
  { id: "coverage", icon: "▦", label: "Coverage & Readiness" },
  { id: "forge", icon: "✶", label: "Generate & Import" },
];

export const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const SEV_COLOR = { Critical: "#ff3b4e", High: "#ff8c2a", Medium: "#ffd23f", Low: "#4ec9b0" };

/* ---- hunt lifecycle ---- */
export const STATUSES = ["new", "in-progress", "validated", "retired"];
const STATUS_META = {
  "new": { label: "New", color: "#74808c" },
  "in-progress": { label: "In progress", color: "#f5a623" },
  "validated": { label: "Validated", color: "#2dd4bf" },
  "retired": { label: "Retired", color: "#566069" },
};
const SIGMA_STATUS = { "new": "experimental", "in-progress": "test", "validated": "stable", "retired": "deprecated" };
export const DISPOSITIONS = ["clean", "suspicious", "confirmed", "inconclusive"];
const DISPO_META = {
  "clean": { label: "Clean — no evidence", color: "#2dd4bf" },
  "suspicious": { label: "Suspicious — follow up", color: "#f5a623" },
  "confirmed": { label: "Confirmed malicious", color: "#ff3b4e" },
  "inconclusive": { label: "Inconclusive", color: "#74808c" },
};
/* Validation provenance — HOW a hunt's query was proven, distinct from lifecycle status.
   This is what lets "validated" mean something specific and inspectable rather than a self-assertion. */
export const VALIDATIONS = ["unverified", "syntax", "ran", "atomic"];
const VALIDATION_META = {
  "unverified": { label: "Unverified", short: "Unverified", color: "#74808c", desc: "Not yet checked against anything." },
  "syntax": { label: "Syntax-checked", short: "Syntax", color: "#8b93a7", desc: "Confirmed valid against the platform's query-language docs — not run on data." },
  "ran": { label: "Ran on platform", short: "Ran", color: "#f5a623", desc: "Executed against real telemetry and returned sane results." },
  "atomic": { label: "Atomic-confirmed", short: "Atomic", color: "#2dd4bf", desc: "Detected a real Atomic Red Team execution of the technique — true-positive proven." },
};
const todayISO = () => new Date().toISOString().slice(0, 10);
export function withLifecycle(h) {
  return {
    ...h,
    status: STATUSES.includes(h.status) ? h.status : "new",
    version: Number.isFinite(h.version) && h.version > 0 ? h.version : 1,
    author: typeof h.author === "string" ? h.author : (h.custom ? "" : "Otter Shell"),
    created: h.created || "",
    reviewed: h.reviewed || "",
    findings: Array.isArray(h.findings) ? h.findings.filter((f) => f && f.date).slice(0, 50) : [],
    pivots: typeof h.pivots === "string" ? h.pivots : "",
    tuning: typeof h.tuning === "string" ? h.tuning : "",
    validation: VALIDATIONS.includes(h.validation) ? h.validation : "unverified",
    validatedOn: typeof h.validatedOn === "string" ? h.validatedOn.slice(0, 40) : "",
    validatedDate: h.validatedDate || "",
  };
}

/* ============================================================
   UNTRUSTED-INPUT SANITIZERS

   Three ingestion paths accept data this app did not author: JSON import,
   workspace-file load, and Sigma import. React escapes on render, so the risk
   is not XSS — it is unbounded/mistyped fields reaching code that assumes a
   shape (e.g. `ent.techniques.filter(...)` on a hand-edited workspace file,
   which throws and blanks the page) and unbounded strings/arrays bloating the
   UI. Every ingestion path rebuilds objects field-by-field from an allowlist
   rather than spreading whatever arrived.
   ============================================================ */

const clampStr = (v, n, fallback = "") =>
  typeof v === "string" ? v.slice(0, n) : (typeof v === "number" && Number.isFinite(v) ? String(v).slice(0, n) : fallback);

const clampList = (v, n, fn) => (Array.isArray(v) ? v.slice(0, n).map(fn).filter(Boolean) : []);

/* One journal finding. Dropped entirely if it has no date. */
export function sanitizeFinding(f) {
  if (!f || typeof f !== "object" || !f.date) return null;
  return {
    date: clampStr(f.date, 20),
    disposition: DISPOSITIONS.includes(f.disposition) ? f.disposition : "inconclusive",
    note: clampStr(f.note, 600),
  };
}

/* A hunt from any untrusted source. Returns null if it lacks the minimum shape. */
export function sanitizeHunt(h, idPrefix) {
  if (!h || typeof h !== "object" || !h.name || !h.queries || typeof h.queries !== "object") return null;
  const q = {};
  for (const k of PLATFORM_IDS) if (typeof h.queries[k] === "string") q[k] = h.queries[k].slice(0, 4000);
  const industries = Array.isArray(h.industries) ? h.industries.filter((x) => ALL_INDUSTRIES.includes(x)) : [];
  return withLifecycle({
    id: typeof h.id === "string" && h.id ? h.id.slice(0, 40) : genId(idPrefix),
    custom: true,
    queries: q,
    name: clampStr(h.name, 160, "Imported hunt"),
    technique: clampStr(h.technique, 80) || "—",
    tactic: clampStr(h.tactic, 80) || "—",
    hypothesis: clampStr(h.hypothesis, 600) || "Imported hunt.",
    fp: clampStr(h.fp, 600) || "Tune to environment.",
    note: clampStr(h.note, 300),
    sev: SEVERITIES.includes(h.sev) ? h.sev : "Medium",
    source: DATA_SOURCES.includes(h.source) ? h.source : "Endpoint / EDR",
    industries: industries.length ? industries : ALL_INDUSTRIES,
    status: h.status,
    version: h.version,
    author: clampStr(h.author, 80),
    created: clampStr(h.created, 20),
    reviewed: clampStr(h.reviewed, 20),
    findings: clampList(h.findings, 50, sanitizeFinding),
    pivots: clampStr(h.pivots, 2000),
    tuning: clampStr(h.tuning, 2000),
    validation: h.validation,
    validatedOn: clampStr(h.validatedOn, 40),
    validatedDate: clampStr(h.validatedDate, 20),
  });
}

/* Saved lifecycle metadata for a BUILT-IN hunt (the workspace file's builtinMeta). */
export function sanitizeBuiltinMeta(o) {
  if (!o || typeof o !== "object" || typeof o.id !== "string") return null;
  return {
    id: o.id.slice(0, 40),
    status: STATUSES.includes(o.status) ? o.status : null,
    version: Number.isFinite(o.version) && o.version > 0 ? o.version : null,
    author: typeof o.author === "string" ? o.author.slice(0, 80) : null,
    created: clampStr(o.created, 20) || null,
    reviewed: clampStr(o.reviewed, 20) || null,
    findings: Array.isArray(o.findings) ? clampList(o.findings, 50, sanitizeFinding) : null,
    pivots: typeof o.pivots === "string" ? o.pivots.slice(0, 2000) : null,
    tuning: typeof o.tuning === "string" ? o.tuning.slice(0, 2000) : null,
    validation: VALIDATIONS.includes(o.validation) ? o.validation : null,
    validatedOn: typeof o.validatedOn === "string" ? o.validatedOn.slice(0, 40) : null,
    validatedDate: clampStr(o.validatedDate, 20) || null,
  };
}

/* An enterprise profile from a workspace file. The render path calls .map/.filter
   on posture, techniques and actors unconditionally, so these MUST be arrays —
   a profile carrying only {id, name} used to blank the page on selection. */
export function sanitizeEnterprise(e) {
  if (!e || typeof e !== "object" || !e.id || !e.name) return null;
  return {
    id: clampStr(e.id, 60),
    name: clampStr(e.name, 120, "Untitled enterprise"),
    sector: clampStr(e.sector, 120) || "—",
    blurb: clampStr(e.blurb, 1000),
    stack: clampStr(e.stack, 600),
    posture: clampList(e.posture, 40, (x) => clampStr(x, 300)),
    techniques: clampList(e.techniques, 60, (x) => clampStr(x, 120)),
    actors: clampList(e.actors, 30, (a) => (a && typeof a === "object" && a.name ? {
      name: clampStr(a.name, 120),
      origin: clampStr(a.origin, 80),
      motive: clampStr(a.motive, 80),
      sev: SEVERITIES.includes(a.sev) ? a.sev : "High",
      detail: clampStr(a.detail, 600),
    } : null)),
    inherits: clampList(e.inherits, 10, (x) => { const id = canonIndustry(x); return ALL_INDUSTRIES.includes(id) ? id : null; }),
    custom: true,
  };
}

/* IOC enrichment — one-click lookups; type-detected, links open externally */
export function enrichLinks(raw) {
  const v = String(raw || "").trim();
  if (!v) return [];
  const e = encodeURIComponent(v);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return [
    { label: "VirusTotal", url: "https://www.virustotal.com/gui/ip-address/" + e },
    { label: "GreyNoise", url: "https://viz.greynoise.io/ip/" + e },
    { label: "Shodan", url: "https://www.shodan.io/host/" + e },
    { label: "AbuseIPDB", url: "https://www.abuseipdb.com/check/" + e },
  ];
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(v)) return [
    { label: "VirusTotal", url: "https://www.virustotal.com/gui/file/" + e },
    { label: "MalwareBazaar", url: "https://bazaar.abuse.ch/browse.php?search=" + e },
  ];
  if (/^https?:\/\//i.test(v)) return [
    { label: "urlscan", url: "https://urlscan.io/search/#" + e },
    { label: "VirusTotal", url: "https://www.virustotal.com/gui/search/" + e },
  ];
  if (/^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return [
    { label: "VirusTotal", url: "https://www.virustotal.com/gui/domain/" + e },
    { label: "urlscan", url: "https://urlscan.io/search/#" + e },
    { label: "Shodan", url: "https://www.shodan.io/search?query=hostname:" + e },
  ];
  return [{ label: "VirusTotal search", url: "https://www.virustotal.com/gui/search/" + e }];
}

export const DATA_SOURCES = ["Endpoint / EDR", "Identity / IdP", "Cloud / SaaS", "DNS", "Web Proxy", "Windows Event Logs"];

export const ALL_INDUSTRIES = ["utility", "gov", "tech", "health", "finance"];

/* Workspaces saved before the flagship profile changed sector carry the old id in a
   custom enterprise's `inherits` list. Map it forward rather than silently dropping it. */
const LEGACY_INDUSTRY_IDS = { natlab: "utility" };
export const canonIndustry = (x) => LEGACY_INDUSTRY_IDS[x] || x;

/* Telemetry feeds used by the readiness audit */
const TELEMETRY = [
  "Endpoint / EDR (Windows)",
  "Endpoint / EDR (Linux)",
  "Endpoint / EDR (macOS)",
  "Entra ID / Okta sign-in + audit",
  "AWS CloudTrail (cloud control-plane)",
  "M365 / Workspace audit",
  "DNS query logs",
  "Web proxy / egress logs",
  "Windows Security events (4624 etc.)",
];

/* Per-hunt telemetry prerequisites (id -> required feeds) */
const REQUIRES = {
  "ps-enc": ["Endpoint / EDR (Windows)"],
  rmm: ["Endpoint / EDR (Windows)"],
  "oauth-consent": ["Entra ID / Okta sign-in + audit"],
  "mfa-fatigue": ["Entra ID / Okta sign-in + audit"],
  "impossible-travel": ["Entra ID / Okta sign-in + audit"],
  "entra-role": ["Entra ID / Okta sign-in + audit"],
  "cloud-log-tamper": ["AWS CloudTrail (cloud control-plane)"],
  "iam-key": ["AWS CloudTrail (cloud control-plane)"],
  "vss-delete": ["Endpoint / EDR (Windows)"],
  "mass-encrypt": ["Endpoint / EDR (Windows)"],
  "dns-tunnel": ["DNS query logs"],
  "lolbin-download": ["Endpoint / EDR (Windows)"],
  "rdp-burst": ["Windows Security events (4624 etc.)"],
  webshell: ["Endpoint / EDR (Windows)"],
  "linux-cron": ["Endpoint / EDR (Linux)"],
  "linux-revshell": ["Endpoint / EDR (Linux)"],
  "macos-launchagent": ["Endpoint / EDR (macOS)"],
  "cloud-exfil": ["M365 / Workspace audit", "Web proxy / egress logs"],
};

/* ATT&CK tactic order for the coverage matrix */
const TACTIC_ORDER = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
  "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command & Control",
  "Exfiltration", "Impact",
];
/* normalize a hunt's (possibly compound) tactic string to ATT&CK tactics */
function tacticsOf(h) {
  const s = (h.tactic || "").toLowerCase();
  return TACTIC_ORDER.filter((t) => s.includes(t.toLowerCase().replace(" & ", " & ")) || s.includes(t.toLowerCase()));
}

/* ---------------------- ENTERPRISE PROFILES ---------------------- */

/* Short label for inline prose ("Build hunts for X"). Enterprises can declare `short`;
   otherwise the first word is used, which suits most org names but not multi-word ones
   like "Regional Energy Utility" — hence the explicit field. */
const shortName = (e) => (e && typeof e.short === "string" && e.short) || String((e && e.name) || "").split(" ")[0] || "this enterprise";

const ENTERPRISES = [
  {
    id: "utility",
    name: "Regional Energy Utility", short: "the Utility",
    sector: "Energy — Electric & Gas Distribution",
    flag: true,
    blurb:
      "Investor-owned electric and gas distribution utility serving a multi-county territory. Crown jewels are grid operations (SCADA / EMS / OMS), customer and billing records, and the engineering data describing the network. A converged IT/OT estate, standing remote access for field crews and equipment vendors, and control-system hardware that cannot be patched on an IT cadence widen the surface well beyond a typical enterprise.",
    posture: [
      "Nation-state interest is about pre-positioning for disruption, not immediate theft — the objective is quiet, long-dwell access to operational networks.",
      "The IT/OT boundary is the decisive control: credible OT impact almost always starts as an ordinary IT compromise that pivots through a jump host or a shared vendor account.",
      "Ransomware does not have to reach OT to cause an outage — losing billing, work-management and outage-management systems forces curtailment on its own.",
      "Field crews, EPC contractors and metering vendors hold standing remote access, so identity lifecycle and vendor offboarding are first-class risks.",
      "Internet-facing VPN concentrators, remote-access gateways and exposed HMIs are the recurring initial-access route across the sector.",
    ],
    actors: [
      { name: "State-aligned infrastructure pre-positioning (Volt Typhoon-style)", origin: "PRC", motive: "Pre-positioning / disruption optionality", sev: "Critical", detail: "Enters through edge devices and valid accounts, then lives off the land — built-in Windows tooling, no custom malware — to persist quietly in IT and reach OT-adjacent networks. Detection depends on behavioural hunting, not signatures." },
      { name: "State-aligned ICS-capable disruption (Sandworm-style)", origin: "Russia — GRU-linked", motive: "Disruption / destruction", sev: "Critical", detail: "The cluster with demonstrated grid-impact capability. Reaches OT through IT, abuses native control-system protocols rather than exploits, and follows with wiper malware to slow recovery." },
      { name: "Ransomware affiliates (Akira / Qilin / BlackCat-style)", origin: "Financially motivated eCrime", motive: "Extortion", sev: "Critical", detail: "Entry via phishing or purchased valid credentials. Precursors include shadow-copy deletion and rapid mass file encryption; double extortion adds disclosure of customer and engineering data on top of the outage." },
      { name: "Hacktivists targeting exposed controllers (CyberAv3ngers-style)", origin: "Ideological", motive: "Disruption / publicity", sev: "High", detail: "Scans for internet-exposed HMIs and PLCs still on vendor default credentials, changes setpoints or defaces them, and publicises the access. Low sophistication, high visibility, and activity tracks geopolitical events." },
      { name: "Vendor / third-party remote-access compromise", origin: "Supply chain", motive: "Onward access / resale", sev: "High", detail: "An integrator, RMM provider or metering vendor is compromised and its standing access into your estate is used or resold. Detect vendor accounts appearing outside their normal hours, hosts and tooling." },
    ],
    techniques: ["T1566 Phishing", "T1190 Exploit Public-Facing Application", "T1133 External Remote Services", "T1078 Valid Accounts", "T1219 Remote Access Software", "T1486 Data Encrypted for Impact"],
    stack: "Ivanti Connect Secure / Cisco ASA / Fortinet FortiOS VPN, Citrix NetScaler, Microsoft Exchange + M365, Palo Alto PAN-OS, VMware vCenter/ESXi, OSIsoft PI historian, HMI web portals",
  },
  {
    id: "gov", name: "State / Federal Agency", short: "the Agency", sector: "Government",
    blurb: "Public-sector entity holding citizen PII, benefits data, and operational systems. High nation-state and hacktivist interest; legacy systems and constrained budgets widen the attack surface.",
    posture: ["Heavy nation-state targeting for espionage and pre-positioning in critical services.", "Edge-device and VPN exploitation is a leading initial-access route.", "Supply-chain / third-party SaaS breaches cause outsized impact."],
    actors: [
      { name: "Nation-state espionage (multiple)", origin: "State", motive: "Espionage / pre-positioning", sev: "Critical", detail: "Targets edge devices, identity providers, and email for long-dwell collection." },
      { name: "Ransomware affiliates", origin: "eCrime", motive: "Extortion", sev: "Critical", detail: "Disrupts public services; double-extortion with data leak." },
      { name: "Hacktivists", origin: "Ideological", motive: "Disruption", sev: "Medium", detail: "DDoS and defacement around political events." },
    ],
    techniques: ["T1190 Exploit Public-Facing App", "T1133 External Remote Services", "T1078 Valid Accounts", "T1486 Data Encrypted for Impact"],
    stack: "Ivanti / Fortinet FortiOS / Cisco ASA VPN, Citrix NetScaler, Microsoft Exchange, Palo Alto PAN-OS, legacy public-facing web apps, VMware",
  },
  {
    id: "tech", name: "SaaS / Technology Co.", short: "the Company", sector: "Technology",
    blurb: "Cloud-native software company. Source code, customer data, and CI/CD pipelines are the crown jewels. Identity and cloud control-plane abuse dominate.",
    posture: ["Identity is the perimeter — OAuth token theft and session hijacking are primary risks.", "CI/CD and developer endpoints are high-value pivots.", "Supply-chain compromise of dependencies and build systems."],
    actors: [
      { name: "Access-broker / Scattered-Spider-style", origin: "eCrime", motive: "Access resale / extortion", sev: "High", detail: "Help-desk social engineering, MFA fatigue, SIM-swap to seize identities." },
      { name: "Nation-state supply-chain actors", origin: "State", motive: "Downstream access", sev: "Critical", detail: "Implants in build pipeline / dependencies to reach customers." },
    ],
    techniques: ["T1528 Steal App Access Token", "T1556 Modify Auth Process", "T1195 Supply Chain Compromise", "T1648 Serverless Execution"],
    stack: "Okta / Entra ID, GitHub / GitLab CI/CD, AWS + Kubernetes control plane, Atlassian Jira/Confluence, Jenkins, Ivanti / Fortinet VPN",
  },
  {
    id: "health", name: "Hospital / Health System", short: "the Health System", sector: "Healthcare",
    blurb: "Care-delivery org with PHI, medical devices, and life-safety uptime requirements. Ransomware poses direct patient-safety risk.",
    posture: ["Ransomware is the dominant existential threat due to care-disruption leverage.", "Unpatchable medical (IoMT) devices expand the attack surface.", "PHI theft for fraud and extortion."],
    actors: [
      { name: "Ransomware affiliates", origin: "eCrime", motive: "Extortion", sev: "Critical", detail: "Targets uptime-critical systems for maximum pressure." },
      { name: "PHI data brokers", origin: "eCrime", motive: "Fraud", sev: "High", detail: "Bulk exfil of patient records." },
    ],
    techniques: ["T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery", "T1078 Valid Accounts", "T1567 Exfiltration to Web Service"],
    stack: "Citrix NetScaler / Ivanti VPN, Microsoft Exchange, Epic/Cerner-adjacent web portals, VMware vCenter/ESXi, Fortinet FortiOS, IoMT device gateways",
  },
  {
    id: "finance", name: "Bank / Financial Services", short: "the Bank", sector: "Finance",
    blurb: "Regulated financial institution. Direct monetary theft, fraud, and well-resourced eCrime/state actors. Mature detection expected.",
    posture: ["High-skill financially motivated and state actors.", "Business email compromise and payment fraud at scale.", "Strict regulatory detection/reporting obligations."],
    actors: [
      { name: "Financial eCrime syndicates", origin: "eCrime", motive: "Theft / fraud", sev: "Critical", detail: "BEC, ATM/SWIFT fraud, info-stealers." },
      { name: "State-sponsored financial theft", origin: "State", motive: "Revenue", sev: "High", detail: "Targets payment infrastructure." },
    ],
    techniques: ["T1566 Phishing", "T1114 Email Collection", "T1071 App-Layer C2", "T1657 Financial Theft"],
    stack: "Citrix NetScaler / Palo Alto GlobalProtect VPN, Microsoft Exchange + M365, MOVEit / managed file transfer, F5 BIG-IP, Oracle WebLogic, VMware",
  },
];

/* ---------------------- HUNT LIBRARY ----------------------
   Queries are validated-syntax STARTING POINTS. Field/dataset/
   index names must be tuned to each environment's schema. */
export const HUNTS = [
  {
    id: "ps-enc", name: "Encoded / Base64 PowerShell Execution", technique: "T1059.001 — PowerShell",
    tactic: "Execution / Defense Evasion", sev: "High", source: "Endpoint / EDR", industries: ALL_INDUSTRIES,
    hypothesis: "An adversary (e.g. Mint Sandstorm post-phish) runs obfuscated PowerShell with -EncodedCommand or in-memory Base64 payloads to evade script logging.",
    fp: "Legitimate use: SCCM, software deployment, admin tooling. Baseline parent processes and exclude known management hosts/service accounts.",
    queries: {
      crowdstrike: `#event_simpleName=ProcessRollup2 ImageFileName=/powershell(_ise)?\\.exe$/i
| CommandLine=/(-enc|-encodedcommand|frombase64string)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])`,
      xsiam: `dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_name in ("powershell.exe","powershell_ise.exe")
| filter lowercase(action_process_image_command_line) contains "-enc"
   or lowercase(action_process_image_command_line) contains "frombase64string"
| fields agent_hostname, actor_effective_username, causality_actor_process_image_name, action_process_image_command_line`,
      sentinel: `DeviceProcessEvents
| where FileName in~ ("powershell.exe","powershell_ise.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      defender: `DeviceProcessEvents
| where FileName in~ ("powershell.exe","powershell_ise.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      elastic: `FROM logs-*
| WHERE event.category == "process" AND process.name IN ("powershell.exe","powershell_ise.exe")
  AND (process.command_line LIKE "*-enc*" OR process.command_line LIKE "*FromBase64String*")
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| LIMIT 200`,
      secops: `rule otter_encoded_powershell {
  meta:
    description = "Encoded/Base64 PowerShell execution"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.file.full_path, \\\`powershell(_ise)?\\\\.exe$\\\`) nocase
    re.regex($e.principal.process.command_line, \\\`-enc|-encodedcommand|frombase64string\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=edr process_name IN ("powershell.exe","powershell_ise.exe")
  (command_line="*-enc*" OR command_line="*FromBase64String*")
| table _time host user parent_process_name command_line`,
    },
  },
  {
    id: "rmm", name: "Unsanctioned Remote-Management Tool (RMM)", technique: "T1219 — Remote Access Software",
    tactic: "Command & Control", sev: "High", source: "Endpoint / EDR", industries: ["utility", "gov", "tech", "finance"],
    hypothesis: "Iranian APTs and the DPRK IT-worker scheme persist via legitimate RMM software (AnyDesk, ScreenConnect, Atera, RustDesk) rather than custom malware to blend in.",
    fp: "IT may sanction one RMM tool. Allow-list the approved product/host group and alert on everything else.",
    queries: {
      crowdstrike: `#event_simpleName=ProcessRollup2
| ImageFileName=/(anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|remoteutilities|rustdesk|ngrok)/i
| groupBy([ComputerName, UserName, ImageFileName], function=collect([CommandLine]))`,
      xsiam: `dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_name in ("anydesk.exe","teamviewer.exe","screenconnect.exe","atera_agent.exe","splashtop.exe","rustdesk.exe","ngrok.exe")
| comp count() as runs by agent_hostname, actor_effective_username, action_process_image_name
| sort desc runs`,
      sentinel: `DeviceProcessEvents
| where FileName has_any ("anydesk","teamviewer","screenconnect","atera","splashtop","rustdesk","ngrok")
| summarize Count=count(), Hosts=make_set(DeviceName) by FileName, AccountName
| sort by Count desc`,
      defender: `DeviceProcessEvents
| where FileName has_any ("anydesk","teamviewer","screenconnect","atera","splashtop","rustdesk","ngrok")
| summarize Count=count(), Hosts=make_set(DeviceName) by FileName, AccountName
| sort by Count desc`,
      elastic: `FROM logs-*
| WHERE event.category == "process" AND (process.name LIKE "*anydesk*" OR process.name LIKE "*teamviewer*"
  OR process.name LIKE "*screenconnect*" OR process.name LIKE "*atera*" OR process.name LIKE "*rustdesk*" OR process.name LIKE "*ngrok*")
| STATS runs = COUNT(*), hosts = VALUES(host.name) BY process.name, user.name
| SORT runs DESC`,
      secops: `rule otter_unsanctioned_rmm {
  meta:
    description = "Unsanctioned remote-management tool execution"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.file.full_path, \\\`(anydesk|teamviewer|screenconnect|atera|splashtop|rustdesk|ngrok)\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=edr process_name IN ("anydesk.exe","teamviewer.exe","screenconnect.exe","atera_agent.exe","splashtop.exe","rustdesk.exe","ngrok.exe")
| stats count values(host) as hosts by process_name user
| sort - count`,
    },
  },
  {
    id: "oauth-consent", name: "Anomalous OAuth App Consent Grant", technique: "T1528 — Steal Application Access Token",
    tactic: "Credential Access / Persistence", sev: "High", source: "Identity / IdP", industries: ["utility", "tech", "gov", "finance"],
    hypothesis: "After a phish, the actor tricks a user into granting consent to a malicious OAuth app, gaining durable mailbox/file access that survives password resets.",
    fp: "Legitimate new app integrations. Baseline approved publishers; alert on unverified publishers and high-privilege scopes (Mail.ReadWrite, Files.ReadWrite.All).",
    note: "Requires Entra ID / M365 audit logs to be onboarded — endpoint EDR will not see this.",
    queries: {
      crowdstrike: `// Falcon Next-Gen SIEM — requires Microsoft Entra ID audit logs onboarded
operationName="Consent to application"
| groupBy([initiatedByUser, targetAppDisplayName, result], function=count())
| sort(result, order=desc)`,
      xsiam: `dataset = msft_azure_ad_audit_raw
| filter operation_name = "Consent to application"
| fields _time, user_name, target_application, result
| limit 200`,
      sentinel: `AuditLogs
| where OperationName == "Consent to application"
| extend App = tostring(TargetResources[0].displayName)
| extend User = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, User, App, Result, CorrelationId`,
      defender: `CloudAppEvents
| where ActionType == "Consent to application"
| project Timestamp, AccountDisplayName, ObjectName, ActivityObjects, IPAddress`,
      elastic: `FROM logs-*
| WHERE event.action == "Consent to application"
| KEEP @timestamp, user.name, azure.auditlogs.properties.target_resources, event.outcome
| LIMIT 200`,
      secops: `rule otter_oauth_consent {
  meta:
    description = "Anomalous OAuth application consent grant"
  events:
    re.regex($e.metadata.product_event_type, \\\`Consent to application\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=azuread sourcetype="azure:aad:audit" operationName="Consent to application"
| rename initiatedBy.user.userPrincipalName as user
| table _time user targetResources{}.displayName result`,
    },
  },
  {
    id: "mfa-fatigue", name: "MFA Fatigue / New MFA Device Registration", technique: "T1621 / T1556.006 — MFA Request Generation",
    tactic: "Credential Access", sev: "Medium", source: "Identity / IdP", industries: ALL_INDUSTRIES,
    hypothesis: "Adversary with valid creds spams push prompts (MFA fatigue) or self-enrolls a new MFA method to hijack the account.",
    fp: "Genuine new-phone enrollment and travel. Correlate with prior failed pushes and new sign-in geo/device.",
    note: "Requires sign-in + audit identity telemetry.",
    queries: {
      crowdstrike: `// Falcon Next-Gen SIEM — Entra sign-in + audit logs onboarded
(operationName="User registered security info" OR status.failureReason=/strong authentication/i)
| groupBy([userPrincipalName], function=count(as=events))
| events > 5`,
      xsiam: `dataset = msft_azure_ad_signin_raw
| filter result_reason contains "MFA" or auth_requirement = "multiFactorAuthentication"
| comp count() as mfa_events by user_name, bin(_time, 10m)
| filter mfa_events > 5`,
      sentinel: `SigninLogs
| where ResultType in ("50074","500121")
| summarize Attempts=count() by UserPrincipalName, bin(TimeGenerated, 10m)
| where Attempts > 5`,
      defender: `AADSignInEventsBeta
| where ErrorCode in (50074, 500121)
| summarize Attempts=count() by AccountUpn, bin(Timestamp, 10m)
| where Attempts > 5`,
      elastic: `FROM logs-*
| WHERE event.category == "authentication" AND event.outcome == "failure"
  AND azure.signinlogs.result_type IN ("50074","500121")
| STATS attempts = COUNT(*) BY user.name
| WHERE attempts > 5`,
      secops: `rule otter_mfa_fatigue {
  meta:
    description = "MFA fatigue — repeated MFA challenges per user"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $user = $e.principal.user.userid
  match:
    $user over 10m
  outcome:
    $attempts = count($e.metadata.id)
  condition:
    $e and $attempts > 5
}`,
      splunk: `index=azuread sourcetype="azure:aad:signin" (status.errorCode=50074 OR status.errorCode=500121)
| bucket _time span=10m
| stats count as attempts by user _time
| where attempts > 5`,
    },
  },
  {
    id: "impossible-travel", name: "Impossible-Travel / Atypical Sign-in", technique: "T1078 — Valid Accounts",
    tactic: "Initial Access / Persistence", sev: "Medium", source: "Identity / IdP", industries: ALL_INDUSTRIES,
    hypothesis: "A staff or contractor account signs in from two geographies too far apart for the time elapsed — credential compromise or session theft.",
    fp: "VPNs, cloud egress IPs, and corporate proxies. Exclude sanctioned VPN ranges and known travel.",
    note: "Requires sign-in logs with geo-IP enrichment.",
    queries: {
      crowdstrike: `// Falcon Identity Protection / NG-SIEM with sign-in geo enrichment
| groupBy([userPrincipalName], function=collect([country, ipAddress, @timestamp]))
| countryCount := count(country)
| countryCount > 1`,
      xsiam: `dataset = msft_azure_ad_signin_raw
| filter auth_result = "success"
| comp count_distinct(country) as geos, values(country) as countries by user_name, bin(_time, 1h)
| filter geos > 1`,
      sentinel: `SigninLogs
| where ResultType == 0
| summarize Countries=make_set(LocationDetails.countryOrRegion) by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1`,
      defender: `AADSignInEventsBeta
| where ErrorCode == 0
| summarize Countries=make_set(Country) by AccountUpn, bin(Timestamp, 1h)
| where array_length(Countries) > 1`,
      elastic: `FROM logs-*
| WHERE event.category == "authentication" AND event.outcome == "success"
| STATS geos = COUNT_DISTINCT(source.geo.country_name) BY user.name, bucket = BUCKET(@timestamp, 1 hour)
| WHERE geos > 1`,
      secops: `rule otter_impossible_travel {
  meta:
    description = "Sign-ins from 2+ cities in a short window"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.user.userid = $user
    $e.principal.location.city = $city
  match:
    $user over 1h
  condition:
    $e and #city > 1
}`,
      splunk: `index=azuread sourcetype="azure:aad:signin" status.errorCode=0
| bucket _time span=1h
| stats dc(location.countryOrRegion) as geos values(location.countryOrRegion) as countries by user _time
| where geos > 1`,
    },
  },
  {
    id: "entra-role", name: "Privileged Directory Role Granted (Entra / Okta)", technique: "T1098.003 — Additional Cloud Roles",
    tactic: "Persistence / Privilege Escalation", sev: "High", source: "Identity / IdP", industries: ALL_INDUSTRIES,
    hypothesis: "An actor with a foothold grants a high-privilege role (Global Admin, Privileged Role Admin, Okta Super Admin) to a controlled account for durable privileged access.",
    fp: "Legitimate admin onboarding. Baseline who is allowed to assign roles; alert on grants outside change windows or from new IPs.",
    note: "Requires Entra ID audit and/or Okta system log onboarding.",
    queries: {
      crowdstrike: `// Falcon NG-SIEM — Entra ID / Okta admin logs onboarded
operationName=/(Add member to role|user.account.privilege.grant)/
| targetRole=/(Global Administrator|Privileged Role Administrator|Super Administrator)/i
| groupBy([initiatedByUser, targetUser, targetRole], function=count())`,
      xsiam: `dataset = msft_azure_ad_audit_raw
| filter operation_name = "Add member to role"
| filter target_role in ("Global Administrator","Privileged Role Administrator","Application Administrator")
| fields _time, initiated_by, target_user, target_role`,
      sentinel: `AuditLogs
| where OperationName == "Add member to role"
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has_any ("Global Administrator","Privileged Role Administrator")
| project TimeGenerated, InitiatedBy, Role, Result`,
      defender: `CloudAppEvents
| where ActionType == "Add member to role"
| where RawEventData has_any ("Global Administrator","Privileged Role Administrator")
| project Timestamp, AccountDisplayName, ActivityObjects, IPAddress`,
      elastic: `FROM logs-*
| WHERE event.action IN ("Add member to role","user.account.privilege.grant")
  AND azure.auditlogs.properties.target_resources LIKE "*Administrator*"
| KEEP @timestamp, user.name, azure.auditlogs.properties.target_resources`,
      secops: `rule otter_priv_role_grant {
  meta:
    description = "Privileged directory role granted"
  events:
    re.regex($e.metadata.product_event_type, \\\`Add member to role|privilege.grant\\\`) nocase
    re.regex($e.target.user.attribute.roles.name, \\\`Global Administrator|Privileged Role Administrator|Super Administrator\\\`) nocase
  condition:
    $e
}`,
      splunk: `(index=okta eventType="user.account.privilege.grant")
  OR (index=azuread operationName="Add member to role")
| table _time actor.displayName target{}.displayName debugContext.debugData.privilegeGranted targetRole`,
    },
  },
  {
    id: "cloud-log-tamper", name: "Cloud Logging / Defense Tampering", technique: "T1562.008 / T1562.001 — Disable Cloud Logs",
    tactic: "Defense Evasion", sev: "Critical", source: "Cloud / SaaS", industries: ["tech", "finance", "gov", "utility"],
    hypothesis: "Attacker stops/deletes CloudTrail or disables GuardDuty to blind defenders before staging the rest of the intrusion.",
    fp: "Rare. Legitimate infra changes during migrations — verify against change tickets and the initiating identity.",
    note: "Requires AWS CloudTrail management events (equivalent: Azure Activity / GCP Audit).",
    queries: {
      crowdstrike: `// Falcon NG-SIEM — CloudTrail onboarded
eventName=/(StopLogging|DeleteTrail|UpdateTrail|DeleteDetector|UpdateDetector)/
| groupBy([userIdentity.arn, eventName, sourceIPAddress], function=count())`,
      xsiam: `dataset = amazon_aws_cloudtrail_raw
| filter event_name in ("StopLogging","DeleteTrail","UpdateTrail","DeleteDetector")
| fields _time, user_identity_arn, event_name, source_ip, aws_region`,
      sentinel: `AWSCloudTrail
| where EventName in ("StopLogging","DeleteTrail","UpdateTrail","DeleteDetector")
| project TimeGenerated, UserIdentityArn, EventName, SourceIpAddress, AWSRegion`,
      defender: `// AWS control-plane (CloudTrail) is not ingested by Defender XDR.
// Use the CrowdStrike NG-SIEM, Splunk, Elastic or SecOps query for this hunt.`,
      elastic: `FROM logs-*
| WHERE event.dataset == "aws.cloudtrail"
  AND event.action IN ("StopLogging","DeleteTrail","UpdateTrail","DeleteDetector")
| KEEP @timestamp, aws.cloudtrail.user_identity.arn, event.action, source.ip, cloud.region`,
      secops: `rule otter_cloud_log_tamper {
  meta:
    description = "CloudTrail / GuardDuty logging disabled"
  events:
    re.regex($e.metadata.product_event_type, \\\`StopLogging|DeleteTrail|UpdateTrail|DeleteDetector\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=cloudtrail eventName IN ("StopLogging","DeleteTrail","UpdateTrail","DeleteDetector")
| table _time userIdentity.arn eventName sourceIPAddress awsRegion`,
    },
  },
  {
    id: "iam-key", name: "New IAM Access Key for Existing User", technique: "T1098.001 — Additional Cloud Credentials",
    tactic: "Persistence", sev: "High", source: "Cloud / SaaS", industries: ["tech", "finance", "gov", "utility"],
    hypothesis: "An attacker creates a new long-lived access key on a compromised IAM user for persistence and out-of-band tooling.",
    fp: "Legitimate key rotation. Prioritize when the creator differs from the key owner, or the target user is privileged.",
    note: "Requires AWS CloudTrail.",
    queries: {
      crowdstrike: `// Falcon NG-SIEM — CloudTrail onboarded
eventName="CreateAccessKey"
| groupBy([userIdentity.arn, responseElements.accessKey.userName, sourceIPAddress], function=count())`,
      xsiam: `dataset = amazon_aws_cloudtrail_raw
| filter event_name = "CreateAccessKey"
| fields _time, user_identity_arn, request_user_name, source_ip`,
      sentinel: `AWSCloudTrail
| where EventName == "CreateAccessKey"
| project TimeGenerated, UserIdentityArn, RequestParameters, SourceIpAddress`,
      defender: `// AWS IAM events are not ingested by Defender XDR.
// Use the CrowdStrike NG-SIEM, Splunk, Elastic or SecOps query for this hunt.`,
      elastic: `FROM logs-*
| WHERE event.dataset == "aws.cloudtrail" AND event.action == "CreateAccessKey"
| KEEP @timestamp, aws.cloudtrail.user_identity.arn, aws.cloudtrail.request_parameters, source.ip`,
      secops: `rule otter_new_iam_key {
  meta:
    description = "New IAM access key created"
  events:
    $e.metadata.product_event_type = "CreateAccessKey"
  condition:
    $e
}`,
      splunk: `index=cloudtrail eventName="CreateAccessKey"
| table _time userIdentity.arn requestParameters.userName sourceIPAddress`,
    },
  },
  {
    id: "vss-delete", name: "Volume Shadow Copy Deletion (Ransomware Precursor)", technique: "T1490 — Inhibit System Recovery",
    tactic: "Impact", sev: "Critical", source: "Endpoint / EDR", industries: ALL_INDUSTRIES,
    hypothesis: "Pre-encryption, ransomware deletes shadow copies / backups (vssadmin, wmic, wbadmin, bcdedit) to prevent recovery.",
    fp: "Very rare legitimately. Almost always investigate; whitelist specific backup-software service accounts only.",
    queries: {
      crowdstrike: `#event_simpleName=ProcessRollup2
| CommandLine=/(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])`,
      xsiam: `dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_name in ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe")
| filter lowercase(action_process_image_command_line) contains "delete"
   or lowercase(action_process_image_command_line) contains "recoveryenabled no"
| fields agent_hostname, actor_effective_username, action_process_image_command_line`,
      sentinel: `DeviceProcessEvents
| where FileName in~ ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe")
| where ProcessCommandLine has_any ("delete shadows","shadowcopy delete","delete catalog","recoveryenabled no")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      defender: `DeviceProcessEvents
| where FileName in~ ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe")
| where ProcessCommandLine has_any ("delete shadows","shadowcopy delete","delete catalog","recoveryenabled no")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      elastic: `FROM logs-*
| WHERE event.category == "process"
  AND process.name IN ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe")
  AND (process.command_line LIKE "*delete*shadow*" OR process.command_line LIKE "*recoveryenabled no*" OR process.command_line LIKE "*delete catalog*")
| KEEP @timestamp, host.name, user.name, process.command_line`,
      secops: `rule otter_vss_delete {
  meta:
    description = "Shadow copy / backup deletion (ransomware precursor)"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.command_line, \\\`(vssadmin.*delete.*shadows|shadowcopy.*delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no)\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=edr process_name IN ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe")
  (command_line="*delete*shadow*" OR command_line="*recoveryenabled no*" OR command_line="*delete catalog*")
| table _time host user command_line`,
    },
  },
  {
    id: "mass-encrypt", name: "Rapid Mass File Modification (Encryption)", technique: "T1486 — Data Encrypted for Impact",
    tactic: "Impact", sev: "Critical", source: "Endpoint / EDR", industries: ALL_INDUSTRIES,
    hypothesis: "A single process modifies/renames a large volume of files in a short window — active ransomware encryption.",
    fp: "Backup, indexing, large software installs, media transcoding. Tune the per-window threshold to your endpoints.",
    queries: {
      crowdstrike: `#event_simpleName=/^(NewExecutableWritten|RansomwareOpenFile|FileWritten)$/
| groupBy([aid, ContextProcessId], function=count(as=fileOps))
| fileOps > 500`,
      xsiam: `dataset = xdr_data
| filter event_type = ENUM.FILE and event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_RENAME)
| comp count() as file_ops by agent_hostname, actor_process_instance_id, bin(_time, 5m)
| filter file_ops > 500
| sort desc file_ops`,
      sentinel: `DeviceFileEvents
| where ActionType in ("FileModified","FileRenamed","FileCreated")
| summarize Ops=count() by DeviceName, InitiatingProcessId, bin(Timestamp, 5m)
| where Ops > 500`,
      defender: `DeviceFileEvents
| where ActionType in ("FileModified","FileRenamed","FileCreated")
| summarize Ops=count() by DeviceName, InitiatingProcessId, bin(Timestamp, 5m)
| where Ops > 500`,
      elastic: `FROM logs-*
| WHERE event.category == "file" AND event.action IN ("modification","rename","creation")
| STATS ops = COUNT(*) BY host.name, process.entity_id, bucket = BUCKET(@timestamp, 5 minute)
| WHERE ops > 500`,
      secops: `rule otter_mass_encrypt {
  meta:
    description = "Rapid mass file modification (ransomware encryption)"
  events:
    $e.metadata.event_type = "FILE_MODIFICATION"
    $host = $e.principal.hostname
    $pid = $e.principal.process.pid
  match:
    $host, $pid over 5m
  outcome:
    $ops = count($e.metadata.id)
  condition:
    $e and $ops > 500
}`,
      splunk: `index=edr (action=modified OR action=renamed OR action=created)
| bucket _time span=5m
| stats count as ops by host process_id _time
| where ops > 500`,
    },
  },
  {
    id: "dns-tunnel", name: "DNS Tunneling / Beaconing", technique: "T1071.004 / T1572 — DNS C2",
    tactic: "Command & Control", sev: "High", source: "DNS", industries: ["utility", "gov", "tech", "finance"],
    hypothesis: "C2 hides in DNS — abnormally high query volume to one domain, very long labels, or high subdomain entropy.",
    fp: "CDNs, telemetry/AV, and cloud SaaS use long randomized subdomains. Allow-list known high-volume domains first.",
    note: "Requires DNS resolver / query logs.",
    queries: {
      crowdstrike: `#event_simpleName=DnsRequest
| domainLen := length(DomainName)
| groupBy([ComputerName, DomainName], function=[count(as=qcount), max(domainLen, as=maxLen)])
| qcount > 500 OR maxLen > 100`,
      xsiam: `dataset = xdr_data
| filter event_type = ENUM.NETWORK and dns_query_name != null
| alter qlen = len(dns_query_name)
| comp count() as qcount, max(qlen) as maxlen by agent_hostname, dns_query_name
| filter qcount > 500 or maxlen > 100
| sort desc qcount`,
      sentinel: `DnsEvents
| extend QLen = strlen(Name)
| summarize Qcount=count(), MaxLen=max(QLen) by ClientIP, Name
| where Qcount > 500 or MaxLen > 100`,
      defender: `DeviceNetworkEvents
| where ActionType == "DnsQueryResponse" or isnotempty(RemoteUrl)
| extend QLen = strlen(RemoteUrl)
| summarize Qcount=count(), MaxLen=max(QLen) by DeviceName, RemoteUrl
| where Qcount > 500 or MaxLen > 100`,
      elastic: `FROM logs-*
| WHERE event.category == "dns"
| EVAL qlen = LENGTH(dns.question.name)
| STATS qcount = COUNT(*), maxlen = MAX(qlen) BY source.ip, dns.question.name
| WHERE qcount > 500 OR maxlen > 100`,
      secops: `rule otter_dns_tunnel {
  meta:
    description = "DNS tunneling — high volume or long labels"
  events:
    $e.metadata.event_type = "NETWORK_DNS"
    $host = $e.principal.hostname
    $dom = $e.network.dns.questions.name
  match:
    $host, $dom over 1h
  outcome:
    $qcount = count($e.metadata.id)
  condition:
    $e and $qcount > 500
}`,
      splunk: `index=dns sourcetype=dns
| eval qlen=len(query)
| stats count as qcount max(qlen) as maxlen by src_ip query
| where qcount > 500 OR maxlen > 100`,
    },
  },
  {
    id: "lolbin-download", name: "LOLBin Remote Payload Download", technique: "T1105 — Ingress Tool Transfer",
    tactic: "Command & Control", sev: "Medium", source: "Endpoint / EDR", industries: ALL_INDUSTRIES,
    hypothesis: "Built-in binaries (certutil, bitsadmin, curl, mshta) are abused to pull a second-stage payload from the internet.",
    fp: "certutil/curl have admin uses. Focus on commands containing http/https + a write/output path.",
    queries: {
      crowdstrike: `#event_simpleName=ProcessRollup2
| ImageFileName=/(certutil|bitsadmin|mshta|curl|wget)\\.exe$/i
| CommandLine=/(http|ftp):\\/\\//i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine])`,
      xsiam: `dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_name in ("certutil.exe","bitsadmin.exe","mshta.exe","curl.exe","wget.exe")
| filter action_process_image_command_line contains "http"
| fields agent_hostname, actor_effective_username, action_process_image_name, action_process_image_command_line`,
      sentinel: `DeviceProcessEvents
| where FileName in~ ("certutil.exe","bitsadmin.exe","mshta.exe","curl.exe","wget.exe")
| where ProcessCommandLine has_any ("http://","https://","ftp://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      defender: `DeviceProcessEvents
| where FileName in~ ("certutil.exe","bitsadmin.exe","mshta.exe","curl.exe","wget.exe")
| where ProcessCommandLine has_any ("http://","https://","ftp://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      elastic: `FROM logs-*
| WHERE event.category == "process"
  AND process.name IN ("certutil.exe","bitsadmin.exe","mshta.exe","curl.exe","wget.exe")
  AND (process.command_line LIKE "*http://*" OR process.command_line LIKE "*https://*" OR process.command_line LIKE "*ftp://*")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line`,
      secops: `rule otter_lolbin_download {
  meta:
    description = "LOLBin used to download a remote payload"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.file.full_path, \\\`(certutil|bitsadmin|mshta|curl|wget)\\\\.exe$\\\`) nocase
    re.regex($e.principal.process.command_line, \\\`https?://|ftp://\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=edr process_name IN ("certutil.exe","bitsadmin.exe","mshta.exe","curl.exe","wget.exe")
  (command_line="*http://*" OR command_line="*https://*")
| table _time host user process_name command_line`,
    },
  },
  {
    id: "rdp-burst", name: "RDP Lateral-Movement Burst", technique: "T1021.001 — Remote Desktop Protocol",
    tactic: "Lateral Movement", sev: "High", source: "Windows Event Logs", industries: ALL_INDUSTRIES,
    hypothesis: "One account makes RDP (Logon Type 10) connections to many distinct hosts in a short window — hands-on-keyboard spread.",
    fp: "Jump hosts and IT admins legitimately fan out. Exclude bastion/admin workstations and service accounts.",
    note: "Requires Windows Security Event ID 4624 collection.",
    queries: {
      crowdstrike: `#event_simpleName=UserLogon LogonType=10
| groupBy([UserName], function=[count_distinct(ComputerName, as=hostCount)])
| hostCount > 5`,
      xsiam: `config case_sensitive = false
| dataset = xdr_data
| filter event_type = EVENT_LOG and action_evtlog_event_id = 4624
| alter logon_type = json_extract_scalar(action_evtlog_data_fields, "$.LogonType"),
        target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName")
| filter logon_type = "10"
| comp count_distinct(agent_hostname) as host_count by target_user, bin(_time, 15m)
| filter host_count > 5`,
      sentinel: `SecurityEvent
| where EventID == 4624 and LogonType == 10
| summarize Hosts=dcount(Computer) by Account, bin(TimeGenerated, 15m)
| where Hosts > 5`,
      defender: `DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| summarize Hosts=dcount(DeviceName) by AccountName, bin(Timestamp, 15m)
| where Hosts > 5`,
      elastic: `FROM logs-*
| WHERE event.code == "4624" AND winlog.event_data.LogonType == "10"
| STATS hosts = COUNT_DISTINCT(host.name) BY winlog.event_data.TargetUserName, bucket = BUCKET(@timestamp, 15 minute)
| WHERE hosts > 5`,
      secops: `rule otter_rdp_burst {
  meta:
    description = "One account RDPs to many hosts quickly"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.extensions.auth.mechanism = "REMOTE_INTERACTIVE"
    $user = $e.principal.user.userid
    $host = $e.target.hostname
  match:
    $user over 15m
  outcome:
    $hosts = count_distinct($host)
  condition:
    $e and $hosts > 5
}`,
      splunk: `index=wineventlog EventCode=4624 Logon_Type=10
| bucket _time span=15m
| stats dc(Computer) as hosts by Account _time
| where hosts > 5`,
    },
  },
  {
    id: "webshell", name: "Web Shell on Public-Facing Application", technique: "T1505.003 — Web Shell",
    tactic: "Persistence", sev: "Critical", source: "Endpoint / EDR", industries: ALL_INDUSTRIES,
    hypothesis: "A web server process (w3wp, httpd, php-fpm, java) spawns a command shell — classic web-shell exploitation of an internet-facing application or portal.",
    fp: "Some apps shell out legitimately (build agents, CGI). Baseline normal child processes per web app.",
    queries: {
      crowdstrike: `#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(w3wp|httpd|nginx|php-cgi|php-fpm|tomcat|java)\\.exe$/i
| ImageFileName=/(cmd|powershell|bash|sh|whoami|net1?)\\.exe$/i
| table([@timestamp, ComputerName, ParentBaseFileName, ImageFileName, CommandLine])`,
      xsiam: `dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter causality_actor_process_image_name in ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat.exe","java.exe")
| filter action_process_image_name in ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| fields agent_hostname, causality_actor_process_image_name, action_process_image_name, action_process_image_command_line`,
      sentinel: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat.exe","java.exe")
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      defender: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat.exe","java.exe")
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      elastic: `FROM logs-*
| WHERE event.category == "process"
  AND process.parent.name IN ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat.exe","java.exe")
  AND process.name IN ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| KEEP @timestamp, host.name, process.parent.name, process.name, process.command_line`,
      secops: `rule otter_webshell {
  meta:
    description = "Web server process spawned a command shell"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.parent_process.file.full_path, \\\`(w3wp|httpd|nginx|php-cgi|php-fpm|tomcat|java)\\\`) nocase
    re.regex($e.principal.process.file.full_path, \\\`(cmd|powershell|bash|sh|whoami|net)\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=edr parent_process_name IN ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat.exe","java.exe")
  process_name IN ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| table _time host parent_process_name process_name command_line`,
    },
  },
  {
    id: "linux-cron", name: "Linux Cron Persistence", technique: "T1053.003 — Cron",
    tactic: "Persistence", sev: "Medium", source: "Endpoint / EDR", industries: ALL_INDUSTRIES,
    hypothesis: "An actor installs a cron job (crontab edit, or a drop into /etc/cron.* or /var/spool/cron) to maintain access on a Linux host.",
    fp: "Legitimate admin and configuration-management deployments. Baseline known jobs and deployment tooling/users.",
    note: "Linux endpoint telemetry required.",
    queries: {
      crowdstrike: `#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/(crontab\\s+-|\\/etc\\/cron|\\/var\\/spool\\/cron)/i
| table([@timestamp, ComputerName, UserName, CommandLine])`,
      xsiam: `dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_LINUX and event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_command_line contains "crontab"
   or action_file_path contains "/etc/cron"
   or action_file_path contains "/var/spool/cron"
| fields agent_hostname, actor_effective_username, action_process_image_command_line`,
      sentinel: `DeviceProcessEvents
| where FileName == "crontab" or ProcessCommandLine has_any ("/etc/cron","/var/spool/cron")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      defender: `DeviceProcessEvents
| where FileName == "crontab" or ProcessCommandLine has_any ("/etc/cron","/var/spool/cron")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      elastic: `FROM logs-*
| WHERE event.category == "process" AND host.os.type == "linux"
  AND (process.name == "crontab" OR process.command_line LIKE "*/etc/cron*" OR process.command_line LIKE "*/var/spool/cron*")
| KEEP @timestamp, host.name, user.name, process.command_line`,
      secops: `rule otter_linux_cron {
  meta:
    description = "Linux cron persistence"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.command_line, \\\`crontab\\\\s+-|/etc/cron|/var/spool/cron\\\`) nocase
  condition:
    $e
}`,
      splunk: `(index=edr OR index=osquery) (process_name="crontab" OR command_line="*/etc/cron*" OR command_line="*/var/spool/cron*")
| table _time host user command_line`,
    },
  },
  {
    id: "linux-revshell", name: "Linux Reverse Shell / Interpreter Network Spawn", technique: "T1059.004 — Unix Shell",
    tactic: "Execution / Command & Control", sev: "High", source: "Endpoint / EDR", industries: ALL_INDUSTRIES,
    hypothesis: "A shell is spawned with a network redirection (bash -i >& /dev/tcp/...), curl|bash, or nc -e, indicating a reverse shell or staged execution.",
    fp: "Some admin/healthcheck scripts use /dev/tcp. Tune against your host baseline and exclude known tooling.",
    note: "Linux endpoint telemetry required.",
    queries: {
      crowdstrike: `#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/(\\/dev\\/(tcp|udp)\\/|sh\\s+-i|curl\\s.*\\|\\s*(ba)?sh|nc\\s+-e)/i
| table([@timestamp, ComputerName, UserName, CommandLine])`,
      xsiam: `dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_LINUX and event_type = ENUM.PROCESS
| filter action_process_image_command_line contains "/dev/tcp"
   or action_process_image_command_line contains "| bash"
   or action_process_image_command_line contains "nc -e"
| fields agent_hostname, actor_effective_username, action_process_image_command_line`,
      sentinel: `DeviceProcessEvents
| where ProcessCommandLine has_any ("/dev/tcp","/dev/udp","| bash","|bash","nc -e","sh -i")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      defender: `DeviceProcessEvents
| where ProcessCommandLine has_any ("/dev/tcp","/dev/udp","| bash","|bash","nc -e","sh -i")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      elastic: `FROM logs-*
| WHERE event.category == "process" AND host.os.type == "linux"
  AND (process.command_line LIKE "*/dev/tcp*" OR process.command_line LIKE "*| bash*" OR process.command_line LIKE "*nc -e*" OR process.command_line LIKE "*sh -i*")
| KEEP @timestamp, host.name, user.name, process.command_line`,
      secops: `rule otter_linux_revshell {
  meta:
    description = "Linux reverse shell / interpreter network spawn"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.command_line, \\\`/dev/(tcp|udp)/|sh\\\\s+-i|curl\\\\s.*\\\\|\\\\s*(ba)?sh|nc\\\\s+-e\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=edr (command_line="*/dev/tcp*" OR command_line="*| bash*" OR command_line="*nc -e*" OR command_line="*sh -i*")
| table _time host user command_line`,
    },
  },
  {
    id: "macos-launchagent", name: "macOS LaunchAgent / LaunchDaemon Persistence", technique: "T1543.001 / T1543.004 — Launch Agent/Daemon",
    tactic: "Persistence", sev: "Medium", source: "Endpoint / EDR", industries: ["utility", "tech", "finance"],
    hypothesis: "A plist is written to LaunchAgents/LaunchDaemons and loaded via launchctl for persistence on a macOS endpoint.",
    fp: "Legitimate app installers add LaunchAgents. Baseline known publishers and install paths; weight unsigned binaries.",
    note: "macOS endpoint telemetry required.",
    queries: {
      crowdstrike: `#event_simpleName=ProcessRollup2 event_platform=Mac
| CommandLine=/launchctl\\s+(load|bootstrap)/i
| table([@timestamp, ComputerName, UserName, CommandLine])`,
      xsiam: `dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_MACOS
| filter action_file_path contains "/Library/LaunchAgents/"
   or action_file_path contains "/Library/LaunchDaemons/"
   or action_process_image_command_line contains "launchctl load"
| fields agent_hostname, actor_effective_username, action_file_path, action_process_image_command_line`,
      sentinel: `DeviceFileEvents
| where FolderPath has_any ("/Library/LaunchAgents/","/Library/LaunchDaemons/")
| where FileName endswith ".plist"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName`,
      defender: `DeviceFileEvents
| where FolderPath has_any ("/Library/LaunchAgents/","/Library/LaunchDaemons/")
| where FileName endswith ".plist"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName`,
      elastic: `FROM logs-*
| WHERE host.os.type == "macos"
  AND (file.path LIKE "*/Library/LaunchAgents/*" OR file.path LIKE "*/Library/LaunchDaemons/*" OR process.command_line LIKE "*launchctl load*")
| KEEP @timestamp, host.name, user.name, file.path, process.command_line`,
      secops: `rule otter_macos_launchagent {
  meta:
    description = "macOS LaunchAgent / LaunchDaemon persistence"
  events:
    re.regex($e.target.file.full_path, \\\`/Library/(LaunchAgents|LaunchDaemons)/.*\\\\.plist$\\\`) nocase
  condition:
    $e
}`,
      splunk: `index=edr (file_path="*/Library/LaunchAgents/*" OR file_path="*/Library/LaunchDaemons/*" OR command_line="*launchctl load*")
| table _time host user file_path command_line`,
    },
  },
  {
    id: "cloud-exfil", name: "Bulk Cloud-Data Access & Exfil", technique: "T1530 / T1567.002 — Cloud Data / Exfil to Cloud",
    tactic: "Collection / Exfiltration", sev: "High", source: "Cloud / SaaS", industries: ["utility", "tech", "health", "finance"],
    hypothesis: "A compromised staff or contractor account downloads or syncs an unusual volume of files, or data egresses to a personal cloud-storage domain — staged data theft.",
    fp: "Legitimate large project transfers and bulk migrations. Baseline per-user normal volume; weight new destinations.",
    note: "Requires M365/Workspace audit logs and/or web-proxy egress logs.",
    queries: {
      crowdstrike: `// Falcon NG-SIEM — proxy / cloud audit logs onboarded
operation=/(FileDownloaded|FileSyncDownloaded)/
| groupBy([userId], function=count(as=downloads))
| downloads > 1000`,
      xsiam: `dataset = msft_o365_general_raw
| filter operation in ("FileDownloaded","FileSyncDownloadedFull")
| comp count() as downloads by user_id, bin(_time, 1h)
| filter downloads > 1000
| sort desc downloads`,
      sentinel: `OfficeActivity
| where Operation in ("FileDownloaded","FileSyncDownloadedFull")
| summarize Downloads=count() by UserId, bin(TimeGenerated, 1h)
| where Downloads > 1000`,
      defender: `CloudAppEvents
| where ActionType in ("FileDownloaded","FileSyncDownloadedFull")
| summarize Downloads=count() by AccountDisplayName, bin(Timestamp, 1h)
| where Downloads > 1000`,
      elastic: `FROM logs-*
| WHERE event.action IN ("FileDownloaded","FileSyncDownloadedFull")
| STATS downloads = COUNT(*) BY user.name, bucket = BUCKET(@timestamp, 1 hour)
| WHERE downloads > 1000`,
      secops: `rule otter_cloud_exfil {
  meta:
    description = "Bulk cloud file download / sync"
  events:
    re.regex($e.metadata.product_event_type, \\\`FileDownloaded|FileSyncDownloaded\\\`) nocase
    $user = $e.principal.user.userid
  match:
    $user over 1h
  outcome:
    $downloads = count($e.metadata.id)
  condition:
    $e and $downloads > 1000
}`,
      splunk: `index=proxy (dest_domain="*.mega.nz" OR dest_domain="*.dropbox.com" OR dest_domain="*pastebin*" OR dest_domain="*anonfiles*")
| stats sum(bytes_out) as bytes_out by user dest_domain
| where bytes_out > 524288000`,
    },
  },
];

/* ============================================================
   SIGMA -> HUNT TRANSLATOR  (best-effort, 7 platforms)
   ============================================================ */
const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, "");

const CAT = {
  process_creation: {
    source: "Endpoint / EDR",
    eventType: "PROCESS_LAUNCH",
    base: {
      crowdstrike: "#event_simpleName=ProcessRollup2",
      xsiam: "dataset = xdr_data\n| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START",
      sentinel: "DeviceProcessEvents",
      defender: "DeviceProcessEvents",
      elastic: 'FROM logs-*\n| WHERE event.category == "process" and event.type == "start"',
      splunk: "index=edr",
    },
    out: {
      crowdstrike: "| table([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine])",
      xsiam: "| fields agent_hostname, actor_effective_username, causality_actor_process_image_name, action_process_image_name, action_process_image_command_line",
      sentinel: "| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine",
      defender: "| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine",
      elastic: "| KEEP @timestamp, host.name, user.name, process.parent.name, process.name, process.command_line\n| LIMIT 200",
      splunk: "| table _time host user parent_process_name process_name command_line",
    },
    f: {
      image: { crowdstrike: "ImageFileName", xsiam: "action_process_image_path", sentinel: "FolderPath", defender: "FolderPath", elastic: "process.executable", secops: "principal.process.file.full_path", splunk: "process_path" },
      commandline: { crowdstrike: "CommandLine", xsiam: "action_process_image_command_line", sentinel: "ProcessCommandLine", defender: "ProcessCommandLine", elastic: "process.command_line", secops: "principal.process.command_line", splunk: "command_line" },
      parentimage: { crowdstrike: "ParentBaseFileName", xsiam: "causality_actor_process_image_path", sentinel: "InitiatingProcessFolderPath", defender: "InitiatingProcessFolderPath", elastic: "process.parent.executable", secops: "principal.process.parent_process.file.full_path", splunk: "parent_process_path" },
      parentcommandline: { crowdstrike: "ParentCommandLine", xsiam: "causality_actor_process_command_line", sentinel: "InitiatingProcessCommandLine", defender: "InitiatingProcessCommandLine", elastic: "process.parent.command_line", secops: "principal.process.parent_process.command_line", splunk: "parent_command_line" },
      user: { crowdstrike: "UserName", xsiam: "actor_effective_username", sentinel: "AccountName", defender: "AccountName", elastic: "user.name", secops: "principal.user.userid", splunk: "user" },
      originalfilename: { crowdstrike: "OriginalFilename", xsiam: "action_process_image_name", sentinel: "ProcessVersionInfoOriginalFileName", defender: "ProcessVersionInfoOriginalFileName", elastic: "process.pe.original_file_name", secops: "principal.process.file.full_path", splunk: "OriginalFileName" },
    },
  },
  dns_query: {
    source: "DNS",
    eventType: "NETWORK_DNS",
    base: {
      crowdstrike: "#event_simpleName=DnsRequest",
      xsiam: "dataset = xdr_data\n| filter event_type = ENUM.NETWORK and dns_query_name != null",
      sentinel: "DnsEvents",
      defender: "DeviceNetworkEvents",
      elastic: 'FROM logs-*\n| WHERE event.category == "dns"',
      splunk: "index=dns",
    },
    out: {
      crowdstrike: "| table([@timestamp, ComputerName, DomainName])",
      xsiam: "| fields agent_hostname, dns_query_name",
      sentinel: "| project TimeGenerated, ClientIP, Name",
      defender: "| project Timestamp, DeviceName, RemoteUrl",
      elastic: "| KEEP @timestamp, source.ip, dns.question.name",
      splunk: "| table _time src_ip query",
    },
    f: {
      queryname: { crowdstrike: "DomainName", xsiam: "dns_query_name", sentinel: "Name", defender: "RemoteUrl", elastic: "dns.question.name", secops: "network.dns.questions.name", splunk: "query" },
      query: { crowdstrike: "DomainName", xsiam: "dns_query_name", sentinel: "Name", defender: "RemoteUrl", elastic: "dns.question.name", secops: "network.dns.questions.name", splunk: "query" },
      destinationhostname: { crowdstrike: "DomainName", xsiam: "dns_query_name", sentinel: "Name", defender: "RemoteUrl", elastic: "dns.question.name", secops: "network.dns.questions.name", splunk: "query" },
    },
  },
  network_connection: {
    source: "Endpoint / EDR",
    eventType: "NETWORK_CONNECTION",
    base: {
      crowdstrike: "#event_simpleName=/NetworkConnectIP4|NetworkReceiveAcceptIP4/",
      xsiam: "dataset = xdr_data\n| filter event_type = ENUM.NETWORK",
      sentinel: "DeviceNetworkEvents",
      defender: "DeviceNetworkEvents",
      elastic: 'FROM logs-*\n| WHERE event.category == "network"',
      splunk: "index=network",
    },
    out: {
      crowdstrike: "| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort])",
      xsiam: "| fields agent_hostname, action_remote_ip, action_remote_port",
      sentinel: "| project Timestamp, DeviceName, RemoteIP, RemotePort",
      defender: "| project Timestamp, DeviceName, RemoteIP, RemotePort",
      elastic: "| KEEP @timestamp, host.name, destination.ip, destination.port",
      splunk: "| table _time host dest_ip dest_port",
    },
    f: {
      destinationip: { crowdstrike: "RemoteAddressIP4", xsiam: "action_remote_ip", sentinel: "RemoteIP", defender: "RemoteIP", elastic: "destination.ip", secops: "target.ip", splunk: "dest_ip" },
      destinationport: { crowdstrike: "RemotePort", xsiam: "action_remote_port", sentinel: "RemotePort", defender: "RemotePort", elastic: "destination.port", secops: "target.port", splunk: "dest_port" },
      image: { crowdstrike: "ImageFileName", xsiam: "action_process_image_path", sentinel: "InitiatingProcessFolderPath", defender: "InitiatingProcessFolderPath", elastic: "process.executable", secops: "principal.process.file.full_path", splunk: "process_path" },
    },
  },
};
CAT.dns = CAT.dns_query;

const TACTIC_MAP = {
  initial_access: "Initial Access", execution: "Execution", persistence: "Persistence",
  privilege_escalation: "Privilege Escalation", defense_evasion: "Defense Evasion",
  credential_access: "Credential Access", discovery: "Discovery", lateral_movement: "Lateral Movement",
  collection: "Collection", command_and_control: "Command & Control", exfiltration: "Exfiltration", impact: "Impact",
};
const LEVEL_MAP = { critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Low" };

export function parseYamlSubset(text) {
  const raw = text.replace(/\r/g, "").split("\n").filter((l) => l.trim() !== "" && !/^\s*#/.test(l));
  const pos = { i: 0 };
  const indentOf = (l) => l.match(/^ */)[0].length;
  const strip = (v) => {
    v = v.trim();
    if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) v = v.slice(1, -1);
    return v;
  };
  function block(min) {
    if (pos.i >= raw.length) return null;
    const ind = indentOf(raw[pos.i]);
    if (ind < min) return null;
    if (raw[pos.i].trim().startsWith("- ")) {
      const arr = [];
      while (pos.i < raw.length) {
        const line = raw[pos.i];
        const ci = indentOf(line);
        if (ci < ind || !line.trim().startsWith("- ")) break;
        const content = line.trim().slice(2);
        if (content === "") { pos.i++; arr.push(block(ci + 1)); }
        else if (/^[\w.|]+:\s*/.test(content)) { raw[pos.i] = " ".repeat(ci + 2) + content; arr.push(block(ci + 2)); }
        else { arr.push(strip(content)); pos.i++; }
      }
      return arr;
    }
    const obj = {};
    while (pos.i < raw.length) {
      const line = raw[pos.i];
      const ci = indentOf(line);
      if (ci < ind) break;
      if (ci > ind) { pos.i++; continue; }
      if (line.trim().startsWith("- ")) break;
      const m = line.trim().match(/^([^:]+):\s*(.*)$/);
      if (!m) { pos.i++; continue; }
      const key = m[1].trim(); const val = m[2];
      if (key === "__proto__" || key === "constructor" || key === "prototype") { pos.i++; if (val === "") block(ci + 1); continue; }
      if (val === "") { pos.i++; obj[key] = block(ci + 1); }
      else if (val.startsWith("[")) { obj[key] = val.replace(/^\[|\]$/g, "").split(",").map((s) => strip(s)).filter(Boolean); pos.i++; }
      else { obj[key] = strip(val); pos.i++; }
    }
    return obj;
  }
  return block(0);
}

function cond(platform, field, mod, v) {
  const q = (x) => '"' + String(x).replace(/"/g, '\\"') + '"';
  if (platform === "crowdstrike") {
    if (mod === "re") return field + "=/" + v + "/i";
    if (mod === "startswith") return field + "=" + q(v + "*");
    if (mod === "endswith") return field + "=" + q("*" + v);
    if (mod === "contains") return field + "=" + q("*" + v + "*");
    return field + "=" + q(v);
  }
  if (platform === "xsiam") {
    if (mod === "re") return field + ' ~= "' + v + '"';
    if (mod === "startswith") return field + ' ~= "^' + v + '"';
    if (mod === "endswith") return field + ' ~= "' + v + '$"';
    if (mod === "contains") return field + " contains " + q(v);
    return field + " = " + q(v);
  }
  if (platform === "sentinel" || platform === "defender") {
    if (mod === "re") return field + " matches regex " + q(v);
    if (mod === "startswith") return field + " startswith " + q(v);
    if (mod === "endswith") return field + " endswith " + q(v);
    if (mod === "contains") return field + " has " + q(v);
    return field + " =~ " + q(v);
  }
  if (platform === "elastic") {
    if (mod === "re") return field + " RLIKE " + q(v);
    if (mod === "startswith") return field + " LIKE " + q(v + "*");
    if (mod === "endswith") return field + " LIKE " + q("*" + v);
    if (mod === "contains") return field + " LIKE " + q("*" + v + "*");
    return field + " == " + q(v);
  }
  // splunk
  if (mod === "startswith") return field + "=" + q(v + "*");
  if (mod === "endswith") return field + "=" + q("*" + v);
  if (mod === "contains" || mod === "re") return field + "=" + q("*" + v + "*");
  return field + "=" + q(v);
}

function blockExpr(platform, blk, cat) {
  const joinAnd = (platform === "crowdstrike" || platform === "splunk") ? " " : " and ";
  if (Array.isArray(blk)) return "(" + blk.map((m) => blockExpr(platform, m, cat)).join(" OR ") + ")";
  const parts = [];
  for (const rawKey of Object.keys(blk || {})) {
    const segs = rawKey.split("|");
    const fname = segs[0];
    let mod = segs[1] ? segs[1].toLowerCase() : "eq";
    if (!["contains", "startswith", "endswith", "re"].includes(mod)) mod = "eq";
    const mapped = (cat.f[norm(fname)] && cat.f[norm(fname)][platform]) || fname;
    const vals = Array.isArray(blk[rawKey]) ? blk[rawKey] : [blk[rawKey]];
    const ors = vals.map((v) => cond(platform, mapped, mod, v));
    parts.push(ors.length > 1 ? "(" + ors.join(" OR ") + ")" : ors[0]);
  }
  return parts.join(joinAnd);
}

/* --- SecOps / YARA-L line builders (rule-based, not pipe-based) --- */
const BT = String.fromCharCode(96); // literal backtick for YARA-L regex delimiters
function reEsc(v, mod) {
  if (mod === "re") return v;
  return String(v).replace(/[.*+?^${}()|[\]\\]/g, (m) => "\\" + m);
}
function secopsLine(field, mod, vals, negate) {
  if (mod === "eq" && vals.length === 1) {
    return negate ? "$e." + field + ' != "' + vals[0] + '"' : "$e." + field + ' = "' + vals[0] + '"';
  }
  let rx = vals.map((v) => reEsc(v, mod)).join("|");
  if (mod === "startswith") rx = "^(" + rx + ")";
  if (mod === "endswith") rx = "(" + rx + ")$";
  const core = "re.regex($e." + field + ", " + BT + rx + BT + ") nocase";
  return negate ? "not " + core : core;
}
function blockToSecops(blk, cat, negate) {
  const lines = [];
  if (Array.isArray(blk)) { blk.forEach((m) => lines.push(...blockToSecops(m, cat, negate))); return lines; }
  for (const rawKey of Object.keys(blk || {})) {
    const segs = rawKey.split("|");
    let mod = segs[1] ? segs[1].toLowerCase() : "eq";
    if (!["contains", "startswith", "endswith", "re"].includes(mod)) mod = "eq";
    const mapped = (cat.f[norm(segs[0])] && cat.f[norm(segs[0])].secops) || ("principal.process." + norm(segs[0]));
    const vals = Array.isArray(blk[rawKey]) ? blk[rawKey] : [blk[rawKey]];
    lines.push(secopsLine(mapped, mod, vals, negate));
  }
  return lines;
}

function buildQuery(platform, logsource, detection) {
  const category = norm(logsource.category || "");
  const cat = CAT[category] || { ...CAT.process_creation, unknown: true };
  const keys = Object.keys(detection || {}).filter((k) => k !== "condition");
  const selNames = keys.filter((k) => !/^(filter|except|reduction|fp)/.test(k.toLowerCase()));
  const filtNames = keys.filter((k) => /^(filter|except|reduction|fp)/.test(k.toLowerCase()));
  const condStr = String(detection.condition || "").toLowerCase();
  const orMode = /\b1 of\b/.test(condStr) || /\bor\b/.test(condStr);
  const useSel = selNames.length ? selNames : keys;

  if (platform === "secops") {
    const et = cat.eventType || "PROCESS_LAUNCH";
    const selLines = []; useSel.forEach((n) => selLines.push(...blockToSecops(detection[n], cat, false)));
    const filtLines = []; filtNames.forEach((n) => filtLines.push(...blockToSecops(detection[n], cat, true)));
    const body = ['$e.metadata.event_type = "' + et + '"', ...selLines, ...filtLines].join("\n    ");
    return "rule otter_imported {\n  meta:\n    author = \"Otter Shell\"\n    description = \"Imported Sigma rule\"\n  events:\n    " + body + "\n  condition:\n    $e\n}";
  }

  const joinAnd = (platform === "crowdstrike" || platform === "splunk") ? " " : " and ";
  const sel = useSel.map((n) => "(" + blockExpr(platform, detection[n], cat) + ")").join(orMode ? " OR " : joinAnd);
  const filt = filtNames.map((n) => "(" + blockExpr(platform, detection[n], cat) + ")").join(joinAnd);

  if (platform === "crowdstrike") {
    let q = cat.base.crowdstrike + "\n| " + sel; if (filt) q += "\n| !(" + filt + ")"; return q + "\n" + cat.out.crowdstrike;
  }
  if (platform === "xsiam") {
    let q = cat.base.xsiam + "\n| filter " + sel; if (filt) q += "\n| filter not (" + filt + ")"; return q + "\n" + cat.out.xsiam;
  }
  if (platform === "sentinel" || platform === "defender") {
    let q = cat.base[platform] + "\n| where " + sel; if (filt) q += "\n| where not (" + filt + ")"; return q + "\n" + cat.out[platform];
  }
  if (platform === "elastic") {
    let q = cat.base.elastic + "\n| WHERE " + sel; if (filt) q += "\n| WHERE NOT (" + filt + ")"; return q + "\n" + cat.out.elastic;
  }
  let q = cat.base.splunk + " " + sel; if (filt) q += " NOT (" + filt + ")"; return q + "\n" + cat.out.splunk;
}

export function sigmaToHunt(text) {
  const root = parseYamlSubset(text);
  if (!root || typeof root !== "object") throw new Error("Could not parse YAML.");
  const detection = root.detection || {};
  const logsource = root.logsource || {};
  if (!Object.keys(detection).filter((k) => k !== "condition").length) throw new Error("No 'detection' selections found.");
  const tags = Array.isArray(root.tags) ? root.tags : [];
  let technique = "—", tactic = "—";
  for (const t of tags) {
    const tt = String(t).toLowerCase();
    const tm = tt.match(/attack\.(t\d{4}(?:\.\d{3})?)/);
    if (tm && technique === "—") technique = tm[1].toUpperCase();
    const ta = tt.replace(/^attack\./, "");
    if (TACTIC_MAP[ta] && tactic === "—") tactic = TACTIC_MAP[ta];
  }
  const category = norm(logsource.category || "");
  const cat = CAT[category] || { source: "Endpoint / EDR", unknown: true };
  const queries = {};
  for (const p of PLATFORM_IDS) queries[p] = buildQuery(p, logsource, detection);
  return {
    id: genId("sig"),
    custom: true,
    name: root.title || "Imported Sigma Rule",
    technique, tactic,
    sev: LEVEL_MAP[String(root.level || "").toLowerCase()] || "Medium",
    source: cat.source || "Endpoint / EDR",
    industries: ALL_INDUSTRIES,
    hypothesis: root.description || "Imported from a Sigma rule.",
    fp: "Imported rule — review the original Sigma 'falsepositives' field and tune in your environment.",
    note: cat.unknown
      ? "Imported from Sigma — logsource category not recognized; query uses generic process defaults. Verify dataset/field mappings."
      : "Imported from Sigma — best-effort translation across platforms. Verify field/dataset names against your deployment.",
    queries,
    _sigma: { title: root.title || "", logsource, detection, level: root.level || "", tags, description: root.description || "", falsepositives: root.falsepositives || [] },
    status: "new", version: 1, author: typeof root.author === "string" ? root.author.slice(0, 80) : "Imported (Sigma)", created: root.date ? String(root.date).replace(/\//g, "-").slice(0, 10) : todayISO(), reviewed: "",
  };
}

/* ============================================================
   HUNT -> SIGMA EXPORT (detection-as-code round-trip)
   Faithful for hunts imported from Sigma (raw detection retained);
   best-effort scaffold otherwise, with native queries preserved.
   ============================================================ */
/* Collision-resistant local ID. Uses crypto.randomUUID when available,
   else a high-entropy fallback. Far larger space than the old 5-char rand. */
function genId(prefix) {
  let rand;
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) rand = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
    else if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      const a = new Uint8Array(8); crypto.getRandomValues(a);
      rand = Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
    }
  } catch { /* fall through */ }
  if (!rand) rand = (Date.now().toString(36) + Math.random().toString(36).slice(2, 10));
  return (prefix || "id") + "-" + rand;
}
function uuidish() {
  // RFC4122-ish v4 without crypto dependency (sufficient for a rule id)
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}
const SOURCE_TO_LOGSOURCE = {
  "Endpoint / EDR": { category: "process_creation", product: "windows" },
  "Windows Event Logs": { product: "windows", service: "security" },
  DNS: { category: "dns_query" },
  "Web Proxy": { category: "proxy" },
  "Identity / IdP": { product: "azure", service: "signinlogs" },
  "Cloud / SaaS": { product: "aws", service: "cloudtrail" },
};
function yamlScalar(v) {
  const s = String(v);
  return /[:#\-?\[\]{}&*!|>'"%@`]|^\s|\s$/.test(s) ? "'" + s.replace(/'/g, "''") + "'" : s;
}
function emitYaml(node, indent) {
  const pad = "  ".repeat(indent);
  if (Array.isArray(node)) {
    if (!node.length) return pad + "[]\n";
    return node.map((it) => {
      if (it && typeof it === "object") {
        const inner = emitYaml(it, indent + 1).replace(/^\s+/, "");
        return pad + "- " + inner;
      }
      return pad + "- " + yamlScalar(it) + "\n";
    }).join("");
  }
  if (node && typeof node === "object") {
    return Object.keys(node).map((k) => {
      const val = node[k];
      if (val && typeof val === "object") {
        const hasKeys = Array.isArray(val) ? val.length : Object.keys(val).length;
        if (!hasKeys) return pad + k + ": " + (Array.isArray(val) ? "[]" : "{}") + "\n";
        return pad + k + ":\n" + emitYaml(val, indent + 1);
      }
      return pad + k + ": " + yamlScalar(val) + "\n";
    }).join("");
  }
  return pad + yamlScalar(node) + "\n";
}
function literalBlock(text, indent) {
  const pad = "  ".repeat(indent);
  return String(text).split("\n").map((l) => pad + l).join("\n");
}
export function huntToSigma(hunt) {
  const techId = techIdOf(hunt);
  const tacticTags = (hunt.tactic || "").toLowerCase().split(/[/,]/).map((t) => {
    const key = Object.keys(TACTIC_MAP).find((k) => TACTIC_MAP[k].toLowerCase() === t.trim());
    return key ? "attack." + key : null;
  }).filter(Boolean);
  const tags = [...tacticTags];
  if (techId) tags.push("attack." + techId.toLowerCase());

  const head = {
    title: hunt.name || "Otter Shell Hunt",
    id: uuidish(),
    status: SIGMA_STATUS[hunt.status] || "experimental",
    description: hunt.hypothesis || "",
    author: hunt.author || "Otter Shell",
    date: (hunt.created || new Date().toISOString().slice(0, 10)).replace(/-/g, "/"),
  };
  if (hunt.reviewed) head.modified = hunt.reviewed.replace(/-/g, "/");
  const tail = {
    falsepositives: (hunt._sigma && hunt._sigma.falsepositives && hunt._sigma.falsepositives.length) ? hunt._sigma.falsepositives : [hunt.fp || "Unknown"],
    level: (hunt.sev || "medium").toLowerCase(),
  };

  let out = emitYaml(head, 0);
  if (tags.length) out += "tags:\n" + emitYaml(tags, 1);

  if (hunt._sigma && hunt._sigma.detection && Object.keys(hunt._sigma.detection).length) {
    // faithful round-trip
    const ls = hunt._sigma.logsource && Object.keys(hunt._sigma.logsource).length ? hunt._sigma.logsource : (SOURCE_TO_LOGSOURCE[hunt.source] || { category: "process_creation" });
    out += "logsource:\n" + emitYaml(ls, 1);
    out += "detection:\n" + emitYaml(hunt._sigma.detection, 1);
  } else {
    // best-effort scaffold — native queries can't be losslessly abstracted into Sigma fields
    const ls = SOURCE_TO_LOGSOURCE[hunt.source] || { category: "process_creation" };
    out += "logsource:\n" + emitYaml(ls, 1);
    out += "detection:\n";
    out += "  # Auto-derived abstract detection is not available for this hunt.\n";
    out += "  # The native per-platform queries are preserved under 'ottershell_queries' below.\n";
    out += "  # Complete this selection, or compile the native query into your platform directly.\n";
    out += "  selection:\n    EventID: '*'   # TODO: replace with real field/value criteria\n";
    out += "  condition: selection\n";
  }
  out += emitYaml(tail, 0);

  // always preserve the real queries so nothing is lost on export
  out += "ottershell_queries:\n";
  for (const p of PLATFORM_IDS) {
    if (hunt.queries && hunt.queries[p]) {
      out += "  " + p + ": |\n" + literalBlock(hunt.queries[p], 2) + "\n";
    }
  }
  return out;
}

/* ============================================================
   COVERAGE + ATT&CK NAVIGATOR HELPERS
   ============================================================ */
/* Chips for one tactic column. Two hunts can cover the same ATT&CK technique — a
   curated hunt and a custom or generated one, say — and printing the id twice reads
   as a duplicate rather than as depth, so the chips are grouped and carry a count.
   The column header still shows the hunt count, which is the honest number. */
export function techChips(hunts) {
  const out = [];
  const at = new Map();
  for (const h of hunts) {
    const id = techIdOf(h) || "—";
    const i = at.get(id);
    if (i == null) { at.set(id, out.length); out.push({ id, count: 1, sev: h.sev, hunts: [h.name] }); }
    else {
      const c = out[i];
      c.count += 1; c.hunts.push(h.name);
      // the chip's border carries the worst severity it covers
      if (SEVERITIES.indexOf(h.sev) < SEVERITIES.indexOf(c.sev)) c.sev = h.sev;
    }
  }
  return out;
}

export function techIdOf(h) {
  const m = (h.technique || "").match(/T\d{4}(?:\.\d{3})?/);
  return m ? m[0] : null;
}
/* Atomic Red Team test folder for a technique (validate that a hunt actually fires) */
export function atomicUrl(h) {
  const id = techIdOf(h);
  return id ? "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/" + id : null;
}

/* ============================================================
   QUERY LINTER — conservative, soft, non-blocking
   Strips string/regex/escape literals before counting brackets
   so regex-heavy queries don't false-positive.
   ============================================================ */
function stripLiterals(q) {
  let s = q;
  s = s.replace(/`[^`]*`/g, "``");                    // YARA-L backtick regex
  s = s.replace(/"(?:[^"\\]|\\.)*"/g, '""');           // double-quoted
  s = s.replace(/'(?:[^'\\]|\\.)*'/g, "''");           // single-quoted
  s = s.replace(/=\/(?:[^\/\\]|\\.)*\/[a-z]*/gi, "=//"); // LogScale field=/regex/
  s = s.replace(/\\[(){}\[\]]/g, "");                  // remaining escaped brackets
  return s;
}
function bracketsBalanced(q) {
  const s = stripLiterals(q);
  const close = { ")": "(", "]": "[", "}": "{" };
  const open = new Set(["(", "[", "{"]);
  const st = [];
  for (const c of s) {
    if (open.has(c)) st.push(c);
    else if (close[c]) { if (st.pop() !== close[c]) return false; }
  }
  return st.length === 0;
}
const TIME_TOKENS = ["ago(", "bin(", "bucket", "between(", "earliest", "span=", " over ", "_time", "timegenerated", "@timestamp", "now()", "starttime"];

/* Two levels, and the difference matters: a `warn` says the query itself looks wrong,
   a `note` is context for running it. Only warnings are defects — the curated library
   is asserted to raise zero of them, while notes are expected and common. */
export function lintQuery(platform, q) {
  const out = [];
  if (!q || typeof q !== "string") return [{ level: "info", msg: "No query for this platform." }];
  const body = q.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n").trim();
  if (!body) return [{ level: "info", msg: "No query for this platform — it's covered by the other platforms." }];

  if (!bracketsBalanced(q)) out.push({ level: "warn", msg: "Brackets look unbalanced — the query may be truncated." });

  if (/<[A-Za-z0-9_]+>/.test(q) || /\bTODO\b/.test(q)) out.push({ level: "info", msg: "Contains placeholders to fill in (e.g. an IP or hostname) before running." });

  // time-window nudge (skip rule-based SecOps — windowing is in the rule engine)
  if (platform !== "secops") {
    const low = q.toLowerCase();
    if (!TIME_TOKENS.some((t) => low.includes(t))) out.push({ level: "info", msg: "No explicit time window in the query — most consoles take the range from the search bar. Add a lookback if you schedule this." });
  }

  // very lenient platform-anchor sanity (only flag clearly-missing base constructs)
  const anchorOk =
    platform === "xsiam" ? /dataset\s*=/.test(body) :
    platform === "elastic" ? /\bFROM\b/.test(body) :
    platform === "secops" ? (/\brule\b/.test(body) && /condition\s*:/.test(body)) :
    platform === "splunk" ? /\bindex\s*=|\bsourcetype\s*=|^search\b/i.test(body) :
    true; // crowdstrike / sentinel / defender vary too much to anchor reliably
  if (!anchorOk) out.push({ level: "info", msg: "Doesn't contain the usual base construct for this platform — double-check the source/dataset." });

  return out;
}

/* Lint result block. The header states the warning count first, because that is the
   number that means something is wrong; notes are listed under it and labelled as
   notes, so an informational line can't be misread as a failing query. */
function LintResult({ issues, platformLabel }) {
  const warns = issues.filter((i) => i.level === "warn").length;
  const notes = issues.length - warns;
  const head =
    (warns ? "⚠ Lint: " + warns + " warning" + (warns === 1 ? "" : "s") : "✓ Lint: no warnings") +
    (platformLabel ? " for " + platformLabel : "") +
    (notes ? " · " + notes + " note" + (notes === 1 ? "" : "s") : "");
  if (!issues.length) return <div className="qr-lint ok">{head}</div>;
  return (
    <div className="qr-lint">
      <div className={"qr-lint-head" + (warns ? " warn" : "")}>{head}</div>
      {issues.map((it, i) => (
        <div key={i} className={"qr-lint-row " + it.level}>
          {it.level === "warn" ? "⚠ Warning — " : "ℹ Note — "}{it.msg}
        </div>
      ))}
    </div>
  );
}

/* Per-platform deployment-dependency notes. Currently flags Sentinel queries
   that read Defender-XDR-connector tables (DeviceProcessEvents etc.), which
   only resolve in Sentinel when the Microsoft 365 Defender connector is on. */
const SENTINEL_DEFENDER_TABLES = ["DeviceProcessEvents","DeviceNetworkEvents","DeviceFileEvents","DeviceLogonEvents","DeviceRegistryEvents","DeviceImageLoadEvents","DeviceEvents","EmailEvents","EmailUrlInfo","IdentityLogonEvents","AlertEvidence"];
function connectorNote(platform, q) {
  if (!q || typeof q !== "string") return null;
  const body = q.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  if (!body.trim()) return null;
  if (platform === "sentinel") {
    const hit = SENTINEL_DEFENDER_TABLES.find((t) => new RegExp("\\b" + t + "\\b").test(body));
    if (hit) return "Reads the " + hit + " table — available in Sentinel only with the Microsoft 365 Defender connector enabled. Without it, use the Defender XDR tab instead.";
  }
  return null;
}

/* ============================================================
   MARKDOWN REPORT EXPORT — shareable record of a hunt + journal
   ============================================================ */
function mdEscape(s) { return String(s || "").replace(/[\r\n]+/g, " ").replace(/\|/g, "\\|"); }
export function huntToMarkdown(hunt) {
  const lines = [];
  lines.push("# " + (hunt.name || "Otter Shell Hunt"));
  lines.push("");
  lines.push("**Status:** " + (STATUS_META[hunt.status] ? STATUS_META[hunt.status].label : hunt.status) +
    " · **Version:** v" + (hunt.version || 1) +
    " · **Author:** " + (hunt.author || "—") +
    " · **Severity:** " + (hunt.sev || "—"));
  lines.push("**ATT&CK:** " + (hunt.technique || "—") + " · **Tactic:** " + (hunt.tactic || "—") + " · **Source:** " + (hunt.source || "—"));
  lines.push("**Created:** " + (hunt.created || "—") + " · **Last reviewed:** " + (hunt.reviewed || "never") +
    (hunt.findings && hunt.findings.length ? " · **Last run:** " + hunt.findings[0].date + " — " + (DISPO_META[hunt.findings[0].disposition] ? DISPO_META[hunt.findings[0].disposition].label : hunt.findings[0].disposition) : ""));
  {
    const vm = VALIDATION_META[hunt.validation] || VALIDATION_META.unverified;
    lines.push("**Validation:** " + vm.label + (hunt.validation !== "unverified" && hunt.validatedOn ? " — " + hunt.validatedOn : "") + (hunt.validation !== "unverified" && hunt.validatedDate ? " (" + hunt.validatedDate + ")" : "") + " · " + vm.desc);
  }
  lines.push("");
  if (hunt.hypothesis) { lines.push("## Hypothesis"); lines.push(""); lines.push(hunt.hypothesis); lines.push(""); }
  if (hunt.fp) { lines.push("## False-Positive Tuning"); lines.push(""); lines.push(hunt.fp); lines.push(""); }
  if (hunt.note) { lines.push("## Telemetry / Notes"); lines.push(""); lines.push(hunt.note); lines.push(""); }
  if (hunt.pivots) { lines.push("## Next Steps / Pivots"); lines.push(""); lines.push(hunt.pivots); lines.push(""); }
  if (hunt.tuning) { lines.push("## Tuning Log"); lines.push(""); lines.push(hunt.tuning); lines.push(""); }
  if (hunt.findings && hunt.findings.length) {
    lines.push("## Findings");
    lines.push("");
    lines.push("| Date | Disposition | Note |");
    lines.push("| --- | --- | --- |");
    for (const f of hunt.findings) {
      const dispo = DISPO_META[f.disposition] ? DISPO_META[f.disposition].label : f.disposition;
      lines.push("| " + mdEscape(f.date) + " | " + mdEscape(dispo) + " | " + mdEscape(f.note) + " |");
    }
    lines.push("");
  }
  const platformLabels = { crowdstrike: "CrowdStrike Falcon LogScale / NG-SIEM", xsiam: "Cortex XSIAM (XQL)", sentinel: "Microsoft Sentinel (KQL)", defender: "Microsoft Defender XDR (KQL)", elastic: "Elastic Security (ES|QL)", secops: "Google SecOps (YARA-L / UDM)", splunk: "Splunk (SPL)" };
  const present = PLATFORM_IDS.filter((p) => hunt.queries && hunt.queries[p]);
  if (present.length) {
    lines.push("## Queries");
    lines.push("");
    for (const p of present) {
      lines.push("### " + platformLabels[p]);
      lines.push("");
      lines.push("```");
      lines.push(hunt.queries[p]);
      lines.push("```");
      lines.push("");
    }
  }
  lines.push("---");
  lines.push("");
  lines.push("*Generated by Otter Shell · " + new Date().toISOString().slice(0, 10) + "*");
  return lines.join("\n");
}
export function programToMarkdown(hunts, enterpriseName) {
  const lines = [];
  lines.push("# Otter Shell — Hunt Program Report");
  lines.push("");
  lines.push("**Enterprise:** " + (enterpriseName || "—") + " · **Generated:** " + new Date().toISOString().slice(0, 10) + " · **Hunts:** " + hunts.length);
  lines.push("");
  // status summary
  const counts = STATUSES.reduce((a, s) => { a[s] = hunts.filter((h) => h.status === s).length; return a; }, {});
  lines.push("## Lifecycle");
  lines.push("");
  lines.push("| Status | Count |");
  lines.push("| --- | --- |");
  for (const s of STATUSES) lines.push("| " + STATUS_META[s].label + " | " + counts[s] + " |");
  lines.push("");
  // recent findings across the program
  const all = [];
  for (const h of hunts) for (const f of (h.findings || [])) all.push({ ...f, hunt: h.name });
  all.sort((a, b) => (b.date || "").localeCompare(a.date || ""));
  if (all.length) {
    lines.push("## Recent Findings");
    lines.push("");
    lines.push("| Date | Hunt | Disposition | Note |");
    lines.push("| --- | --- | --- | --- |");
    for (const f of all.slice(0, 30)) {
      const dispo = DISPO_META[f.disposition] ? DISPO_META[f.disposition].label : f.disposition;
      lines.push("| " + mdEscape(f.date) + " | " + mdEscape(f.hunt) + " | " + mdEscape(dispo) + " | " + mdEscape(f.note) + " |");
    }
    lines.push("");
  }
  // hunt index
  lines.push("## Hunts");
  lines.push("");
  lines.push("| Status | Severity | Hunt | Technique | Last run |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const h of hunts) {
    const last = h.findings && h.findings.length ? (h.findings[0].date + " — " + (DISPO_META[h.findings[0].disposition] ? DISPO_META[h.findings[0].disposition].label : h.findings[0].disposition)) : "—";
    lines.push("| " + (STATUS_META[h.status] ? STATUS_META[h.status].label : h.status) + " | " + (h.sev || "—") + " | " + mdEscape(h.name) + " | " + mdEscape(h.technique) + " | " + mdEscape(last) + " |");
  }
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("*Generated by Otter Shell · run individual hunt reports for full queries and journal detail.*");
  return lines.join("\n");
}

export function buildNavLayer(hunts, enterprise) {
  const counts = {};
  hunts.forEach((h) => { const id = techIdOf(h); if (id) counts[id] = (counts[id] || 0) + 1; });
  const max = Math.max(1, ...Object.values(counts));
  const techniques = Object.keys(counts).map((id) => ({
    techniqueID: id,
    score: counts[id],
    color: "",
    comment: hunts.filter((h) => techIdOf(h) === id).map((h) => h.name).join("; "),
    enabled: true,
  }));
  return {
    name: "Otter Shell — " + enterprise.name + " hunt coverage",
    versions: { attack: "15", navigator: "4.9.1", layer: "4.5" },
    domain: "enterprise-attack",
    description: "Detection-hunt coverage exported from Otter Shell for " + enterprise.name + ".",
    sorting: 3,
    techniques,
    gradient: { colors: ["#2c3a46", "#f5a623", "#2dd4bf"], minValue: 0, maxValue: max },
    legendItems: [], metadata: [], showTacticRowBackground: true, tacticRowBackground: "#0d1218",
    selectTechniquesAcrossTactics: true,
  };
}

/* ============================================================
   AUTHORITATIVE CISA KEV FEED
   Source: cisagov/kev-data (CISA's own GitHub mirror, CC0).
   raw.githubusercontent.com is CORS-permissive, so the browser
   can fetch it directly — no model recall, exact + current.
   ============================================================ */
const KEV_FEED_URLS = [
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
];
let KEV_CACHE = null; // module-level cache for the session

async function loadKevCatalog() {
  if (KEV_CACHE) return KEV_CACHE;
  let lastErr;
  for (const url of KEV_FEED_URLS) {
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), 15000) : null;
    try {
      const res = await fetch(url, { cache: "no-store", signal: ctrl ? ctrl.signal : undefined });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
      if (!vulns.length) throw new Error("empty catalog");
      KEV_CACHE = { vulns, version: data.catalogVersion || data.dateReleased || "", count: vulns.length };
      return KEV_CACHE;
    } catch (e) { lastErr = e && e.name === "AbortError" ? new Error("feed timed out after 15s") : e; }
    finally { if (timer) clearTimeout(timer); }
  }
  throw lastErr || new Error("could not load KEV feed");
}

/* derive matchable vendor/product terms from an enterprise stack string */
const KEV_STOP = new Set(["vpn", "edge", "appliance", "appliances", "control", "plane", "file", "transfer", "managed",
  "web", "apps", "app", "portal", "portals", "gateway", "gateways", "style", "connect", "secure", "server", "servers",
  "device", "devices", "and", "the", "via", "networks", "network", "cloud", "legacy", "public-facing", "facing"]);
/* Each comma/slash/plus-separated phrase becomes ONE term whose significant words are
   ANDed at match time, so "Microsoft Exchange" selects Exchange CVEs rather than every
   Microsoft CVE in the catalog. The previous version also emitted each word as its own
   keyword, which left bare vendor tokens standing alone: against the September 2026
   catalog `microsoft` on its own selects 386 of 1,687 entries, and the flagship stack
   as a whole selected 617 — 37% of KEV, presented as one utility's internet-facing
   exposure. A vendor name is not a product match. */
export function stackKeywords(stack) {
  if (!stack) return [];
  const out = new Set();
  stack.split(/[,/+]/).forEach((phrase) => {
    const words = phrase.trim().split(/\s+/)
      .map((w) => w.replace(/[^\w-]/g, "").toLowerCase())
      // 3 chars is safe where 4 was not: a short word like "asa" is only ever matched
      // alongside the rest of its phrase, never on its own.
      .filter((t) => t.length >= 3 && !KEV_STOP.has(t));
    // A phrase that survives as a single short word is too generic to stand alone.
    if (!words.length || (words.length === 1 && words[0].length < 4)) return;
    out.add(words.join(" "));
  });
  return [...out];
}
/* The feed sometimes repeats the vendor as the product ("Microsoft" / "Microsoft" —
   79 entries in the September 2026 catalog). Render that once rather than twice. */
function kevProductLabel(v) {
  const vendor = String(v.vendorProject || "").trim();
  const product = String(v.product || "").trim();
  if (!vendor) return product;
  if (!product || product.toLowerCase() === vendor.toLowerCase()) return vendor;
  return vendor + " " + product;
}

/* Trim third-party text to a word boundary and mark the cut. The CISA descriptions run
   long and a hard slice ends mid-word ("...restricted HTTPS access thro"), which reads
   as a rendering bug rather than as a deliberate cap. Never exceeds `n` characters. */
function clip(text, n) {
  const t = String(text || "");
  if (t.length <= n) return t;
  const cut = t.slice(0, n - 1);
  const sp = cut.lastIndexOf(" ");
  return (sp > n * 0.6 ? cut.slice(0, sp) : cut).replace(/[\s,;:.\u2013\u2014-]+$/, "") + "\u2026";
}

/* A term matches when EVERY word in it appears in the entry's vendor/product text —
   order-independent, so "cisco asa" still matches "Cisco Secure Firewall Adaptive
   Security Appliance (ASA)". An entry matches the scan if any one term matches. */
export function matchKev(vulns, keywords, limit) {
  const terms = keywords.map((k) => String(k).toLowerCase().split(/\s+/).filter(Boolean)).filter((t) => t.length);
  if (!terms.length) return [];
  const hits = vulns.filter((v) => {
    const hay = ((v.vendorProject || "") + " " + (v.product || "") + " " + (v.vulnerabilityName || "")).toLowerCase();
    return terms.some((words) => words.every((w) => hay.includes(w)));
  });
  hits.sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")));
  // Field caps: this is third-party data fetched at runtime. React escapes it on
  // render, so the concern is layout blowout from an oversized field, not XSS.
  return hits.slice(0, limit).map((v) => ({
    cve: String(v.cveID || "").slice(0, 40),
    product: clip(kevProductLabel(v) || String(v.cveID || ""), 160),
    desc: clip(v.shortDescription || v.vulnerabilityName || "", 400),
    dateAdded: String(v.dateAdded || "").slice(0, 20),
    ransomware: /^known$/i.test((v.knownRansomwareCampaignUse || "").trim()),
  }));
}


/* source -> telemetry feed (for custom hunts not in REQUIRES) */
const SOURCE_TO_TELE = {
  "Endpoint / EDR": "Endpoint / EDR (Windows)",
  "Identity / IdP": "Entra ID / Okta sign-in + audit",
  "Cloud / SaaS": "M365 / Workspace audit",
  DNS: "DNS query logs",
  "Web Proxy": "Web proxy / egress logs",
  "Windows Event Logs": "Windows Security events (4624 etc.)",
};
const reqOf = (h) => REQUIRES[h.id] || [SOURCE_TO_TELE[h.source] || "Endpoint / EDR (Windows)"];

/* ============================================================
   HUNT PREVIEW (shared by generator + importer)
   ============================================================ */
function HuntPreview({ hunt, onAdd, onDiscard, copyFn }) {
  const [plat, setPlat] = useState("crowdstrike");
  const [cp, setCp] = useState(false);
  const doCopy = () => { copyFn(hunt.queries[plat]); setCp(true); setTimeout(() => setCp(false), 1300); };
  return (
    <div className="qr-preview">
      <div className="qr-detail-head">
        <span className="qr-sev-pill big" style={{ color: SEV_COLOR[hunt.sev] || "#fff", borderColor: SEV_COLOR[hunt.sev] || "#888" }}>{hunt.sev}</span>
        <h2>{hunt.name}</h2>
      </div>
      <div className="qr-detail-meta">
        <span><b>ATT&amp;CK</b> {hunt.technique}</span>
        <span><b>Tactic</b> {hunt.tactic}</span>
        <span><b>Source</b> {hunt.source}</span>
      </div>
      <div className="qr-field"><h4>Hunt Hypothesis</h4><p>{hunt.hypothesis}</p></div>
      <div className="qr-field"><h4>False-Positive Tuning</h4><p>{hunt.fp}</p></div>
      {hunt.note && <div className="qr-reqnote">⚠ {hunt.note}</div>}
      <div className="qr-prev-plats">
        {PLATFORMS.map((p) => (
          <button key={p.id} className={"qr-mini-pill " + (plat === p.id ? "on" : "")} onClick={() => setPlat(p.id)}>{p.label}</button>
        ))}
        <button className="qr-copy" style={{ marginLeft: "auto" }} onClick={doCopy}>{cp ? "✓ Copied" : "⧉ Copy"}</button>
      </div>
      <pre className="qr-code">{hunt.queries[plat] || "// no query authored for this platform"}</pre>
      {(() => {
        return <LintResult issues={lintQuery(plat, hunt.queries[plat])} />;
      })()}
      {(() => {
        const note = connectorNote(plat, hunt.queries[plat]);
        return note ? <div className="qr-conn-note">⊗ Deployment note: {note}</div> : null;
      })()}
      <div className="qr-prev-actions">
        <button className="qr-cta" onClick={() => onAdd(hunt)}>＋ Add to library</button>
        <button className="qr-ghost" onClick={onDiscard}>Discard</button>
      </div>
    </div>
  );
}

/* ============================================================
   ENTERPRISE BUILDER (modal)
   ============================================================ */
/* ============================================================
   HUNT JOURNAL — next steps, tuning, dated findings, IOC enrichment
   ============================================================ */
function HuntJournal({ hunt, onAddFinding, onRemoveFinding, onPivots, onTuning, onExportReport }) {
  const [dispo, setDispo] = useState("clean");
  const [note, setNote] = useState("");
  const [ioc, setIoc] = useState("");
  const links = enrichLinks(ioc);
  const submit = () => { onAddFinding(hunt.id, dispo, note); setNote(""); };
  return (
    <div className="qr-journal">
      <div className="qr-jr-head">
        <h4 className="qr-jr-title">⊕ Hunt Journal</h4>
        <button className="qr-copy" onClick={() => onExportReport(hunt)} title="Download this hunt as a markdown report">⤓ Report (MD)</button>
      </div>

      <div className="qr-jr-field">
        <span className="qr-jr-label">NEXT STEPS / PIVOTS — if this fires, what to run next</span>
        <textarea className="qr-jr-ta" rows={2} value={hunt.pivots} placeholder="e.g. pull the parent process tree, then check the same user's auth events ±4h and any new outbound destinations…"
          onChange={(e) => onPivots(hunt.id, e.target.value)} />
      </div>
      <div className="qr-jr-field">
        <span className="qr-jr-label">TUNING LOG — thresholds you landed on &amp; why</span>
        <textarea className="qr-jr-ta" rows={2} value={hunt.tuning} placeholder="e.g. raised file-op threshold 500→1200 (backup agent baseline ~900/5m); excluded svc-backup, host BKP01…"
          onChange={(e) => onTuning(hunt.id, e.target.value)} />
      </div>

      <div className="qr-jr-field">
        <span className="qr-jr-label">FINDINGS — log each run (a clean result is still coverage)</span>
        <div className="qr-jr-add">
          <select value={dispo} onChange={(e) => setDispo(e.target.value)}>
            {DISPOSITIONS.map((d) => <option key={d} value={d}>{DISPO_META[d].label}</option>)}
          </select>
          <input value={note} maxLength={600} onChange={(e) => setNote(e.target.value.slice(0, 600))} placeholder="What you found (or didn't) — scope, hosts, follow-ups…" onKeyDown={(e) => { if (e.key === "Enter") submit(); }} />
          <button className="qr-jr-log" onClick={submit}>＋ Log {todayISO()}</button>
        </div>
        {hunt.findings.length > 0 && (
          <div className="qr-jr-list">
            {hunt.findings.map((f, i) => (
              <div key={i} className="qr-jr-entry">
                <span className="qr-jr-dot" style={{ background: DISPO_META[f.disposition] ? DISPO_META[f.disposition].color : "#74808c" }} />
                <span className="qr-jr-entry-body">
                  <span className="qr-jr-entry-head">{f.date} · <span style={{ color: DISPO_META[f.disposition] ? DISPO_META[f.disposition].color : "#74808c" }}>{DISPO_META[f.disposition] ? DISPO_META[f.disposition].label : f.disposition}</span></span>
                  {f.note && <span className="qr-jr-entry-note">{f.note}</span>}
                </span>
                <button className="qr-jr-rm" onClick={() => onRemoveFinding(hunt.id, i)} title="Remove" aria-label={"Remove the finding logged on " + f.date}><span aria-hidden="true">✕</span></button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="qr-jr-field">
        <span className="qr-jr-label">IOC ENRICHMENT — paste an indicator to triage</span>
        <input className="qr-jr-ioc" value={ioc} maxLength={2048} onChange={(e) => setIoc(e.target.value.slice(0, 2048))} placeholder="IP, domain, URL, or file hash…" />
        {links.length > 0 && (
          <div className="qr-jr-links">
            {links.map((l) => (<a key={l.label} className="qr-jr-link" href={l.url} target="_blank" rel="noreferrer noopener">{l.label} ↗</a>))}
          </div>
        )}
      </div>
    </div>
  );
}

function EnterpriseBuilder({ onSave, onClose }) {
  const [name, setName] = useState("");
  const [sector, setSector] = useState("");
  const [blurb, setBlurb] = useState("");
  const [stack, setStack] = useState("");
  const [posture, setPosture] = useState("");
  const [techniques, setTechniques] = useState("");
  const [inherits, setInherits] = useState(new Set(ALL_INDUSTRIES));
  const [actors, setActors] = useState([]);
  const [aName, setAName] = useState(""); const [aOrigin, setAOrigin] = useState(""); const [aMotive, setAMotive] = useState("");
  const [aSev, setASev] = useState("High"); const [aDetail, setADetail] = useState("");

  const toggleInh = (id) => setInherits((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const addActor = () => {
    if (!aName.trim()) return;
    setActors((p) => [...p, { name: aName.trim(), origin: aOrigin.trim() || "—", motive: aMotive.trim() || "—", sev: aSev, detail: aDetail.trim() }]);
    setAName(""); setAOrigin(""); setAMotive(""); setASev("High"); setADetail("");
  };
  const save = () => {
    if (!name.trim() || !sector.trim()) return;
    onSave({
      name, sector, blurb, stack,
      posture: posture.split("\n").map((s) => s.trim()).filter(Boolean),
      techniques: techniques.split("\n").map((s) => s.trim()).filter(Boolean),
      actors,
      inherits: [...inherits],
    });
  };
  const canSave = name.trim() && sector.trim();

  return (
    <div className="qr-modal-overlay" onClick={onClose}>
      <div className="qr-modal" role="dialog" aria-modal="true" aria-labelledby="qr-modal-title" onClick={(e) => e.stopPropagation()}>
        <div className="qr-modal-head">
          <h3 id="qr-modal-title">＋ New Enterprise Profile</h3>
          <button className="qr-modal-x" onClick={onClose} aria-label="Close this dialog"><span aria-hidden="true">✕</span></button>
        </div>
        <div className="qr-modal-body">
          <div className="qr-fg-2">
            <label className="qr-fld"><span>Name *</span><input value={name} maxLength={120} onChange={(e) => setName(e.target.value.slice(0, 120))} placeholder="Acme Manufacturing" /></label>
            <label className="qr-fld"><span>Sector *</span><input value={sector} maxLength={120} onChange={(e) => setSector(e.target.value.slice(0, 120))} placeholder="Manufacturing / OT" /></label>
          </div>
          <label className="qr-fld"><span>Description</span><textarea rows={2} maxLength={1000} value={blurb} onChange={(e) => setBlurb(e.target.value.slice(0, 1000))} placeholder="What this org is, what's valuable, exposure surface…" /></label>
          <label className="qr-fld"><span>Internet-facing stack (drives the KEV scan)</span><input value={stack} maxLength={600} onChange={(e) => setStack(e.target.value.slice(0, 600))} placeholder="Fortinet FortiOS, Citrix NetScaler, Exchange, SAP, Rockwell…" /></label>
          <div className="qr-fg-2">
            <label className="qr-fld"><span>Posture &amp; exposure (one per line)</span><textarea rows={4} maxLength={12000} value={posture} onChange={(e) => setPosture(e.target.value.slice(0, 12000))} placeholder={"Ransomware is the top disruption risk\nFlat OT/IT network increases blast radius"} /></label>
            <label className="qr-fld"><span>Likely ATT&amp;CK techniques (one per line)</span><textarea rows={4} maxLength={7200} value={techniques} onChange={(e) => setTechniques(e.target.value.slice(0, 7200))} placeholder={"T1190 Exploit Public-Facing App\nT1486 Data Encrypted for Impact"} /></label>
          </div>

          <div className="qr-fld">
            <span>Draw hunts from these sectors</span>
            <div className="qr-inh">
              {ENTERPRISES.map((e) => (
                <button key={e.id} type="button" className={"qr-inh-chip " + (inherits.has(e.id) ? "on" : "")} onClick={() => toggleInh(e.id)}>
                  {inherits.has(e.id) ? "✓ " : ""}{e.sector}
                </button>
              ))}
            </div>
            <p className="qr-fld-hint">Built-in hunts are tagged to these sectors — pick which ones this enterprise's library pulls from. Your own custom hunts always appear. Default: all.</p>
          </div>

          <div className="qr-fld">
            <span>Adversaries ({actors.length})</span>
            {actors.length > 0 && (
              <div className="qr-actor-mini-list">
                {actors.map((a, i) => (
                  <div key={i} className="qr-actor-mini">
                    <span className="qr-sev-dot" style={{ background: SEV_COLOR[a.sev] }} />
                    <span className="qr-actor-mini-name">{a.name}</span>
                    <span className="qr-actor-mini-meta">{a.origin} · {a.motive} · {a.sev}</span>
                    <button className="qr-actor-rm" onClick={() => setActors((p) => p.filter((_, j) => j !== i))}>✕</button>
                  </div>
                ))}
              </div>
            )}
            <div className="qr-actor-add">
              <div className="qr-fg-4">
                <input value={aName} maxLength={120} onChange={(e) => setAName(e.target.value.slice(0, 120))} placeholder="Actor / group" />
                <input value={aOrigin} maxLength={80} onChange={(e) => setAOrigin(e.target.value.slice(0, 80))} placeholder="Origin (e.g. eCrime)" />
                <input value={aMotive} maxLength={80} onChange={(e) => setAMotive(e.target.value.slice(0, 80))} placeholder="Motive" />
                <select value={aSev} onChange={(e) => setASev(e.target.value)}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select>
              </div>
              <textarea rows={2} maxLength={600} value={aDetail} onChange={(e) => setADetail(e.target.value.slice(0, 600))} placeholder="How they operate against this enterprise…" />
              <button className="qr-ghost" onClick={addActor} disabled={!aName.trim()}>＋ Add adversary</button>
            </div>
          </div>
        </div>
        <div className="qr-modal-foot">
          <button className="qr-ghost" onClick={onClose}>Cancel</button>
          <button className="qr-cta" onClick={save} disabled={!canSave}>Create enterprise</button>
        </div>
      </div>
    </div>
  );
}

/* ============================================================
   MAIN COMPONENT
   ============================================================ */
export default function OtterShell() {
  const [hunts, setHunts] = useState(() => HUNTS.map(withLifecycle));
  const [entId, setEntId] = useState("utility");
  const [tab, setTab] = useState("landscape");
  const [platform, setPlatform] = useState("crowdstrike");
  const [sevFilter, setSevFilter] = useState("All");
  const [srcFilter, setSrcFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [openHunt, setOpenHunt] = useState(HUNTS[0].id);
  const [copied, setCopied] = useState(null);

  const [genText, setGenText] = useState("");
  const [genUrl, setGenUrl] = useState("");
  const [genMode, setGenMode] = useState("tech");
  const [genBusy, setGenBusy] = useState(false);
  const [genErr, setGenErr] = useState("");
  const [genSummary, setGenSummary] = useState("");
  const [sigmaText, setSigmaText] = useState(SIGMA_SAMPLE);
  const [jsonText, setJsonText] = useState("");
  const [pending, setPending] = useState(null);
  const [notice, setNotice] = useState("");
  const [exportText, setExportText] = useState("");
  const [navText, setNavText] = useState("");
  const [have, setHave] = useState(() => new Set(TELEMETRY));
  const [kevScan, setKevScan] = useState({}); // entId -> { busy, err, items:[{cve,product,desc,covered}] }
  const wsFileRef = useRef(null);
  const [customEnts, setCustomEnts] = useState([]);
  const [builderOpen, setBuilderOpen] = useState(false);

  const allEnts = useMemo(() => [...ENTERPRISES, ...customEnts], [customEnts]);
  const ent = allEnts.find((e) => e.id === entId) || ENTERPRISES[0];
  const inheritsOf = (e) => (Array.isArray(e.inherits) && e.inherits.length ? e.inherits : [e.id]);
  const libForEnt = useMemo(() => {
    const inh = inheritsOf(ent);
    return hunts.filter((h) => h.industries.some((i) => inh.includes(i)));
  }, [hunts, ent]);
  const filteredHunts = useMemo(() => libForEnt
    .filter((h) => sevFilter === "All" || h.sev === sevFilter)
    .filter((h) => srcFilter === "All" || h.source === srcFilter)
    .filter((h) => statusFilter === "All" || h.status === statusFilter)
    .sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev)), [libForEnt, sevFilter, srcFilter, statusFilter]);
  const activeHunt = filteredHunts.find((h) => h.id === openHunt) || filteredHunts[0];

  const copy = async (text, id) => {
    try { await navigator.clipboard.writeText(text); }
    catch {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch {}
      document.body.removeChild(ta);
    }
    if (id) { setCopied(id); setTimeout(() => setCopied(null), 1400); }
  };
  const flash = (m) => { setNotice(m); setTimeout(() => setNotice(""), 2600); };
  const addHunt = (h) => { setHunts((prev) => { const taken = new Set(prev.map((x) => x.id)); let id = h.id; while (!id || taken.has(id)) id = genId("gen"); return [withLifecycle({ ...h, id, custom: true }), ...prev]; }); setPending(null); setGenSummary(""); flash('Added "' + h.name + '" to the library.'); };

  // lifecycle mutations
  const updateHunt = (id, patch) => setHunts((prev) => prev.map((h) => (h.id === id ? { ...h, ...patch } : h)));
  const setStatus = (id, status) => updateHunt(id, { status });
  const markReviewed = (id) => updateHunt(id, { reviewed: todayISO() });
  const bumpVersion = (h, delta) => updateHunt(h.id, { version: Math.max(1, (h.version || 1) + delta) });

  // hunt journal mutations
  const addFinding = (id, disposition, note) => setHunts((prev) => prev.map((h) => h.id === id ? { ...h, findings: [{ date: todayISO(), disposition, note: String(note || "").slice(0, 1000) }, ...(h.findings || [])].slice(0, 50) } : h));
  const removeFinding = (id, idx) => setHunts((prev) => prev.map((h) => h.id === id ? { ...h, findings: (h.findings || []).filter((_, i) => i !== idx) } : h));
  const setPivots = (id, text) => updateHunt(id, { pivots: text.slice(0, 1500) });
  const setTuning = (id, text) => updateHunt(id, { tuning: text.slice(0, 1500) });
  const setValidation = (id, validation, platformLabel) => updateHunt(id, { validation, validatedOn: validation === "unverified" ? "" : (platformLabel || ""), validatedDate: validation === "unverified" ? "" : todayISO() });

  // --- custom enterprise create / delete ---
  const addEnterprise = (e) => {
    const id = genId("ent");
    const inherits = (Array.isArray(e.inherits) && e.inherits.length ? e.inherits : ALL_INDUSTRIES).filter((x) => ALL_INDUSTRIES.includes(x));
    const built = {
      id, custom: true,
      name: String(e.name || "Custom Enterprise").slice(0, 80),
      sector: String(e.sector || "Custom").slice(0, 60),
      blurb: String(e.blurb || "").slice(0, 1200),
      stack: String(e.stack || e.sector || "").slice(0, 600),
      posture: (e.posture || []).map((s) => String(s).slice(0, 300)).filter(Boolean).slice(0, 12),
      techniques: (e.techniques || []).map((s) => String(s).slice(0, 80)).filter(Boolean).slice(0, 20),
      actors: (e.actors || []).slice(0, 12).map((a) => ({
        name: String(a.name || "Unnamed actor").slice(0, 120),
        origin: String(a.origin || "—").slice(0, 60),
        motive: String(a.motive || "—").slice(0, 60),
        sev: SEVERITIES.includes(a.sev) ? a.sev : "Medium",
        detail: String(a.detail || "").slice(0, 600),
      })),
      inherits: inherits.length ? inherits : ALL_INDUSTRIES,
    };
    setCustomEnts((prev) => [...prev, built]);
    setEntId(id); setBuilderOpen(false); setOpenHunt("");
    flash('Created enterprise "' + built.name + '".');
  };
  const deleteEnterprise = (id) => {
    setCustomEnts((prev) => prev.filter((e) => e.id !== id));
    if (entId === id) { setEntId("utility"); setOpenHunt(""); }
    flash("Enterprise removed.");
  };

  const normalizeHunt = (obj) => ({
    ...obj, id: genId("gen"), custom: true, industries: ALL_INDUSTRIES,
    queries: (obj.queries && typeof obj.queries === "object") ? obj.queries : {},
    name: String(obj.name || "Generated hunt").slice(0, 160),
    technique: String(obj.technique || "—").slice(0, 80),
    tactic: String(obj.tactic || "—").slice(0, 80),
    hypothesis: String(obj.hypothesis || "Generated hunt.").slice(0, 600),
    fp: String(obj.fp || "Tune to environment.").slice(0, 600),
    sev: SEVERITIES.includes(obj.sev) ? obj.sev : "Medium",
    source: DATA_SOURCES.includes(obj.source) ? obj.source : "Endpoint / EDR",
    note: (obj.note ? String(obj.note).slice(0, 300) : "") || (genMode === "report" ? ("Report-derived — verify field/dataset names and tune thresholds." + (genUrl ? " Source: " + genUrl.slice(0, 200) : "")) : genMode !== "tech" ? "Intel-derived — validate field/dataset names and tune thresholds." : "AI-generated — validate field/dataset names and tune thresholds before use."),
    status: "new", version: 1, author: genMode === "tech" ? "AI-generated" : genMode === "report" ? "Report-derived" : "Intel-derived", created: todayISO(), reviewed: "",
  });

  const generate = async () => {
    if (!genText.trim()) return;
    if (!AI_ENABLED) { setGenErr(AI_DISABLED_MSG); setPending(null); setGenSummary(""); return; }
    setGenBusy(true); setGenErr(""); setPending(null); setGenSummary("");
    const platSpec = "queries (object with keys crowdstrike, xsiam, sentinel, defender, elastic, secops, splunk — each a concise working hunt query, <=7 lines, for CrowdStrike Falcon LogScale, Cortex XSIAM XQL, Microsoft Sentinel KQL, Microsoft Defender XDR advanced-hunting KQL, Elastic ES|QL, Google SecOps YARA-L 2.0 rule over UDM, and Splunk SPL respectively)";
    const huntShape = "a hunt object with keys: name, technique (e.g. 'T1059.001 — PowerShell'), tactic, sev (Critical/High/Medium/Low), source (one of: 'Endpoint / EDR','Identity / IdP','Cloud / SaaS','DNS','Web Proxy','Windows Event Logs'), hypothesis (<=2 sentences), fp (<=2 sentences), note (telemetry requirement or empty string), " + platSpec;
    const sys = genMode === "intel"
      ? "You are a senior threat-hunt engineer. Use AT MOST 2 web searches to gather CURRENT tactics, techniques and procedures for the threat actor, malware, or CVE described. Do not narrate between searches; do not preface or follow the JSON with any text. After searching, your entire final response must be ONE JSON object only (no markdown fences, no commentary), with keys: summary (<=3 sentence current-intel summary with the most relevant TTP) and hunt (" + huntShape + "). Begin the final response with `{` and end with `}`. Nothing else."
      : genMode === "kev"
      ? "You are a senior threat-hunt engineer. Use AT MOST 2 web searches to find RECENT additions to the CISA Known Exploited Vulnerabilities (KEV) catalog that affect the vendor/product stack described; pick the single most relevant actively-exploited CVE. Do not narrate between searches; do not preface or follow the JSON with any text. Your entire final response must be ONE JSON object only (no markdown fences, no commentary), with keys: summary (<=3 sentences naming the CVE, affected product, and how it is being exploited) and hunt (" + huntShape + " — detecting exploitation or post-exploitation of that CVE). Begin the final response with `{` and end with `}`. Nothing else."
      : genMode === "report"
      ? "You are a senior threat-hunt engineer. The user has pasted a threat-intel report or excerpt, and optionally a source URL. If the pasted text is sparse, use AT MOST 2 web searches to gather current details on the named CVE / vendor / product / actor. Do not narrate between searches; do not preface or follow the JSON with any text. EXTRACT: vendor/product affected, CVE(s), threat actor if named, ATT&CK technique(s), and observed in-the-wild behavior. Then DRAFT a defensive hunt focused on the MOST OBSERVABLE post-exploitation behavior — not the exploit itself. Prefer signals visible in normal SIEM/EDR telemetry (process trees, config changes, auth anomalies, network patterns) over signals that require the appliance vendor's internal logs. Your entire final response must be ONE JSON object only (no markdown fences, no commentary), with keys: summary (<=3 sentences naming the CVE/actor, affected product, and the chosen detection signal) and hunt (" + huntShape + "). Begin the final response with `{` and end with `}`. Nothing else."
      : "You are a senior threat-hunt engineer. Given a technique or behaviour, output ONE JSON object ONLY (no markdown, no prose) which is " + huntShape + ". Return only the JSON.";
    const userMsg = genMode === "report"
      ? (
          genUrl && genText.trim()
            ? "Source URL: " + genUrl + "\n\nReport excerpt:\n" + genText + "\n\nIf the excerpt is sparse, use web search to gather more current details on the named CVE / actor / vendor."
            : genUrl
            ? "Source URL: " + genUrl + "\n\n(No article body was pasted. Use web search to find this article and any current intel on the CVE / actor / vendor it covers.)"
            : "Report:\n" + genText
        )
      : genText;
    const wsMode = (genMode === "intel" || genMode === "kev" || genMode === "report");
    const tokenCap = wsMode ? 2500 : 1000;
    const body = { model: "claude-sonnet-4-20250514", max_tokens: tokenCap, messages: [{ role: "user", content: sys + "\n\nInput:\n" + userMsg }] };
    if (wsMode) body.tools = [{ type: "web_search_20250305", name: "web_search" }];
    try {
      const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
      const timer = ctrl ? setTimeout(() => ctrl.abort(), 90000) : null;
      let res;
      try { res = await fetch(CLAUDE_ENDPOINT, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: ctrl ? ctrl.signal : undefined }); }
      finally { if (timer) clearTimeout(timer); }
      const data = await res.json();
      if (!res.ok) {
        const apiMsg = (data && data.error && (data.error.message || data.error.type)) || ("HTTP " + res.status);
        throw new Error(apiMsg);
      }
      const blocks = Array.isArray(data.content) ? data.content : [];
      const textBlocks = blocks.filter((b) => b && b.type === "text").map((b) => b.text || "");
      if (!textBlocks.length) throw new Error("Model returned no text content (response had " + blocks.length + " blocks of other types).");
      // Robust JSON extraction: scan text blocks from last to first, strip code fences,
      // and find a properly-balanced {...} respecting string literals. This avoids
      // grabbing stray "{" inside intermediate narration when web_search is on.
      const findBalancedJSON = (raw) => {
        let t = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "").trim();
        const start = t.indexOf("{");
        if (start < 0) return null;
        let depth = 0, inStr = false, esc = false;
        for (let i = start; i < t.length; i++) {
          const c = t[i];
          if (esc) { esc = false; continue; }
          if (inStr && c === "\\") { esc = true; continue; }
          if (c === '"') { inStr = !inStr; continue; }
          if (inStr) continue;
          if (c === "{") depth++;
          else if (c === "}") { depth--; if (depth === 0) return t.slice(start, i + 1); }
        }
        return null;
      };
      let obj = null, parseErr = null;
      for (let i = textBlocks.length - 1; i >= 0 && !obj; i--) {
        const candidate = findBalancedJSON(textBlocks[i]);
        if (!candidate) continue;
        try { obj = JSON.parse(candidate); } catch (e) { parseErr = e; }
      }
      if (!obj) {
        if (data.stop_reason === "max_tokens") throw new Error("Model hit the " + tokenCap + "-token output cap before finishing the JSON. This usually means the source had a lot to cover — try pasting a shorter excerpt, narrowing to one specific aspect (e.g. \"detection signals for CVE-X\"), or rerun.");
        throw new Error("Could not parse JSON from model response" + (parseErr ? " (" + parseErr.message + ")" : "") + ". Try rerunning — web-search responses occasionally need a retry.");
      }
      if (obj.hunt) { setGenSummary(obj.summary || ""); setPending(normalizeHunt(obj.hunt)); }
      else setPending(normalizeHunt(obj));
    } catch (err) { setGenErr("Generation failed: " + (err && err.name === "AbortError" ? "the request timed out after 90 seconds — try a shorter input or run it again" : (err.message || "unknown error") + ". Try a more specific prompt or run it again.")); }
    finally { setGenBusy(false); }
  };

  const convertSigma = () => {
    setGenErr(""); setPending(null); setGenSummary("");
    try { setPending(sigmaToHunt(sigmaText)); }
    catch (err) { setGenErr("Sigma parse error: " + (err.message || "unrecognized format") + ". This converter handles standard process_creation / dns / network rules best."); }
  };

  const importJson = () => {
    setGenErr(""); setPending(null); setGenSummary("");
    try {
      if (jsonText.length > 3000000) throw new Error("Input is too large (over 3 MB). Split it into smaller files.");
      const parsed = JSON.parse(jsonText);
      const arr = Array.isArray(parsed) ? parsed : (parsed.hunts || [parsed]);
      if (arr.length > 200) throw new Error("Refusing to import more than 200 hunts at once.");
      const cleaned = arr.map((h) => sanitizeHunt(h, "imp")).filter(Boolean);
      if (!cleaned.length) throw new Error("No valid hunts found (each needs a name and a queries object).");
      setHunts((prev) => {
        // Reassign IDs that collide with anything already loaded (built-in or custom) or with each other,
        // so React keys stay unique and imports never clobber existing hunts.
        const taken = new Set(prev.map((h) => h.id));
        const merged = cleaned.map((h) => {
          let id = h.id;
          if (taken.has(id)) id = genId("imp");
          while (taken.has(id)) id = genId("imp");
          taken.add(id);
          return id === h.id ? h : { ...h, id };
        });
        return [...merged, ...prev];
      });
      flash("Imported " + cleaned.length + " hunt" + (cleaned.length !== 1 ? "s" : "") + " from JSON.");
    } catch (err) { setGenErr("JSON import error: " + (err.message || "invalid JSON")); }
  };

  const exportLibrary = () => { const json = JSON.stringify(hunts, null, 2); setExportText(json); copy(json); flash("Library JSON copied to clipboard (also shown below)."); };
  const exportNav = () => { const json = JSON.stringify(buildNavLayer(libForEnt, ent), null, 2); setNavText(json); copy(json); flash("ATT&CK Navigator layer copied — import it at mitre-attack.github.io/attack-navigator."); };
  const toggleTele = (t) => setHave((prev) => { const n = new Set(prev); n.has(t) ? n.delete(t) : n.add(t); return n; });

  // trigger a real file download; fall back to clipboard if the sandbox blocks blob URLs
  const downloadText = (filename, text, mime) => {
    try {
      const blob = new Blob([text], { type: mime || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      return true;
    } catch (e) { copy(text); return false; }
  };

  // --- Save / load workspace (custom hunts + built-in lifecycle + telemetry) ---
  const currentWorkspace = () => ({
    schema: "otter-shell-workspace", version: 1, savedAt: new Date().toISOString(),
    customHunts: hunts.filter((h) => h.custom),
    builtinMeta: hunts.filter((h) => !h.custom).map((h) => ({ id: h.id, status: h.status, version: h.version, author: h.author, created: h.created, reviewed: h.reviewed, findings: h.findings, pivots: h.pivots, tuning: h.tuning, validation: h.validation, validatedOn: h.validatedOn, validatedDate: h.validatedDate })),
    customEnterprises: customEnts,
    telemetry: [...have],
  });

  const downloadWorkspace = () => {
    const ws = currentWorkspace();
    const ok = downloadText("otter-shell-workspace-" + new Date().toISOString().slice(0, 10) + ".json", JSON.stringify(ws, null, 2), "application/json");
    flash(ok ? "Workspace downloaded — re-load it any time with Load workspace." : "Download blocked by sandbox — workspace JSON copied to clipboard instead.");
  };
  /**
   * Merge a workspace-shaped object into state. Shared by the file loader, the demo
   * program and the localStorage restore, so all three go through exactly the same
   * allowlist sanitizers — a new entry point can never become a new soft spot.
   * Returns a short summary for the caller to surface.
   */
  const applyWorkspace = (ws) => {
    {
      {
        if (!ws || ws.schema !== "otter-shell-workspace") throw new Error("not an Otter Shell workspace file");
        // Every branch below goes through the same allowlist sanitizers as JSON import.
        // A workspace file is user-supplied and hand-editable — it is not trusted input
        // just because this app wrote the last one.
        const custom = (Array.isArray(ws.customHunts) ? ws.customHunts : [])
          .slice(0, 500).map((h) => sanitizeHunt(h, "ws")).filter(Boolean);
        const builtinIds = new Set(HUNTS.map((h) => h.id));
        const base = HUNTS.map(withLifecycle);
        // apply saved lifecycle to built-in hunts
        if (Array.isArray(ws.builtinMeta)) {
          const m = new Map(ws.builtinMeta.slice(0, 500).map(sanitizeBuiltinMeta).filter(Boolean).map((x) => [x.id, x]));
          base.forEach((h) => {
            const o = m.get(h.id);
            if (!o) return;
            // null from the sanitizer means "absent or invalid" — keep the built-in default.
            for (const k of ["status", "version", "author", "created", "reviewed", "findings", "pivots", "tuning", "validation", "validatedOn", "validatedDate"]) {
              if (o[k] !== null) h[k] = o[k];
            }
          });
        }
        // Custom hunts must not shadow a built-in id, and must not collide with each other.
        const taken = new Set(builtinIds);
        const uniqueCustom = [];
        for (const h of custom) {
          if (builtinIds.has(h.id)) continue;
          let id = h.id;
          while (taken.has(id)) id = genId("ws");
          taken.add(id);
          uniqueCustom.push(id === h.id ? h : { ...h, id });
        }
        setHunts([...uniqueCustom, ...base]);
        if (Array.isArray(ws.telemetry)) setHave(new Set(ws.telemetry.filter((t) => TELEMETRY.includes(t))));
        const ents = (Array.isArray(ws.customEnterprises) ? ws.customEnterprises : [])
          .slice(0, 100).map(sanitizeEnterprise).filter(Boolean);
        setCustomEnts(ents);
        setGenErr("");
        return { hunts: uniqueCustom.length, enterprises: ents.length };
      }
    }
  };

  const loadWorkspaceFile = (file) => {
    if (!file) return;
    if (file.size > 10000000) { setGenErr("Workspace file is too large (over 10 MB) — it may be corrupt."); return; }
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const raw = String(reader.result);
        if (raw.length > 10000000) throw new Error("file too large");
        const n = applyWorkspace(JSON.parse(raw));
        flash("Workspace loaded — " + n.hunts + " hunt" + (n.hunts !== 1 ? "s" : "") + ", " + n.enterprises + " enterprise" + (n.enterprises !== 1 ? "s" : "") + " restored.");
      } catch (err) { setGenErr("Workspace load error: " + (err.message || "invalid file") + "."); }
    };
    reader.onerror = () => setGenErr("Could not read the file.");
    reader.readAsText(file);
  };

  /* Seed a worked example so the Coverage view shows a real programme rather than
     zeros. Built as a workspace object and pushed through applyWorkspace, so the
     demo exercises the same code path a real file does. */
  const loadDemo = () => {
    try {
      const n = applyWorkspace(buildDemoWorkspace());
      setTab("coverage");
      flash("Demo programme loaded — " + n.hunts + " custom hunts plus logged findings across the built-in library. Reset with Clear demo.");
    } catch (err) { setGenErr("Could not load the demo: " + (err.message || "unknown error")); }
  };

  const clearDemo = () => {
    setHunts(HUNTS.map(withLifecycle));
    setCustomEnts([]);
    setHave(new Set(TELEMETRY));
    flash("Demo cleared — back to the stock library.");
  };

  /* Restore the autosaved workspace once, on mount. Guarded by a ref so the autosave
     effect below cannot fire before the restore has happened and overwrite it with
     the empty initial state. A corrupt or outdated entry is dropped, not surfaced as
     an error — there is nothing the user can do about it and the app still works. */
  const restoredRef = useRef(false);
  useEffect(() => {
    const raw = lsGet();
    if (raw) {
      try { applyWorkspace(JSON.parse(raw)); }
      catch { lsClear(); }
    }
    restoredRef.current = true;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* Autosave. Debounced so a burst of edits (typing in the tuning log) writes once.
     If storage is unavailable or full, `saved` goes false and the UI says so rather
     than silently pretending the work is safe. */
  const [saved, setSaved] = useState(null);
  useEffect(() => {
    if (!restoredRef.current) return;
    const t = setTimeout(() => setSaved(lsSet(JSON.stringify(currentWorkspace()))), 400);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hunts, customEnts, have]);

  const forgetSaved = () => {
    lsClear();
    setHunts(HUNTS.map(withLifecycle));
    setCustomEnts([]);
    setHave(new Set(TELEMETRY));
    setSaved(null);
    flash("Saved workspace cleared from this browser.");
  };

  // --- Sigma export ---
  const exportHuntSigma = (hunt) => { const y = huntToSigma(hunt); copy(y); flash("Sigma rule for \"" + hunt.name + "\" copied to clipboard."); };
  const exportAllSigma = () => {
    const all = hunts.map(huntToSigma).join("\n---\n");
    const ok = downloadText("otter-shell-hunts-" + new Date().toISOString().slice(0, 10) + ".sigma.yml", all, "text/yaml");
    flash(ok ? "Exported " + hunts.length + " hunts as a multi-document Sigma file." : "Download blocked — Sigma YAML copied to clipboard instead.");
  };

  // --- markdown report export ---
  const slugify = (s) => String(s || "hunt").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) || "hunt";
  const exportHuntReport = (hunt) => {
    const md = huntToMarkdown(hunt);
    const ok = downloadText("otter-shell-" + slugify(hunt.name) + ".md", md, "text/markdown");
    flash(ok ? 'Hunt report for "' + hunt.name + '" downloaded.' : "Download blocked — report markdown copied to clipboard instead.");
  };
  const exportProgramReport = () => {
    const md = programToMarkdown(libForEnt, ent.name);
    const ok = downloadText("otter-shell-program-" + slugify(ent.name) + "-" + new Date().toISOString().slice(0, 10) + ".md", md, "text/markdown");
    flash(ok ? "Program report for " + ent.name + " downloaded (" + libForEnt.length + " hunts)." : "Download blocked — program markdown copied to clipboard instead.");
  };

  // --- cross-hunt journal activity (recent findings + counts) ---
  const recentActivity = useMemo(() => {
    const all = [];
    for (const h of libForEnt) for (const f of (h.findings || [])) all.push({ ...f, huntId: h.id, huntName: h.name });
    all.sort((a, b) => (b.date || "").localeCompare(a.date || ""));
    const dispoCounts = DISPOSITIONS.reduce((a, d) => { a[d] = all.filter((f) => f.disposition === d).length; return a; }, {});
    return { items: all, total: all.length, byDispo: dispoCounts };
  }, [libForEnt]);

  // Coverage -> KEV loop: scan the authoritative CISA KEV catalog against this enterprise's stack.
  // Primary path fetches the real feed and filters client-side (exact + current).
  // Falls back to model recall only if the browser cannot reach the feed.
  const scanKev = async () => {
    const id = entId;
    const stack = ent.stack || ent.sector;
    setKevScan((p) => ({ ...p, [id]: { busy: true, err: "", items: [], source: "", version: "" } }));
    try {
      const cat = await loadKevCatalog();
      const items = matchKev(cat.vulns, stackKeywords(stack), 12);
      setKevScan((p) => ({ ...p, [id]: { busy: false, err: "", items, source: "feed", version: cat.version } }));
      flash(items.length
        ? "Matched " + items.length + " KEV CVE" + (items.length !== 1 ? "s" : "") + " from the live CISA catalog."
        : "No catalog matches for this stack — try editing the enterprise stack keywords.");
      return;
    } catch (feedErr) {
      // fallback: model recall (best-effort) when the feed is unreachable.
      // Requires the AI backend; without one, report the feed failure plainly.
      if (!AI_ENABLED) {
        setKevScan((p) => ({ ...p, [id]: { busy: false, err: "Could not reach the CISA KEV feed (" + (feedErr.message || "network blocked") + "). The live feed needs browser access to raw.githubusercontent.com. The model fallback is unavailable because no AI backend is configured — see the README.", items: [], source: "", version: "" } }));
        return;
      }
      try {
        const sys = "You are a threat-intel analyst. Use web search to find the most RECENT entries in the CISA Known Exploited Vulnerabilities (KEV) catalog that affect any product in the stack below. Return ONLY a JSON array (no markdown, no prose) of up to 8 objects, newest first, each with keys: cve, product, desc (<=18 words), dateAdded (YYYY-MM-DD if known else empty). Return only the JSON array.";
        const res = await fetch(CLAUDE_ENDPOINT, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "claude-sonnet-4-20250514", max_tokens: 1000,
            messages: [{ role: "user", content: sys + "\n\nStack:\n" + stack }],
            tools: [{ type: "web_search_20250305", name: "web_search" }],
          }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error((data && data.error && (data.error.message || data.error.type)) || ("HTTP " + res.status));
        const blocks = Array.isArray(data.content) ? data.content : [];
        const textBlocks = blocks.filter((b) => b && b.type === "text").map((b) => b.text || "");
        // Balanced-bracket array extraction (respects string literals) so web-search
        // narration containing "[1]"-style citations doesn't break the parse.
        const findArray = (raw) => {
          const t = raw.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "");
          const start = t.indexOf("[");
          if (start < 0) return null;
          let depth = 0, inStr = false, esc = false;
          for (let i = start; i < t.length; i++) {
            const c = t[i];
            if (esc) { esc = false; continue; }
            if (inStr && c === "\\") { esc = true; continue; }
            if (c === '"') { inStr = !inStr; continue; }
            if (inStr) continue;
            if (c === "[") depth++;
            else if (c === "]") { depth--; if (depth === 0) return t.slice(start, i + 1); }
          }
          return null;
        };
        let arr = null;
        for (let i = textBlocks.length - 1; i >= 0 && !arr; i--) {
          const cand = findArray(textBlocks[i]);
          if (!cand) continue;
          try { const parsed = JSON.parse(cand); if (Array.isArray(parsed)) arr = parsed; } catch { /* try next block */ }
        }
        if (!arr) throw new Error("no parseable JSON array in model response");
        const items = arr.filter((x) => x && x.cve).slice(0, 8)
          .map((x) => ({ cve: String(x.cve).slice(0, 40), product: String(x.product || x.cve).slice(0, 160), desc: String(x.desc || "").slice(0, 200), dateAdded: String(x.dateAdded || "").slice(0, 20), ransomware: false }));
        setKevScan((p) => ({ ...p, [id]: { busy: false, err: "", items, source: "model", version: "" } }));
        flash(items.length ? "Live feed unreachable — used best-effort model recall (" + items.length + ")." : "No matches found.");
      } catch (modelErr) {
        setKevScan((p) => ({ ...p, [id]: { busy: false, err: "Could not reach the CISA feed (" + (feedErr.message || "network blocked") + ") and the model fallback also failed. The live feed needs browser access to raw.githubusercontent.com.", items: [], source: "", version: "" } }));
      }
    }
  };

  // jump to Forge in KEV mode, prefilled to draft a hunt for a specific CVE
  const draftForCve = (item) => {
    setGenMode("kev");
    setGenText(item.cve + " — " + (item.product || "") + (item.desc ? " (" + item.desc + ")" : ""));
    setTab("forge");
  };

  const coveredTechIds = useMemo(() => new Set(libForEnt.map(techIdOf).filter(Boolean)), [libForEnt]);
  const entGaps = useMemo(() => ent.techniques.filter((t) => { const m = t.match(/T\d{4}(?:\.\d{3})?/); return m && !coveredTechIds.has(m[0]); }), [ent, coveredTechIds]);
  const runnable = libForEnt.filter((h) => reqOf(h).every((r) => have.has(r)));
  const blind = libForEnt.filter((h) => !reqOf(h).every((r) => have.has(r)));
  const statusCounts = useMemo(() => STATUSES.reduce((a, s) => { a[s] = libForEnt.filter((h) => h.status === s).length; return a; }, {}), [libForEnt]);

  const kev = kevScan[entId] || { busy: false, err: "", items: [], source: "", version: "" };
  const kevItems = useMemo(() => {
    const hay = libForEnt.map((h) => ((h.name || "") + " " + (h.hypothesis || "") + " " + (h.technique || "")).toLowerCase());
    return kev.items.map((it) => ({ ...it, covered: hay.some((s) => s.includes(String(it.cve).toLowerCase())) }));
  }, [kev.items, libForEnt]);

  return (
    <div className="qr-root">
      <style>{CSS}</style>
      {builderOpen && <EnterpriseBuilder onSave={addEnterprise} onClose={() => setBuilderOpen(false)} />}

      <header className="qr-header">
        <div className="qr-brand">
          <span className="qr-logo" aria-hidden="true">🦦</span>
          <div><h1>OTTER SHELL</h1><p>Threat Hunt Console</p></div>
        </div>
        <div className="qr-ent-pick">
          <label htmlFor="qr-ent-select">ENTERPRISE</label>
          <div className="qr-ent-row">
            <select id="qr-ent-select" value={entId} onChange={(e) => { setEntId(e.target.value); setOpenHunt(""); }}>
              <optgroup label="Built-in">
                {ENTERPRISES.map((e) => (<option key={e.id} value={e.id}>{e.name} — {e.sector}</option>))}
              </optgroup>
              {customEnts.length > 0 && (
                <optgroup label="Custom">
                  {customEnts.map((e) => (<option key={e.id} value={e.id}>{e.name} — {e.sector}</option>))}
                </optgroup>
              )}
            </select>
            {ent.custom && <button className="qr-ent-del" title="Delete this custom enterprise" aria-label={"Delete the custom enterprise " + ent.name} onClick={() => deleteEnterprise(ent.id)}><span aria-hidden="true">🗑</span></button>}
            <button className="qr-ent-new" onClick={() => setBuilderOpen(true)}>＋ New</button>
          </div>
        </div>
      </header>

      <nav className="qr-tabs" role="tablist" aria-label="Console sections">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            id={"qr-tab-" + t.id}
            aria-selected={tab === t.id}
            aria-controls={"qr-panel-" + t.id}
            tabIndex={tab === t.id ? 0 : -1}
            className={tab === t.id ? "on" : ""}
            onClick={() => setTab(t.id)}
            onKeyDown={(e) => {
              // Left/Right move between tabs, as expected of a tablist.
              const i = TABS.findIndex((x) => x.id === tab);
              if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
                e.preventDefault();
                const next = TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length];
                setTab(next.id);
                const el = document.getElementById("qr-tab-" + next.id);
                if (el) el.focus();
              }
            }}
          >
            <span aria-hidden="true">{t.icon}</span> {t.label}
          </button>
        ))}
      </nav>

      <div className="qr-live" role="status" aria-live="polite">{notice}</div>
      {notice && <div className="qr-toast">{notice}</div>}

      {tab === "landscape" && (
        <main className="qr-landscape" role="tabpanel" id="qr-panel-landscape" aria-labelledby="qr-tab-landscape" tabIndex={-1}>
          <section className="qr-profile">
            <div className="qr-prof-head">
              <div>
                <span className="qr-tag">{ent.sector}</span>
                {ent.flag && <span className="qr-flag">FLAGSHIP PROFILE</span>}
                <h2>{ent.name}</h2>
              </div>
            </div>
            <p className="qr-blurb">{ent.blurb}</p>
            <div className="qr-posture">
              <h3>Posture &amp; Exposure</h3>
              <ul>{ent.posture.map((p, i) => (<li key={i}>{p}</li>))}</ul>
            </div>
            <div className="qr-tech-strip">
              <h3>Most-Likely ATT&amp;CK Techniques</h3>
              <div className="qr-chips">{ent.techniques.map((t) => (<span key={t} className="qr-chip">{t}</span>))}</div>
            </div>
            <button className="qr-cta" onClick={() => setTab("hunts")}>→ Build hunts for {shortName(ent)}</button>
          </section>
          <section className="qr-actors">
            <h3 className="qr-actors-title">Adversaries Likely Targeting This Enterprise</h3>
            <div className="qr-actor-grid">
              {ent.actors.map((a, i) => (
                <article key={i} className="qr-actor-card">
                  <div className="qr-actor-top">
                    <span className="qr-sev-dot" style={{ background: SEV_COLOR[a.sev] }} />
                    <h4>{a.name}</h4>
                  </div>
                  <div className="qr-actor-meta">
                    <span><b>Origin</b> {a.origin}</span>
                    <span><b>Motive</b> {a.motive}</span>
                    <span style={{ color: SEV_COLOR[a.sev] }}><b>Threat</b> {a.sev}</span>
                  </div>
                  <p>{a.detail}</p>
                </article>
              ))}
            </div>
          </section>
        </main>
      )}

      {tab === "hunts" && (
        <main className="qr-hunts" role="tabpanel" id="qr-panel-hunts" aria-labelledby="qr-tab-hunts" tabIndex={-1}>
          <aside className="qr-rail">
            <div className="qr-rail-block">
              <label>PLATFORM</label>
              <div className="qr-plat-list" role="radiogroup" aria-label="Query platform">
                {PLATFORMS.map((p) => (
                  <button key={p.id} role="radio" aria-checked={platform === p.id} aria-label={p.label + " — " + p.sub} className={"qr-plat " + (platform === p.id ? "on" : "")} onClick={() => setPlatform(p.id)}>
                    <span className="qr-plat-name">{p.label}</span>
                    <span className="qr-plat-sub">{p.sub}</span>
                  </button>
                ))}
              </div>
            </div>
            <div className="qr-rail-block">
              <label>SEVERITY</label>
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
                <option>All</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div className="qr-rail-block">
              <label>DATA SOURCE</label>
              <select value={srcFilter} onChange={(e) => setSrcFilter(e.target.value)}>
                <option>All</option>{DATA_SOURCES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div className="qr-rail-block">
              <label>STATUS</label>
              <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                <option>All</option>{STATUSES.map((s) => <option key={s} value={s}>{STATUS_META[s].label}</option>)}
              </select>
            </div>
            <div className="qr-rail-foot">{filteredHunts.length} hunt{filteredHunts.length !== 1 ? "s" : ""} matched for <b>{ent.name}</b></div>
          </aside>

          <section className="qr-list">
            {filteredHunts.map((h) => (
              <button key={h.id} className={"qr-hunt-row " + (activeHunt && activeHunt.id === h.id ? "on" : "")} onClick={() => setOpenHunt(h.id)}>
                <span className="qr-sev-bar" style={{ background: SEV_COLOR[h.sev] }} />
                <span className="qr-hunt-info">
                  <span className="qr-hunt-name">{h.name}{h.custom && <span className="qr-custom-badge">CUSTOM</span>}{h.validation && h.validation !== "unverified" && <span className="qr-val-badge" style={{ color: VALIDATION_META[h.validation].color, borderColor: VALIDATION_META[h.validation].color }} title={VALIDATION_META[h.validation].label + (h.validatedOn ? " — " + h.validatedOn : "")}>{VALIDATION_META[h.validation].short}</span>}</span>
                  <span className="qr-hunt-meta">
                    <span className="qr-status-dot" style={{ background: STATUS_META[h.status].color }} title={STATUS_META[h.status].label} />
                    {STATUS_META[h.status].label} · {h.technique} · {h.source}
                  </span>
                </span>
                <span className="qr-sev-pill" style={{ color: SEV_COLOR[h.sev], borderColor: SEV_COLOR[h.sev] }}>{h.sev}</span>
              </button>
            ))}
            {filteredHunts.length === 0 && <div className="qr-empty">No hunts match these filters for this enterprise.</div>}
          </section>

          {activeHunt && (
            <section className="qr-detail">
              <div className="qr-detail-head">
                <span className="qr-sev-pill big" style={{ color: SEV_COLOR[activeHunt.sev], borderColor: SEV_COLOR[activeHunt.sev] }}>{activeHunt.sev}</span>
                <h2>{activeHunt.name}</h2>
              </div>
              <div className="qr-detail-meta">
                <span><b>ATT&amp;CK</b> {activeHunt.technique}</span>
                <span><b>Tactic</b> {activeHunt.tactic}</span>
                <span><b>Source</b> {activeHunt.source}</span>
                {atomicUrl(activeHunt) && <span><b>Validate</b> <a className="qr-link" href={atomicUrl(activeHunt)} target="_blank" rel="noreferrer noopener">Atomic Red Team ↗</a></span>}
              </div>
              <div className="qr-lifecycle">
                <div className="qr-lc-row">
                  <span className="qr-lc-label">STATUS</span>
                  <div className="qr-status-seg">
                    {STATUSES.map((s) => (
                      <button key={s} className={"qr-status-btn " + (activeHunt.status === s ? "on" : "")}
                        style={activeHunt.status === s ? { color: STATUS_META[s].color, borderColor: STATUS_META[s].color } : {}}
                        onClick={() => setStatus(activeHunt.id, s)}>{STATUS_META[s].label}</button>
                    ))}
                  </div>
                </div>
                <div className="qr-lc-row">
                  <span className="qr-lc-label">VERSION</span>
                  <div className="qr-ver">
                    <button className="qr-ver-btn" onClick={() => bumpVersion(activeHunt, -1)} disabled={(activeHunt.version || 1) <= 1}>−</button>
                    <span className="qr-ver-n">v{activeHunt.version || 1}</span>
                    <button className="qr-ver-btn" onClick={() => bumpVersion(activeHunt, 1)}>+</button>
                  </div>
                  <span className="qr-lc-label" style={{ marginLeft: "auto" }}>AUTHOR</span>
                  <input className="qr-author" value={activeHunt.author} placeholder="—"
                    onChange={(e) => updateHunt(activeHunt.id, { author: e.target.value.slice(0, 80) })} />
                </div>
                <div className="qr-lc-row qr-lc-dates">
                  <span>Created {activeHunt.created || "—"}</span>
                  <span>Last reviewed {activeHunt.reviewed || "never"}</span>
                  {activeHunt.findings.length > 0 && (
                    <span>Last run {activeHunt.findings[0].date} · <span style={{ color: DISPO_META[activeHunt.findings[0].disposition] ? DISPO_META[activeHunt.findings[0].disposition].color : "#74808c" }}>{DISPO_META[activeHunt.findings[0].disposition] ? DISPO_META[activeHunt.findings[0].disposition].label.split(" — ")[0] : activeHunt.findings[0].disposition}</span></span>
                  )}
                  <button className="qr-lc-review" onClick={() => markReviewed(activeHunt.id)}>✓ Mark reviewed today</button>
                </div>
                <div className="qr-val-row">
                  <span className="qr-lc-label">VALIDATION</span>
                  <div className="qr-val-seg">
                    {VALIDATIONS.map((v) => (
                      <button key={v} className={"qr-val-btn " + (activeHunt.validation === v ? "on" : "")}
                        style={activeHunt.validation === v ? { color: VALIDATION_META[v].color, borderColor: VALIDATION_META[v].color } : {}}
                        title={VALIDATION_META[v].desc}
                        onClick={() => {
                          if (v === "unverified") { setValidation(activeHunt.id, v); return; }
                          const plat = window.prompt("Which platform / method proved this? (e.g. 'Splunk', 'Sentinel', 'Atomic T1059.001')", activeHunt.validatedOn || PLATFORMS.find((p) => p.id === platform).label);
                          if (plat !== null) setValidation(activeHunt.id, v, plat.slice(0, 40));
                        }}>{VALIDATION_META[v].short}</button>
                    ))}
                  </div>
                </div>
                <p className="qr-val-note">
                  {VALIDATION_META[activeHunt.validation].desc}
                  {activeHunt.validation !== "unverified" && activeHunt.validatedOn ? " — " + activeHunt.validatedOn : ""}
                  {activeHunt.validation !== "unverified" && activeHunt.validatedDate ? " (" + activeHunt.validatedDate + ")" : ""}
                </p>
              </div>
              <div className="qr-field"><h4>Hunt Hypothesis</h4><p>{activeHunt.hypothesis}</p></div>
              <div className="qr-field"><h4>False-Positive Tuning</h4><p>{activeHunt.fp}</p></div>
              {activeHunt.note && <div className="qr-reqnote">⚠ {activeHunt.note}</div>}
              <div className="qr-query-head">
                <h4>Query · <span style={{ color: "#f5a623" }}>{PLATFORMS.find((p) => p.id === platform).label}</span>
                  <span className="qr-qsub"> ({PLATFORMS.find((p) => p.id === platform).sub})</span></h4>
                <div className="qr-qh-btns">
                  <button className="qr-copy" onClick={() => exportHuntSigma(activeHunt)} title="Copy this hunt as a Sigma rule (detection-as-code)">⇪ Sigma</button>
                  <button className="qr-copy" onClick={() => copy(activeHunt.queries[platform], activeHunt.id)}>{copied === activeHunt.id ? "✓ Copied" : "⧉ Copy"}</button>
                </div>
              </div>
              <pre className="qr-code">{activeHunt.queries[platform] || "// no query authored for this platform — use Generate & Import to add one"}</pre>
              {(() => {
                return <LintResult issues={lintQuery(platform, activeHunt.queries[platform])} platformLabel={PLATFORMS.find((p) => p.id === platform).label} />;
              })()}
              {(() => {
                const note = connectorNote(platform, activeHunt.queries[platform]);
                return note ? <div className="qr-conn-note">⊗ Deployment note: {note}</div> : null;
              })()}
              <p className="qr-disclaimer">Generated query is a validated-syntax <b>starting point</b>. Field, dataset and index names vary by deployment — confirm against your onboarded log sources and schema, set a sensible lookback window, and tune thresholds before operationalizing.</p>
              <HuntJournal key={activeHunt.id} hunt={activeHunt} onAddFinding={addFinding} onRemoveFinding={removeFinding} onPivots={setPivots} onTuning={setTuning} onExportReport={exportHuntReport} />
            </section>
          )}
        </main>
      )}

      {tab === "coverage" && (
        <main className="qr-coverage" role="tabpanel" id="qr-panel-coverage" aria-labelledby="qr-tab-coverage" tabIndex={-1}>
          <section className="qr-card">
            <div className="qr-cov-head">
              <h3 className="qr-card-h">⊕ Recent Hunt Activity — {ent.name}</h3>
              <button className="qr-ghost" disabled={!libForEnt.length} onClick={exportProgramReport}>⤓ Export program report (MD)</button>
            </div>
            <p className="qr-card-sub">Findings logged across all hunts in this enterprise's library — newest first. A clean result is documented coverage, not nothing. Click an entry to open its hunt.</p>
            <div className="qr-act-stats">
              <div className="qr-act-stat"><span className="qr-act-stat-n">{recentActivity.total}</span><span className="qr-act-stat-l">Total runs logged</span></div>
              {DISPOSITIONS.map((d) => (
                <div key={d} className="qr-act-stat">
                  <span className="qr-act-stat-n" style={{ color: DISPO_META[d].color }}>{recentActivity.byDispo[d]}</span>
                  <span className="qr-act-stat-l">{DISPO_META[d].label.split(" — ")[0]}</span>
                </div>
              ))}
            </div>
            {recentActivity.items.length === 0 ? (
              <div className="qr-empty-cta">
                <p>No runs logged yet. Open a hunt and log a finding in its journal — even a clean result counts.</p>
                <button className="qr-cta alt" onClick={loadDemo}>▶ Load a demo programme</button>
                <span>Seeds a worked example — findings, tuning notes, validation states and two custom hunts — so you can see what the console looks like in use. Nothing is sent anywhere; clear it any time.</span>
              </div>
            ) : (
              <div className="qr-act-list">
                {recentActivity.items.slice(0, 15).map((f, i) => (
                  <button key={i} className="qr-act-row" onClick={() => { setOpenHunt(f.huntId); setTab("hunts"); }}>
                    <span className="qr-act-dot" style={{ background: DISPO_META[f.disposition] ? DISPO_META[f.disposition].color : "#74808c" }} />
                    <span className="qr-act-body">
                      <span className="qr-act-head"><span className="qr-act-date">{f.date}</span> · <span className="qr-act-hunt">{f.huntName}</span> · <span style={{ color: DISPO_META[f.disposition] ? DISPO_META[f.disposition].color : "#74808c" }}>{DISPO_META[f.disposition] ? DISPO_META[f.disposition].label.split(" — ")[0] : f.disposition}</span></span>
                      {f.note && <span className="qr-act-note">{f.note}</span>}
                    </span>
                  </button>
                ))}
                {recentActivity.items.length > 15 && (
                  <p className="qr-card-sub" style={{ marginTop: 6, fontStyle: "italic" }}>Showing 15 of {recentActivity.items.length}. Export the program report for the full record.</p>
                )}
              </div>
            )}
          </section>

          <section className="qr-card">
            <div className="qr-cov-head">
              <h3 className="qr-card-h">▦ ATT&amp;CK Coverage — {ent.name}</h3>
              <button className="qr-ghost" onClick={exportNav}>⤓ Export Navigator layer</button>
            </div>
            <p className="qr-card-sub">Hunt counts per ATT&amp;CK tactic for the current enterprise library. Export produces a Navigator layer JSON you can load at mitre-attack.github.io/attack-navigator.</p>
            <div className="qr-lc-summary">
              {STATUSES.map((s) => (
                <div key={s} className="qr-lc-stat" onClick={() => { setStatusFilter(s); setTab("hunts"); }} title={"Filter hunts: " + STATUS_META[s].label}>
                  <span className="qr-lc-stat-n" style={{ color: STATUS_META[s].color }}>{statusCounts[s]}</span>
                  <span className="qr-lc-stat-l">{STATUS_META[s].label}</span>
                </div>
              ))}
            </div>
            <div className="qr-matrix">
              {TACTIC_ORDER.map((t) => {
                const th = libForEnt.filter((h) => tacticsOf(h).includes(t));
                return (
                  <div key={t} className={"qr-col " + (th.length ? "has" : "gap")}>
                    <div className="qr-col-head"><span>{t}</span><span className="qr-col-n">{th.length}</span></div>
                    <div className="qr-col-body">
                      {techChips(th).map((c) => (
                        <span key={c.id} className="qr-cell" style={{ borderColor: SEV_COLOR[c.sev] }} title={c.hunts.join(" · ")}>
                          {c.id}{c.count > 1 && <span className="qr-cell-n"> ×{c.count}</span>}
                        </span>
                      ))}
                      {!th.length && <span className="qr-cell-empty">no hunt</span>}
                    </div>
                  </div>
                );
              })}
            </div>
            {entGaps.length > 0 && (
              <div className="qr-gaps">
                <h4>Priority gaps — likely techniques for {ent.name} with no hunt yet</h4>
                <div className="qr-chips">{entGaps.map((t) => (<span key={t} className="qr-chip gap">{t}</span>))}</div>
                <p className="qr-card-sub" style={{ marginTop: 10 }}>Use Generate &amp; Import to draft hunts for these, then they'll appear here as covered.</p>
              </div>
            )}
            {navText && <pre className="qr-code small">{navText.slice(0, 900)}{navText.length > 900 ? "\n… (full layer on clipboard)" : ""}</pre>}
          </section>

          <section className="qr-card">
            <div className="qr-cov-head">
              <h3 className="qr-card-h">🛰 Actively-Exploited (CISA KEV) Exposure — {ent.name}</h3>
              <button className="qr-ghost" disabled={kev.busy} onClick={scanKev}>{kev.busy ? "Scanning…" : "↻ Scan KEV catalog"}</button>
            </div>
            <p className="qr-card-sub">Reads the authoritative CISA KEV catalog (cisagov/kev-data) and filters it against {shortName(ent)}'s internet-facing stack, flagging actively-exploited CVEs that have no hunt in your library yet. Edit the enterprise's stack in the profile to change what's matched.</p>
            {kev.err && <div className="qr-err">{kev.err}</div>}
            {kev.source && kevItems.length > 0 && (
              <div className="qr-kev-prov">
                {kev.source === "feed"
                  ? <span><span className="qr-prov-dot ok" /> Live CISA feed{kev.version ? " · catalog " + kev.version : ""}</span>
                  : <span><span className="qr-prov-dot warn" /> Best-effort model recall (live feed was unreachable) — verify against cisa.gov/kev</span>}
              </div>
            )}
            {!kev.items.length && !kev.busy && !kev.err && (
              <p className="qr-card-sub" style={{ fontStyle: "italic" }}>No scan yet. Run a scan to pull the live catalog and see which actively-exploited CVEs for this stack are uncovered.</p>
            )}
            {kevItems.length > 0 && (
              <div className="qr-kev-list">
                {kevItems.map((it) => (
                  <div key={it.cve} className={"qr-kev-row " + (it.covered ? "ok" : "gap")}>
                    <span className={"qr-kev-flag " + (it.covered ? "ok" : "gap")}>{it.covered ? "✓ hunt exists" : "no hunt"}</span>
                    <span className="qr-kev-body">
                      <span className="qr-kev-cve">{it.cve} <span className="qr-kev-prod">· {it.product}</span>
                        {it.ransomware && <span className="qr-kev-ransom">ransomware</span>}
                        {it.dateAdded && <span className="qr-kev-date">added {it.dateAdded}</span>}
                      </span>
                      <span className="qr-kev-desc">{it.desc}</span>
                    </span>
                    {!it.covered && <button className="qr-kev-draft" onClick={() => draftForCve(it)}>Draft hunt →</button>}
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="qr-card">
            <h3 className="qr-card-h">📡 Telemetry-Readiness Audit</h3>
            <p className="qr-card-sub">Toggle the log sources you've actually onboarded. Otter Shell shows which hunts you can run today versus where you're blind.</p>
            <div className="qr-readiness">
              <div className="qr-ready-stat"><span className="qr-big-n" style={{ color: "#4ec9b0" }}>{runnable.length}</span><span>runnable now</span></div>
              <div className="qr-ready-stat"><span className="qr-big-n" style={{ color: "#ff8c2a" }}>{blind.length}</span><span>blind spots</span></div>
              <div className="qr-ready-stat"><span className="qr-big-n">{libForEnt.length}</span><span>total for {shortName(ent)}</span></div>
            </div>
            <div className="qr-tele-toggles">
              {TELEMETRY.map((t) => (
                <button key={t} className={"qr-tele " + (have.has(t) ? "on" : "")} onClick={() => toggleTele(t)}>
                  <span className="qr-tele-box">{have.has(t) ? "✓" : ""}</span>{t}
                </button>
              ))}
            </div>
            {blind.length > 0 && (
              <div className="qr-blind">
                <h4>Blind hunts — missing telemetry</h4>
                {blind.map((h) => (
                  <div key={h.id} className="qr-blind-row">
                    <span className="qr-blind-name">{h.name}</span>
                    <span className="qr-blind-need">needs: {reqOf(h).filter((r) => !have.has(r)).join(", ")}</span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </main>
      )}

      {tab === "forge" && (
        <main className="qr-forge" role="tabpanel" id="qr-panel-forge" aria-labelledby="qr-tab-forge" tabIndex={-1}>
          <div className="qr-forge-col">
            {/* With no AI backend configured the generator is a disabled card with a long
                notice attached, so it must not be the first thing on the page: the Sigma
                converter is what actually works in that build, and it goes first. */}
            {(() => {
              const generator = (
              <section className="qr-card">
                <h3 className="qr-card-h">✶ AI Hunt Generator</h3>
                <div className="qr-mode-row">
                  <button className={"qr-mode " + (genMode === "tech" ? "on" : "")} onClick={() => setGenMode("tech")}>Technique → hunt</button>
                  <button className={"qr-mode " + (genMode === "intel" ? "on" : "")} onClick={() => setGenMode("intel")}>Intel → hunt</button>
                  <button className={"qr-mode " + (genMode === "kev" ? "on" : "")} onClick={() => setGenMode("kev")}>CISA KEV → hunt</button>
                  <button className={"qr-mode " + (genMode === "report" ? "on" : "")} onClick={() => setGenMode("report")}>Report → hunt</button>
                </div>
                <p className="qr-card-sub">{genMode === "tech"
                  ? "Describe a technique or behaviour. Otter Shell drafts a hunt with queries for all seven platforms."
                  : genMode === "kev"
                  ? "List a vendor / product stack (VPN, email, web apps). Otter Shell searches the current CISA KEV catalog for an actively-exploited CVE affecting it and drafts an exploitation-detection hunt."
                  : genMode === "report"
                  ? "Paste an article body, advisory, or short excerpt — and/or a source URL. Otter Shell extracts what's there and uses web search to fill gaps on the named CVE / actor / vendor, then drafts a hunt focused on the most observable post-exploitation signal. URL → fetch isn't possible from the browser (CORS); pasting still wins for full articles."
                  : "Name a threat actor, malware family, or CVE. Otter Shell searches the web for current TTPs, summarizes them, and drafts a matching hunt."}</p>
                {genMode === "report" && (
                  <input className="qr-url-input" placeholder="Optional: source URL (e.g. https://www.cybersecuritydive.com/news/...) — used as a search seed if the excerpt is sparse"
                    value={genUrl} onChange={(e) => setGenUrl(e.target.value.slice(0, 500))} />
                )}
                <textarea className="qr-ta" rows={genMode === "report" ? 10 : 4}
                  placeholder={genMode === "tech"
                    ? "e.g. Detect Kerberoasting — TGS-REQ with RC4 (etype 0x17) across many SPNs from one account"
                    : genMode === "kev"
                    ? "e.g. Ivanti Connect Secure VPN, Citrix NetScaler, Microsoft Exchange, Fortinet FortiOS"
                    : genMode === "report"
                    ? "Paste the article body, advisory text, or a short excerpt — reader-mode text gives the cleanest extraction. URL-only is fine too; web search will fill in the gaps."
                    : "e.g. Scattered Spider — current help-desk social-engineering and persistence TTPs    ·    or: CVE-2025-0282 exploitation"}
                  value={genText} onChange={(e) => setGenText(e.target.value.slice(0, 8000))} />
                {genMode === "kev" && ent.stack && (
                  <button className="qr-seed-chip" onClick={() => setGenText(ent.stack)} title="Prefill with this enterprise's likely internet-facing stack">
                    ↧ use {shortName(ent)}'s likely stack
                  </button>
                )}
                {!AI_ENABLED && (
                  <div className="qr-ai-off">
                    <b>AI generation is off in this build.</b> It needs a backend holding an Anthropic API key
                    server-side — a key shipped in the frontend would be a published key. Set
                    <code> VITE_CLAUDE_PROXY_URL</code> to your proxy and rebuild to switch it on; see the README
                    and <code>migration/03_PROXY_CONTRACT.md</code>. Everything else on this page — Sigma import,
                    JSON import/export, workspace save/load, Detection-as-Code export — works right now, as does
                    the full hunt library, ATT&amp;CK coverage map and the live CISA KEV scan.
                  </div>
                )}
                <button className="qr-cta" disabled={!AI_ENABLED || genBusy || (!genText.trim() && !(genMode === "report" && genUrl.trim()))} onClick={generate}>
                  {genBusy
                    ? (genMode === "tech" ? "Generating…" : "Researching + drafting…")
                    : !AI_ENABLED
                    ? (genMode === "tech" ? "Generate Hunt — needs AI backend" : "Research & Draft Hunt — needs AI backend")
                    : (genMode === "tech" ? "Generate Hunt" : genMode === "report" ? "Research & Draft Hunt" : "Research & Draft Hunt")}
                </button>
                {genBusy && genMode !== "tech" && (
                  <p className="qr-busy-hint">↻ Running web search, then drafting the hunt — usually 15–45 seconds. The button re-enables when it's done.</p>
                )}
              </section>
              );
              const sigma = (
              <section className="qr-card">
                <h3 className="qr-card-h">⇪ Import Sigma Rule</h3>
                <p className="qr-card-sub">A sample rule is already in the box — hit <b>Convert Sigma → Hunt</b> to watch it become a hunt with queries for all seven platforms, then replace it with your own. The converter maps logsource + detection (best with process_creation / dns / network rules).</p>
                <textarea className="qr-ta mono" rows={6} maxLength={200000} placeholder={SIGMA_SAMPLE} value={sigmaText} onChange={(e) => setSigmaText(e.target.value.slice(0, 200000))} />
                <button className="qr-cta alt" disabled={!sigmaText.trim()} onClick={convertSigma}>Convert Sigma → Hunt</button>
              </section>
              );
              return AI_ENABLED
                ? <React.Fragment key="gen-first">{generator}{sigma}</React.Fragment>
                : <React.Fragment key="sigma-first">{sigma}{generator}</React.Fragment>;
            })()}

            <section className="qr-card">
              <h3 className="qr-card-h">⤓ Import / Export JSON</h3>
              <p className="qr-card-sub">Import hunts in Otter Shell's schema (array or single object with name + queries), or export the whole library.</p>
              <textarea className="qr-ta mono" rows={4} placeholder='[{ "name": "...", "sev": "High", "source": "Endpoint / EDR", "queries": { "crowdstrike": "...", "splunk": "..." } }]'
                value={jsonText} onChange={(e) => setJsonText(e.target.value)} />
              <div className="qr-btn-row">
                <button className="qr-cta alt" disabled={!jsonText.trim()} onClick={importJson}>Import JSON</button>
                <button className="qr-ghost" onClick={exportLibrary}>Export library ({hunts.length})</button>
              </div>
              {exportText && <pre className="qr-code small">{exportText.slice(0, 1100)}{exportText.length > 1100 ? "\n… (full JSON on clipboard)" : ""}</pre>}
            </section>

            <section className="qr-card">
              <h3 className="qr-card-h">💾 Save / Load Workspace</h3>
              <p className="qr-card-sub">Your work autosaves to this browser and comes back on reload. Download the workspace — custom &amp; generated hunts, journals and telemetry selections — as a file to move it between browsers or keep a snapshot. Built-in hunts are re-added automatically on load.</p>
              <div className="qr-btn-row">
                <button className="qr-cta" onClick={downloadWorkspace}>⤓ Download workspace</button>
                <button className="qr-ghost" onClick={() => wsFileRef.current && wsFileRef.current.click()}>⤒ Load workspace</button>
                <button className="qr-ghost" onClick={loadDemo}>▶ Load demo</button>
                <button className="qr-ghost" onClick={clearDemo}>↺ Clear demo</button>
                <button className="qr-ghost" onClick={forgetSaved}>✕ Forget saved data</button>
                <input ref={wsFileRef} type="file" accept="application/json,.json" style={{ display: "none" }}
                  onChange={(e) => { loadWorkspaceFile(e.target.files && e.target.files[0]); e.target.value = ""; }} />
              </div>
              <p className="qr-card-sub" style={{ marginTop: 10, marginBottom: 0, fontStyle: "italic" }}>
                {saved === false
                  ? "⚠ This browser is blocking local storage (private mode, or the quota is full), so nothing is being saved. Download your workspace before closing the tab."
                  : "Autosaved to this browser only — never uploaded. Download the file to keep a copy elsewhere."}
              </p>
            </section>

            <section className="qr-card">
              <h3 className="qr-card-h">⇪ Detection-as-Code Export (Sigma)</h3>
              <p className="qr-card-sub">Export the whole library as a multi-document Sigma file for your detection-as-code pipeline. Hunts imported from Sigma round-trip faithfully; others export as a Sigma scaffold with full metadata and the native per-platform queries preserved under a custom field. (Per-hunt export is on each hunt's Copy row in the Hunt Library.)</p>
              <button className="qr-cta alt" onClick={exportAllSigma}>⇩ Export all {hunts.length} hunts as Sigma</button>
            </section>
          </div>

          <div className="qr-forge-col">
            {genErr && <div className="qr-err">{genErr}</div>}
            {genSummary && <div className="qr-summary"><b>Current-intel summary</b><p>{genSummary}</p></div>}
            {pending ? (
              <HuntPreview hunt={pending} onAdd={addHunt} onDiscard={() => { setPending(null); setGenSummary(""); }} copyFn={(t) => copy(t)} />
            ) : (
              <div className="qr-placeholder">
                <span className="qr-logo big" aria-hidden="true">🦦</span>
                <p>Drafted and imported hunts preview here before you keep them.<br />Anything you add works under every enterprise and rolls up into the Coverage view.</p>

                <div className="qr-ph-steps">
                  <div className="qr-ph-step">
                    <span className="qr-ph-num">1</span>
                    <div>
                      <b>Draft or import</b>
                      <span>Convert a Sigma rule, paste Otter Shell JSON, or{AI_ENABLED ? " describe a technique and let the generator draft one" : " — with an AI backend configured — describe a technique in plain English"}.</span>
                    </div>
                  </div>
                  <div className="qr-ph-step">
                    <span className="qr-ph-num">2</span>
                    <div>
                      <b>Review all seven platforms</b>
                      <span>Every draft arrives with a CrowdStrike, XSIAM, Sentinel, Defender, Elastic, SecOps and Splunk query, each run through the linter.</span>
                    </div>
                  </div>
                  <div className="qr-ph-step">
                    <span className="qr-ph-num">3</span>
                    <div>
                      <b>Keep what survives review</b>
                      <span>Added hunts pick up the full lifecycle — status, validation provenance, findings journal — and appear in the ATT&amp;CK coverage map.</span>
                    </div>
                  </div>
                </div>

                {!AI_ENABLED && (
                  <p className="qr-ph-hint">
                    The Sigma converter is the fastest way to see this working — a sample rule is already in the box, so just hit <b>Convert Sigma → Hunt</b>.
                  </p>
                )}
              </div>
            )}
          </div>
        </main>
      )}

      <footer className="qr-footer">
        <span className="qr-footer-badge">TEST / PORTFOLIO PROJECT</span>
        OTTER SHELL · defensive threat-hunting tooling · not production software, not supported ·
        queries map to MITRE ATT&amp;CK® · validate &amp; tune to environment before use
      </footer>
    </div>
  );
}

/* Prefilled into the Sigma box, so the converter is one click away on a cold start
   (and doubles as the placeholder if you clear the box). */
const SIGMA_SAMPLE = `title: Suspicious Encoded PowerShell
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - 'FromBase64String'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001`;

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Oxanium:wght@500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
.qr-root{--bg:#0a0e12;--panel:#11161c;--panel2:#0d1218;--panel3:#151c24;--line:#1d2730;--line2:#28333d;--txt:#d6dde4;--txt-hi:#f2f6fa;--muted:#74808c;--amber:#f5a623;--amber-dk:#c9821a;--teal:#2dd4bf;--teal-dk:#1fa896;
  --radius:9px;--radius-lg:14px;--shadow:0 2px 8px rgba(0,0,0,.35);--shadow-lg:0 24px 80px rgba(0,0,0,.6);--ease:cubic-bezier(.22,.61,.36,1);
  font-family:'IBM Plex Sans',sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;width:100%;
  background-image:radial-gradient(circle at 12% -10%,rgba(245,166,35,.06),transparent 40%),radial-gradient(circle at 90% 0%,rgba(45,212,191,.05),transparent 45%),linear-gradient(rgba(255,255,255,.012) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.012) 1px,transparent 1px);
  background-size:auto,auto,42px 42px,42px 42px;}
.qr-root *{box-sizing:border-box;}
.qr-root ::selection{background:rgba(245,166,35,.28);color:#fff;}
@keyframes qr-rise{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:none;}}
@keyframes qr-fade{from{opacity:0;}to{opacity:1;}}
@keyframes qr-scan{0%{transform:translateX(-100%);}100%{transform:translateX(300%);}}
.qr-header{display:flex;justify-content:space-between;align-items:center;padding:18px 26px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,rgba(17,22,28,.9),rgba(10,14,18,.6));animation:qr-rise .5s var(--ease) both;position:relative;}
.qr-header:after{content:'';position:absolute;left:0;right:0;bottom:-1px;height:1px;background:linear-gradient(90deg,transparent,rgba(245,166,35,.5),rgba(45,212,191,.4),transparent);}
.qr-brand{display:flex;align-items:center;gap:14px;}
.qr-logo{font-size:30px;line-height:1;filter:drop-shadow(0 0 12px rgba(245,166,35,.4));}
.qr-logo.big{font-size:52px;opacity:.5;}
.qr-brand h1{font-family:'Oxanium',sans-serif;font-weight:800;font-size:23px;letter-spacing:6px;margin:0;color:var(--txt-hi);text-shadow:0 0 24px rgba(245,166,35,.18);}
.qr-brand p{margin:2px 0 0;font-size:10px;letter-spacing:3.5px;text-transform:uppercase;color:var(--muted);}
.qr-ent-pick{display:flex;flex-direction:column;gap:4px;align-items:flex-end;}
.qr-ent-pick label{font-size:10px;letter-spacing:2px;color:var(--muted);font-family:'IBM Plex Mono',monospace;}
.qr-ent-pick select,.qr-rail select{background:var(--panel);color:var(--txt);border:1px solid var(--line);padding:9px 12px;border-radius:7px;font-family:'IBM Plex Mono',monospace;font-size:13px;min-width:260px;cursor:pointer;}
.qr-ent-pick select:focus,.qr-rail select:focus{outline:none;border-color:var(--amber);}
.qr-ent-row{display:flex;gap:6px;align-items:center;}
.qr-ent-new{background:rgba(245,166,35,.12);border:1px solid var(--amber);color:var(--amber);font-family:'Oxanium',sans-serif;font-weight:700;font-size:12px;padding:8px 11px;border-radius:7px;cursor:pointer;white-space:nowrap;transition:.13s;}
.qr-ent-new:hover{background:var(--amber);color:#0a0e12;}
.qr-ent-del{background:var(--panel);border:1px solid var(--line);color:var(--muted);font-size:13px;padding:8px 9px;border-radius:7px;cursor:pointer;transition:.13s;}
.qr-ent-del:hover{border-color:#ff3b4e;color:#ff3b4e;}
.qr-modal-overlay{position:fixed;inset:0;background:rgba(4,7,10,.78);backdrop-filter:blur(3px);display:flex;align-items:flex-start;justify-content:center;z-index:50;padding:32px 16px;overflow-y:auto;}
.qr-modal{background:var(--panel);border:1px solid var(--line);border-radius:14px;width:100%;max-width:720px;box-shadow:0 24px 80px rgba(0,0,0,.6);}
.qr-modal:before{content:'';display:block;height:3px;border-radius:14px 14px 0 0;background:linear-gradient(90deg,var(--amber),var(--teal));}
.qr-modal-head{display:flex;justify-content:space-between;align-items:center;padding:16px 22px;border-bottom:1px solid var(--line);}
.qr-modal-head h3{font-family:'Oxanium',sans-serif;font-size:18px;margin:0;color:#fff;}
.qr-modal-x{background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;}
.qr-modal-x:hover{color:var(--txt);}
.qr-modal-body{padding:20px 22px;display:flex;flex-direction:column;gap:14px;max-height:64vh;overflow-y:auto;}
.qr-modal-body>*{flex-shrink:0;}
.qr-modal-foot{display:flex;justify-content:flex-end;gap:10px;padding:16px 22px;border-top:1px solid var(--line);}
.qr-modal-foot .qr-cta{width:auto;}
.qr-fld{display:flex;flex-direction:column;gap:6px;}
.qr-fld>span{font-family:'IBM Plex Mono',monospace;font-size:10.5px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted);}
.qr-fld input,.qr-fld textarea,.qr-fld select{background:#06090c;border:1px solid var(--line);border-radius:8px;color:var(--txt);padding:9px 11px;font-family:'IBM Plex Sans',sans-serif;font-size:13px;resize:vertical;}
.qr-fld input:focus,.qr-fld textarea:focus,.qr-fld select:focus{outline:none;border-color:var(--amber);}
.qr-fld-hint{font-size:11.5px;color:var(--muted);line-height:1.5;margin:2px 0 0;}
.qr-fg-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.qr-fg-4{display:grid;grid-template-columns:1fr 1fr 1fr 100px;gap:8px;}
@media(max-width:620px){.qr-fg-2,.qr-fg-4{grid-template-columns:1fr;}}
.qr-inh{display:flex;flex-wrap:wrap;gap:7px;}
.qr-inh-chip{background:var(--panel2);border:1px solid var(--line);color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:11.5px;padding:6px 10px;border-radius:6px;cursor:pointer;transition:.12s;}
.qr-inh-chip.on{border-color:var(--teal);color:var(--teal);background:rgba(45,212,191,.08);}
.qr-actor-mini-list{display:flex;flex-direction:column;gap:6px;margin-bottom:10px;}
.qr-actor-mini{display:flex;align-items:center;gap:9px;background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:7px 10px;}
.qr-actor-mini-name{font-family:'Oxanium',sans-serif;font-weight:600;font-size:13px;color:var(--txt);}
.qr-actor-mini-meta{font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:var(--muted);}
.qr-actor-rm{margin-left:auto;background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px;}
.qr-actor-rm:hover{color:#ff3b4e;}
.qr-actor-add{display:flex;flex-direction:column;gap:8px;background:var(--panel2);border:1px dashed var(--line);border-radius:8px;padding:12px;}
.qr-actor-add input,.qr-actor-add textarea,.qr-actor-add select{background:#06090c;border:1px solid var(--line);border-radius:6px;color:var(--txt);padding:7px 9px;font-family:'IBM Plex Sans',sans-serif;font-size:12.5px;}
.qr-actor-add input:focus,.qr-actor-add textarea:focus{outline:none;border-color:var(--amber);}
.qr-actor-add .qr-ghost{align-self:flex-start;}
.qr-tabs{display:flex;gap:4px;padding:0 26px;border-bottom:1px solid var(--line);background:var(--panel2);flex-wrap:wrap;animation:qr-fade .6s var(--ease) .1s both;}
.qr-tabs button{background:none;border:none;color:var(--muted);font-family:'Oxanium',sans-serif;font-weight:600;font-size:14px;letter-spacing:1px;padding:15px 18px;cursor:pointer;border-bottom:2px solid transparent;transition:color .15s var(--ease),border-color .15s var(--ease);position:relative;overflow:hidden;}
.qr-tabs button:hover{color:var(--txt);}
.qr-tabs button.on{color:var(--amber);border-bottom-color:var(--amber);}
.qr-tabs button.on:after{content:'';position:absolute;left:0;bottom:0;width:34%;height:2px;background:linear-gradient(90deg,transparent,var(--amber),transparent);animation:qr-scan 3.2s linear infinite;}
.qr-tabs button:hover{color:var(--txt);}
.qr-tabs button.on{color:var(--amber);border-bottom-color:var(--amber);}
.qr-toast{margin:14px 26px -6px;background:rgba(45,212,191,.12);border:1px solid rgba(45,212,191,.4);color:var(--teal);padding:9px 14px;border-radius:8px;font-size:13px;font-family:'IBM Plex Mono',monospace;}
.qr-landscape{display:grid;grid-template-columns:1fr 1.25fr;gap:22px;padding:26px;max-width:1400px;margin:0 auto;animation:qr-rise .4s var(--ease) both;}
@media(max-width:900px){.qr-landscape{grid-template-columns:1fr;}}
.qr-profile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px;position:relative;overflow:hidden;}
.qr-profile:before{content:'';position:absolute;top:0;left:0;width:100%;height:3px;background:linear-gradient(90deg,var(--amber),var(--teal));}
.qr-tag{font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:2px;color:var(--teal);text-transform:uppercase;}
.qr-flag{margin-left:10px;font-family:'IBM Plex Mono',monospace;font-size:10px;background:rgba(245,166,35,.14);color:var(--amber);padding:3px 8px;border-radius:4px;letter-spacing:1px;}
.qr-profile h2{font-family:'Oxanium',sans-serif;font-size:26px;margin:10px 0 0;color:#fff;}
.qr-blurb{color:var(--muted);font-size:14px;line-height:1.65;margin:14px 0 20px;}
.qr-posture h3,.qr-tech-strip h3,.qr-actors-title{font-family:'Oxanium',sans-serif;font-size:13px;letter-spacing:2px;text-transform:uppercase;color:var(--amber);margin:0 0 12px;}
.qr-posture ul{list-style:none;padding:0;margin:0 0 22px;}
.qr-posture li{position:relative;padding-left:20px;margin-bottom:11px;font-size:13.5px;line-height:1.55;}
.qr-posture li:before{content:'▸';position:absolute;left:0;color:var(--teal);}
.qr-chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:22px;}
.qr-chip{font-family:'IBM Plex Mono',monospace;font-size:12px;background:var(--panel2);border:1px solid var(--line);color:var(--txt);padding:5px 10px;border-radius:6px;}
.qr-chip.gap{border-color:rgba(255,140,42,.5);color:var(--amber);}
.qr-cta{width:100%;background:linear-gradient(90deg,rgba(245,166,35,.16),rgba(245,166,35,.06));border:1px solid var(--amber);color:var(--amber);font-family:'Oxanium',sans-serif;font-weight:700;letter-spacing:1px;padding:13px;border-radius:var(--radius);cursor:pointer;font-size:14px;transition:background .16s var(--ease),color .16s var(--ease),box-shadow .16s var(--ease),transform .08s var(--ease);}
.qr-cta:hover:not(:disabled){background:var(--amber);color:#0a0e12;box-shadow:0 0 24px rgba(245,166,35,.35);}
.qr-cta:active:not(:disabled){transform:translateY(1px);}
.qr-cta:disabled{opacity:.45;cursor:not-allowed;}
.qr-cta:disabled{opacity:.4;cursor:not-allowed;}
.qr-cta.alt{background:linear-gradient(90deg,rgba(45,212,191,.16),rgba(45,212,191,.05));border-color:var(--teal);color:var(--teal);}
.qr-cta.alt:hover:not(:disabled){background:var(--teal);color:#0a0e12;}
.qr-ghost{background:var(--panel2);border:1px solid var(--line);color:var(--txt);font-family:'Oxanium',sans-serif;font-weight:600;letter-spacing:1px;padding:11px 16px;border-radius:8px;cursor:pointer;font-size:13px;transition:.15s;white-space:nowrap;}
.qr-ghost:hover{border-color:var(--muted);}
.qr-actor-grid{display:flex;flex-direction:column;gap:14px;}
.qr-actor-card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;transition:.15s;}
.qr-actor-card:hover{border-color:#2c3a46;transform:translateX(3px);}
.qr-actor-top{display:flex;align-items:center;gap:10px;margin-bottom:10px;}
.qr-sev-dot{width:10px;height:10px;border-radius:50%;flex:0 0 auto;box-shadow:0 0 10px currentColor;}
.qr-actor-card h4{font-family:'Oxanium',sans-serif;font-size:16px;margin:0;color:#fff;font-weight:700;}
.qr-actor-meta{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:10px;font-family:'IBM Plex Mono',monospace;font-size:11.5px;}
.qr-actor-meta b{color:var(--muted);font-weight:500;margin-right:5px;text-transform:uppercase;letter-spacing:1px;}
.qr-actor-card p{margin:0;font-size:13.5px;line-height:1.6;color:var(--muted);}
.qr-hunts{display:grid;grid-template-columns:230px 360px 1fr;gap:18px;padding:22px;max-width:1500px;margin:0 auto;align-items:start;animation:qr-rise .4s var(--ease) both;}
@media(max-width:1100px){.qr-hunts{grid-template-columns:1fr;}.qr-rail,.qr-detail{position:static;}.qr-list{max-height:none;}}
.qr-rail{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:18px;position:sticky;top:14px;}
.qr-rail-block{margin-bottom:18px;}
.qr-rail label{display:block;font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--muted);margin-bottom:8px;}
.qr-rail select{width:100%;min-width:0;}
.qr-plat-list{display:flex;flex-direction:column;gap:7px;}
.qr-plat{display:flex;flex-direction:column;align-items:flex-start;text-align:left;background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:9px 11px;cursor:pointer;transition:.13s;}
.qr-plat:hover{border-color:#33424f;}
.qr-plat.on{border-color:var(--amber);background:rgba(245,166,35,.08);}
.qr-plat-name{font-family:'Oxanium',sans-serif;font-weight:700;font-size:13.5px;color:var(--txt);}
.qr-plat.on .qr-plat-name{color:var(--amber);}
.qr-plat-sub{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-top:2px;}
.qr-rail-foot{font-size:11.5px;color:var(--muted);line-height:1.5;border-top:1px solid var(--line);padding-top:12px;}
.qr-rail-foot b{color:var(--txt);}
.qr-list{display:flex;flex-direction:column;gap:8px;max-height:80vh;overflow-y:auto;padding-right:4px;}
.qr-hunt-row{display:flex;align-items:stretch;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);cursor:pointer;overflow:hidden;text-align:left;transition:border-color .13s var(--ease),background .13s var(--ease),transform .1s var(--ease);flex:0 0 auto;}
.qr-hunt-row:hover{border-color:var(--line2);background:var(--panel3);transform:translateX(2px);}
.qr-hunt-row.on{border-color:var(--amber);background:linear-gradient(90deg,rgba(245,166,35,.06),transparent);}
.qr-sev-bar{width:4px;flex:0 0 auto;}
.qr-hunt-info{display:flex;flex-direction:column;gap:3px;padding:12px;flex:1;min-width:0;}
.qr-hunt-name{font-family:'Oxanium',sans-serif;font-weight:600;font-size:14px;color:var(--txt);line-height:1.25;overflow-wrap:anywhere;}
.qr-custom-badge{font-family:'IBM Plex Mono',monospace;font-size:8.5px;background:rgba(45,212,191,.16);color:var(--teal);padding:2px 5px;border-radius:3px;margin-left:7px;letter-spacing:1px;vertical-align:middle;}
.qr-hunt-meta{font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:var(--muted);}
.qr-sev-pill{align-self:center;margin-right:11px;font-family:'IBM Plex Mono',monospace;font-size:10px;border:1px solid;border-radius:5px;padding:3px 7px;letter-spacing:1px;white-space:nowrap;}
.qr-sev-pill.big{font-size:11px;margin:0;}
.qr-empty{color:var(--muted);font-size:13px;padding:20px;text-align:center;}
.qr-detail,.qr-preview{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:24px;position:sticky;top:14px;}
.qr-detail-head{display:flex;align-items:center;gap:12px;margin-bottom:12px;}
.qr-detail-head h2{font-family:'Oxanium',sans-serif;font-size:21px;margin:0;color:#fff;line-height:1.2;}
.qr-detail-meta{display:flex;flex-wrap:wrap;gap:16px;font-family:'IBM Plex Mono',monospace;font-size:11.5px;padding-bottom:16px;border-bottom:1px solid var(--line);margin-bottom:16px;}
.qr-detail-meta b{color:var(--muted);font-weight:500;margin-right:5px;text-transform:uppercase;letter-spacing:1px;}
.qr-field{margin-bottom:16px;}
.qr-field h4{font-family:'Oxanium',sans-serif;font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:var(--teal);margin:0 0 6px;}
.qr-field p{margin:0;font-size:13.5px;line-height:1.6;}
.qr-reqnote{background:rgba(245,166,35,.1);border:1px solid rgba(245,166,35,.35);color:var(--amber);font-size:12.5px;padding:9px 12px;border-radius:7px;margin-bottom:16px;font-family:'IBM Plex Mono',monospace;}
.qr-query-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;}
.qr-qh-btns{display:flex;gap:8px;}
.qr-status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle;}
.qr-lifecycle{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:12px 14px;margin-bottom:16px;display:flex;flex-direction:column;gap:10px;}
.qr-lc-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.qr-lc-label{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:1.5px;color:var(--muted);}
.qr-status-seg{display:flex;gap:5px;flex-wrap:wrap;}
.qr-status-btn{background:var(--panel);border:1px solid var(--line);color:var(--muted);font-family:'Oxanium',sans-serif;font-weight:600;font-size:11.5px;padding:5px 10px;border-radius:6px;cursor:pointer;transition:.12s;}
.qr-status-btn:hover{border-color:#33424f;color:var(--txt);}
.qr-status-btn.on{background:rgba(255,255,255,.04);}
.qr-ver{display:flex;align-items:center;gap:6px;}
.qr-ver-btn{background:var(--panel);border:1px solid var(--line);color:var(--txt);width:24px;height:24px;border-radius:6px;cursor:pointer;font-size:14px;line-height:1;}
.qr-ver-btn:hover:not(:disabled){border-color:var(--teal);color:var(--teal);}
.qr-ver-btn:disabled{opacity:.35;cursor:not-allowed;}
.qr-ver-n{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--txt);min-width:30px;text-align:center;}
.qr-author{background:var(--panel);border:1px solid var(--line);color:var(--txt);font-family:'IBM Plex Mono',monospace;font-size:12px;padding:5px 9px;border-radius:6px;width:150px;}
.qr-author:focus{outline:none;border-color:var(--amber);}
.qr-lc-dates{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);border-top:1px solid var(--line);padding-top:9px;}
.qr-lc-review{margin-left:auto;background:rgba(45,212,191,.1);border:1px solid rgba(45,212,191,.4);color:var(--teal);font-family:'IBM Plex Mono',monospace;font-size:11px;padding:5px 10px;border-radius:6px;cursor:pointer;transition:.12s;}
.qr-lc-review:hover{background:var(--teal);color:#0a0e12;}
.qr-val-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;border-top:1px solid var(--line);padding-top:10px;margin-top:2px;}
.qr-val-seg{display:flex;gap:5px;flex-wrap:wrap;}
.qr-val-btn{background:var(--panel);border:1px solid var(--line);color:var(--muted);font-family:'IBM Plex Mono',monospace;font-weight:600;font-size:11px;padding:5px 10px;border-radius:6px;cursor:pointer;transition:.12s;}
.qr-val-btn:hover{border-color:var(--line2);color:var(--txt);}
.qr-val-btn.on{background:rgba(255,255,255,.04);}
.qr-val-note{font-size:11.5px;line-height:1.5;color:var(--muted);margin:8px 0 0;font-family:'IBM Plex Mono',monospace;}
.qr-val-badge{font-family:'IBM Plex Mono',monospace;font-size:9px;font-weight:700;letter-spacing:.5px;border:1px solid;border-radius:4px;padding:1px 5px;margin-left:7px;vertical-align:middle;text-transform:uppercase;}
.qr-lc-summary{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;}
.qr-lc-stat{flex:1;min-width:90px;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:12px;cursor:pointer;transition:.12s;text-align:center;}
.qr-lc-stat:hover{border-color:#33424f;}
.qr-lc-stat-n{display:block;font-family:'Oxanium',sans-serif;font-weight:800;font-size:26px;line-height:1;}
.qr-lc-stat-l{display:block;font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:var(--muted);margin-top:5px;letter-spacing:1px;}
.qr-journal{margin-top:18px;border-top:1px solid var(--line);padding-top:16px;display:flex;flex-direction:column;gap:14px;}
.qr-jr-title{font-family:'Oxanium',sans-serif;font-size:13px;letter-spacing:1px;text-transform:uppercase;color:var(--amber);margin:0;}
.qr-jr-field{display:flex;flex-direction:column;gap:6px;}
.qr-jr-label{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:1px;color:var(--muted);}
.qr-jr-ta,.qr-jr-ioc{background:#06090c;border:1px solid var(--line);border-radius:8px;color:var(--txt);padding:9px 11px;font-family:'IBM Plex Sans',sans-serif;font-size:13px;line-height:1.5;resize:vertical;width:100%;}
.qr-jr-ta:focus,.qr-jr-ioc:focus{outline:none;border-color:var(--amber);}
.qr-jr-add{display:flex;gap:7px;flex-wrap:wrap;}
.qr-jr-add select{background:#06090c;border:1px solid var(--line);border-radius:7px;color:var(--txt);padding:8px 9px;font-family:'IBM Plex Sans',sans-serif;font-size:12.5px;flex:0 0 auto;}
.qr-jr-add input{flex:1;min-width:140px;background:#06090c;border:1px solid var(--line);border-radius:7px;color:var(--txt);padding:8px 11px;font-family:'IBM Plex Sans',sans-serif;font-size:12.5px;}
.qr-jr-add input:focus,.qr-jr-add select:focus{outline:none;border-color:var(--amber);}
.qr-jr-log{background:rgba(45,212,191,.1);border:1px solid rgba(45,212,191,.4);color:var(--teal);font-family:'IBM Plex Mono',monospace;font-size:11.5px;padding:8px 11px;border-radius:7px;cursor:pointer;white-space:nowrap;transition:.12s;}
.qr-jr-log:hover{background:var(--teal);color:#0a0e12;}
.qr-jr-list{display:flex;flex-direction:column;gap:6px;margin-top:8px;}
.qr-jr-entry{display:flex;gap:9px;align-items:flex-start;background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:8px 10px;}
.qr-jr-dot{width:9px;height:9px;border-radius:50%;margin-top:4px;flex:0 0 auto;box-shadow:0 0 7px currentColor;}
.qr-jr-entry-body{display:flex;flex-direction:column;gap:3px;flex:1;min-width:0;}
.qr-jr-entry-head{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--txt);}
.qr-jr-entry-note{font-size:12.5px;line-height:1.5;color:var(--muted);overflow-wrap:anywhere;}
.qr-jr-rm{background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px;flex:0 0 auto;}
.qr-jr-rm:hover{color:#ff3b4e;}
.qr-jr-links{display:flex;flex-wrap:wrap;gap:7px;margin-top:2px;}
.qr-jr-link{font-family:'IBM Plex Mono',monospace;font-size:11.5px;background:var(--panel2);border:1px solid var(--line);color:var(--teal);padding:5px 9px;border-radius:6px;text-decoration:none;transition:.12s;}
.qr-jr-link:hover{border-color:var(--teal);background:rgba(45,212,191,.08);}
.qr-jr-head{display:flex;justify-content:space-between;align-items:center;}
.qr-act-stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;}
.qr-act-stat{flex:1;min-width:80px;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:11px;text-align:center;}
.qr-act-stat-n{display:block;font-family:'Oxanium',sans-serif;font-weight:800;font-size:22px;line-height:1;color:var(--txt);}
.qr-act-stat-l{display:block;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-top:4px;letter-spacing:1px;}
.qr-act-list{display:flex;flex-direction:column;gap:6px;}
.qr-act-row{display:flex;gap:10px;align-items:flex-start;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:9px 12px;cursor:pointer;text-align:left;transition:.13s;}
.qr-act-row:hover{border-color:var(--amber);}
.qr-act-dot{width:9px;height:9px;border-radius:50%;margin-top:5px;flex:0 0 auto;box-shadow:0 0 7px currentColor;}
.qr-act-body{display:flex;flex-direction:column;gap:3px;flex:1;min-width:0;}
.qr-act-head{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--txt);}
.qr-act-date{color:var(--muted);}
.qr-act-hunt{font-family:'Oxanium',sans-serif;font-weight:600;color:var(--txt);}
.qr-act-note{font-size:12.5px;line-height:1.5;color:var(--muted);overflow-wrap:anywhere;}
.qr-query-head h4{font-family:'Oxanium',sans-serif;font-size:13px;letter-spacing:1px;text-transform:uppercase;color:var(--txt);margin:0;}
.qr-qsub{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);text-transform:none;letter-spacing:0;}
.qr-copy{background:var(--panel2);border:1px solid var(--line);color:var(--txt);font-family:'IBM Plex Mono',monospace;font-size:12px;padding:6px 12px;border-radius:6px;cursor:pointer;transition:.13s;}
.qr-copy:hover{border-color:var(--teal);color:var(--teal);}
.qr-code{background:#06090c;border:1px solid var(--line);border-left:3px solid var(--amber);border-radius:8px;padding:16px;font-family:'IBM Plex Mono',monospace;font-size:12.5px;line-height:1.65;color:#bfe9df;white-space:pre-wrap;word-break:break-word;overflow-x:auto;margin:0 0 14px;}
.qr-code.small{font-size:11px;max-height:260px;overflow-y:auto;}
.qr-disclaimer{font-size:11.5px;line-height:1.55;color:var(--muted);margin:0;border-top:1px dashed var(--line);padding-top:12px;}
.qr-disclaimer b{color:var(--txt);}
.qr-lint{margin:0 0 14px;display:flex;flex-direction:column;gap:4px;}
.qr-lint.ok{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--teal);opacity:.75;}
.qr-lint-head{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--teal);opacity:.8;margin-bottom:2px;}
.qr-lint-head.warn{color:var(--amber);opacity:1;}
.qr-lint-row{font-family:'IBM Plex Mono',monospace;font-size:11.5px;line-height:1.5;padding:5px 9px;border-radius:6px;}
.qr-lint-row.warn{background:rgba(255,140,42,.1);border:1px solid rgba(255,140,42,.35);color:var(--amber);}
.qr-lint-row.info{background:var(--panel2);border:1px solid var(--line);color:var(--muted);}
.qr-conn-note{font-family:'IBM Plex Mono',monospace;font-size:11.5px;line-height:1.55;color:var(--amber);background:rgba(245,166,35,.06);border-left:2px solid var(--amber);padding:9px 12px;margin:0 0 14px;border-radius:0 6px 6px 0;}
.qr-busy-hint{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--teal);background:rgba(45,212,191,.06);border:1px dashed rgba(45,212,191,.35);padding:9px 12px;border-radius:7px;margin:10px 0 0;line-height:1.55;}
.qr-coverage{display:grid;grid-template-columns:1fr;gap:20px;padding:22px;max-width:1400px;margin:0 auto;animation:qr-rise .4s var(--ease) both;}
.qr-card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:var(--radius-lg);padding:20px;box-shadow:var(--shadow);}
.qr-card-h{font-family:'Oxanium',sans-serif;font-size:16px;margin:0 0 6px;color:#fff;letter-spacing:.5px;}
.qr-card-sub{font-size:12.5px;color:var(--muted);line-height:1.55;margin:0 0 14px;}
.qr-cov-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;}
.qr-matrix{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-bottom:18px;}
.qr-col{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:8px;min-height:90px;}
.qr-col.gap{border-style:dashed;opacity:.7;}
.qr-col.has{border-color:#2c3a46;}
.qr-col-head{display:flex;justify-content:space-between;align-items:center;font-family:'Oxanium',sans-serif;font-size:11px;color:var(--txt);margin-bottom:8px;line-height:1.2;}
.qr-col-n{font-family:'IBM Plex Mono',monospace;background:rgba(245,166,35,.16);color:var(--amber);border-radius:4px;padding:1px 6px;font-size:11px;}
.qr-col-body{display:flex;flex-wrap:wrap;gap:4px;}
.qr-cell{font-family:'IBM Plex Mono',monospace;font-size:9.5px;background:#06090c;border:1px solid;border-radius:4px;padding:2px 5px;color:#bfe9df;}
.qr-cell-n{opacity:.55;}
.qr-cell-empty{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);}
.qr-gaps{border-top:1px solid var(--line);padding-top:14px;}
.qr-gaps h4{font-family:'Oxanium',sans-serif;font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--amber);margin:0 0 10px;}
.qr-kev-list{display:flex;flex-direction:column;gap:8px;}
.qr-kev-row{display:flex;align-items:center;gap:12px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;}
.qr-kev-row.gap{border-left:3px solid var(--amber);}
.qr-kev-row.ok{border-left:3px solid var(--teal);opacity:.8;}
.qr-kev-flag{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:3px 7px;border-radius:5px;white-space:nowrap;flex:0 0 auto;}
.qr-kev-flag.gap{background:rgba(245,166,35,.14);color:var(--amber);}
.qr-kev-flag.ok{background:rgba(45,212,191,.14);color:var(--teal);}
.qr-kev-body{display:flex;flex-direction:column;gap:2px;flex:1;min-width:0;}
.qr-kev-cve{font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--txt);font-weight:600;}
.qr-kev-prod{color:var(--muted);font-weight:400;}
.qr-kev-desc{font-size:12px;color:var(--muted);line-height:1.45;}
.qr-kev-draft{background:linear-gradient(90deg,rgba(245,166,35,.16),rgba(245,166,35,.06));border:1px solid var(--amber);color:var(--amber);font-family:'Oxanium',sans-serif;font-weight:700;font-size:12px;padding:7px 11px;border-radius:7px;cursor:pointer;white-space:nowrap;flex:0 0 auto;transition:.13s;}
.qr-kev-draft:hover{background:var(--amber);color:#0a0e12;}
.qr-kev-prov{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);margin-bottom:12px;display:flex;align-items:center;}
.qr-prov-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;}
.qr-prov-dot.ok{background:var(--teal);box-shadow:0 0 8px var(--teal);}
.qr-prov-dot.warn{background:var(--amber);box-shadow:0 0 8px var(--amber);}
.qr-kev-ransom{font-family:'IBM Plex Mono',monospace;font-size:9px;letter-spacing:1px;text-transform:uppercase;background:rgba(255,59,78,.16);color:#ff6b78;padding:2px 6px;border-radius:4px;margin-left:8px;vertical-align:middle;}
.qr-kev-date{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-left:8px;font-weight:400;}
.qr-readiness{display:flex;gap:24px;margin-bottom:16px;}
.qr-ready-stat{display:flex;flex-direction:column;}
.qr-big-n{font-family:'Oxanium',sans-serif;font-weight:800;font-size:30px;line-height:1;color:#fff;}
.qr-ready-stat span:last-child{font-size:11px;color:var(--muted);font-family:'IBM Plex Mono',monospace;margin-top:4px;}
.qr-tele-toggles{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;}
.qr-tele{display:flex;align-items:center;gap:8px;background:var(--panel2);border:1px solid var(--line);color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:12px;padding:7px 11px;border-radius:7px;cursor:pointer;transition:.13s;}
.qr-tele.on{border-color:var(--teal);color:var(--txt);}
.qr-tele-box{width:15px;height:15px;border:1px solid var(--line);border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--teal);}
.qr-tele.on .qr-tele-box{border-color:var(--teal);background:rgba(45,212,191,.12);}
.qr-blind{border-top:1px solid var(--line);padding-top:14px;}
.qr-blind h4{font-family:'Oxanium',sans-serif;font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--amber);margin:0 0 10px;}
.qr-blind-row{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px solid rgba(29,39,48,.5);font-size:12.5px;flex-wrap:wrap;}
.qr-blind-name{color:var(--txt);}
.qr-blind-need{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--amber);}
.qr-forge{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding:22px;max-width:1400px;margin:0 auto;align-items:start;animation:qr-rise .4s var(--ease) both;}
@media(max-width:1000px){.qr-forge{grid-template-columns:1fr;}}
.qr-forge-col{display:flex;flex-direction:column;gap:18px;}
.qr-mode-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;}
.qr-link{color:var(--teal);text-decoration:none;border-bottom:1px dotted var(--teal);}
.qr-link:hover{color:#5fe6d4;}
.qr-seed-chip{background:rgba(45,212,191,.08);border:1px dashed rgba(45,212,191,.5);color:var(--teal);font-family:'IBM Plex Mono',monospace;font-size:11.5px;padding:7px 11px;border-radius:7px;cursor:pointer;margin-bottom:12px;transition:.13s;text-align:left;}
.qr-seed-chip:hover{background:rgba(45,212,191,.16);border-style:solid;}
.qr-mode{flex:1 1 auto;min-width:96px;background:var(--panel2);border:1px solid var(--line);color:var(--muted);font-family:'Oxanium',sans-serif;font-weight:600;font-size:12.5px;padding:9px;border-radius:7px;cursor:pointer;transition:.13s;}
.qr-mode.on{border-color:var(--amber);color:var(--amber);background:rgba(245,166,35,.08);}
.qr-ta{width:100%;background:#06090c;border:1px solid var(--line);border-radius:8px;color:var(--txt);padding:12px;font-family:'IBM Plex Sans',sans-serif;font-size:13px;line-height:1.5;resize:vertical;margin-bottom:12px;}
.qr-url-input{width:100%;background:#06090c;border:1px solid var(--line);border-radius:8px;color:var(--txt);padding:10px 12px;font-family:'IBM Plex Mono',monospace;font-size:12px;margin-bottom:10px;}
.qr-url-input:focus{outline:none;border-color:var(--amber);}
.qr-ta.mono{font-family:'IBM Plex Mono',monospace;font-size:12px;color:#bfe9df;}
.qr-ta:focus{outline:none;border-color:var(--amber);}
.qr-btn-row{display:flex;gap:10px;}
.qr-prev-plats{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:10px;}
.qr-mini-pill{background:var(--panel2);border:1px solid var(--line);color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:11px;padding:5px 9px;border-radius:6px;cursor:pointer;transition:.13s;}
.qr-mini-pill.on{border-color:var(--amber);color:var(--amber);}
.qr-prev-actions{display:flex;gap:10px;margin-top:6px;}
.qr-prev-actions .qr-cta{width:auto;flex:1;}
.qr-summary{background:rgba(45,212,191,.08);border:1px solid rgba(45,212,191,.35);border-radius:10px;padding:14px 16px;margin-bottom:16px;}
.qr-summary b{font-family:'Oxanium',sans-serif;font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--teal);}
.qr-summary p{margin:6px 0 0;font-size:13px;line-height:1.6;color:var(--txt);}
.qr-ph-steps{display:flex;flex-direction:column;gap:14px;text-align:left;margin-top:8px;width:100%;max-width:460px;}
.qr-ph-step{display:flex;gap:12px;align-items:flex-start;}
.qr-ph-num{flex:0 0 auto;width:22px;height:22px;border-radius:50%;border:1px solid var(--teal);color:var(--teal);font-family:'IBM Plex Mono',monospace;font-size:11px;display:flex;align-items:center;justify-content:center;margin-top:2px;}
.qr-ph-step b{display:block;font-family:'Oxanium',sans-serif;font-size:13px;color:var(--txt);margin-bottom:3px;}
.qr-ph-step span{display:block;font-size:12px;color:var(--muted);line-height:1.55;}
.qr-ph-hint{margin:6px 0 0;font-size:12px;color:var(--muted);line-height:1.6;max-width:460px;}
.qr-ph-hint b{color:var(--teal);}
.qr-footer-badge{display:inline-block;margin-right:10px;padding:3px 9px;border:1px solid rgba(245,166,35,.45);border-radius:5px;color:var(--amber);font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:1.5px;vertical-align:1px;}
.qr-live{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0;}
.qr-placeholder{background:var(--panel2);border:1px dashed var(--line);border-radius:11px;padding:50px 24px;text-align:center;display:flex;flex-direction:column;align-items:center;gap:14px;}
.qr-placeholder p{color:var(--muted);font-size:13.5px;line-height:1.6;margin:0;}
.qr-empty-cta{margin-top:14px;padding:16px;border:1px dashed rgba(45,212,191,.28);border-radius:10px;background:rgba(45,212,191,.04);}
.qr-empty-cta p{margin:0 0 12px;font-size:13px;color:var(--muted);font-style:italic;}
.qr-empty-cta .qr-cta{width:auto;padding:10px 18px;}
.qr-empty-cta span{display:block;margin-top:10px;font-size:11.5px;color:var(--muted);line-height:1.55;}
.qr-ai-off{background:rgba(245,166,35,.08);border:1px solid rgba(245,166,35,.35);color:#e8c98a;font-size:12.5px;padding:11px 14px;border-radius:8px;margin-bottom:12px;line-height:1.55;}
.qr-ai-off b{color:var(--amber);}
.qr-ai-off code{font-family:'JetBrains Mono',monospace;font-size:11.5px;background:rgba(0,0,0,.3);padding:1px 5px;border-radius:4px;color:#f5d9a0;}
.qr-err{background:rgba(255,59,78,.1);border:1px solid rgba(255,59,78,.4);color:#ff8c97;font-size:12.5px;padding:11px 14px;border-radius:8px;margin-bottom:16px;line-height:1.5;}
.qr-footer{text-align:center;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);padding:18px;border-top:1px solid var(--line);letter-spacing:1px;margin-top:10px;}
.qr-root button:focus-visible,.qr-root a:focus-visible,.qr-root select:focus-visible,.qr-root input:focus-visible,.qr-root textarea:focus-visible{outline:2px solid var(--teal);outline-offset:2px;border-radius:6px;}
.qr-root button:focus:not(:focus-visible){outline:none;}

/* ============================================================
   NARROW VIEWPORTS

   The grid breakpoints above already collapse to a single column, but the page still
   scrolled sideways on a phone: the header is a non-wrapping flex row, the tab bar's
   buttons are wider than the viewport, and grid children default to min-width:auto,
   so a long query line forces the whole track wider than the screen.
   ============================================================ */

/* Grid and flex children may shrink below their content width; long queries scroll
   inside their own <pre> rather than widening the page. */
.qr-hunts > *, .qr-forge > *, .qr-landscape > *, .qr-detail, .qr-list, .qr-rail { min-width: 0; }
.qr-root { overflow-x: hidden; }

@media(max-width:820px){
  .qr-header{flex-direction:column;align-items:stretch;gap:14px;padding:16px 14px;}
  .qr-brand{gap:11px;}
  .qr-brand h1{font-size:19px;letter-spacing:4px;}
  .qr-logo{font-size:26px;}
  .qr-ent-pick{align-items:stretch;width:100%;}
  .qr-ent-row{width:100%;}
  .qr-ent-row select{flex:1 1 auto;min-width:0;}

  /* Horizontal scroll belongs to the tab strip, not the document. */
  .qr-tabs{flex-wrap:nowrap;overflow-x:auto;padding:0 12px;gap:2px;-webkit-overflow-scrolling:touch;scrollbar-width:none;}
  .qr-tabs::-webkit-scrollbar{display:none;}
  .qr-tabs button{white-space:nowrap;font-size:12.5px;padding:13px 11px;letter-spacing:.5px;}

  .qr-landscape,.qr-hunts,.qr-forge{padding:14px;gap:14px;}
  .qr-profile{padding:18px;}
  .qr-profile h2{font-size:21px;}
  .qr-list{max-height:none;}
  .qr-code{font-size:11.5px;padding:13px;}
  .qr-btn-row{flex-wrap:wrap;}
  .qr-modal{width:calc(100vw - 24px);max-width:none;}
}

@media(max-width:520px){
  .qr-brand h1{font-size:17px;letter-spacing:3px;}
  .qr-kev-row{flex-direction:column;align-items:flex-start;gap:6px;}
  .qr-jr-add{flex-direction:column;align-items:stretch;}
  .qr-prev-actions{flex-direction:column;}
  .qr-empty-cta .qr-cta{width:100%;}
}

@media (prefers-reduced-motion: reduce){
  .qr-root *,.qr-root *:before,.qr-root *:after{animation-duration:.001ms !important;animation-iteration-count:1 !important;transition-duration:.001ms !important;}
  .qr-header,.qr-tabs,.qr-landscape,.qr-hunts,.qr-coverage,.qr-forge{animation:none !important;}
  .qr-tabs button.on:after{animation:none !important;display:none;}
}
`;
