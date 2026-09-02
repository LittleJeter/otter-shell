# Otter Shell — Hunt Validation Script

This is the afternoon checklist that turns "syntactically valid" into "I ran these on a real platform and here's the evidence." Work through it for the 4 demo hunts below and you'll be able to say, truthfully and specifically, that the tool's output detects the techniques it claims.

**What "validated" means here** (three levels, matching the in-app Validation field):
- **Syntax** — the query parses in the platform's editor without error. Cheapest; proves it's well-formed.
- **Ran** — the query executes against real telemetry and returns sane results (no field/schema errors). Proves it works on that platform's data model.
- **Atomic** — the query catches a real [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) execution of the technique. Proves it's a true-positive detection, not just valid syntax. **This is the level that convinces a detection engineer.**

Record the result for each in the tool: open the hunt → Lifecycle panel → **VALIDATION** → pick the level and enter the platform/method. Then export the hunt's markdown report — the provenance travels with it.

---

## Setup (one-time, ~30 min)

**Pick one SIEM to start.** You don't need all of them. Recommended order by ease of free-tier setup:

1. **Splunk** — [Splunk Free](https://www.splunk.com/en_us/download/splunk-enterprise.html) (single instance, 500 MB/day) or [Splunk Cloud trial](https://www.splunk.com/en_us/download/splunk-cloud-platform.html) (14 days). Install the [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709) and [Windows TA](https://splunkbase.splunk.com/app/742).
2. **Microsoft Sentinel / Defender** — [Azure free trial](https://azure.microsoft.com/free/) → create a Log Analytics workspace → enable Sentinel (free for 31 days on new workspaces). This also lets you **empirically confirm the M365-Defender-connector finding** (below).
3. **Elastic** — [Elastic Cloud trial](https://www.elastic.co/cloud/cloudtrial) (14 days). Ship Windows logs with [Elastic Agent](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html) + the Windows integration.

**Stand up one test endpoint** — a throwaway Windows 10/11 VM (Hyper-V, VirtualBox, or a cloud VM) with:
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) installed with [SwiftOnSecurity's config](https://github.com/SwiftOnSecurity/sysmon-config) (gives you process-creation with command lines).
- Your chosen SIEM's log shipper pointed at it.
- [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam) installed (`Install-Module invoke-atomicredteam`). **Run atomics only in the isolated VM, never on a production or personal machine** — they execute real (benign) attacker behavior and some leave artifacts.

**The connector caveat that matters for Sentinel** — the `DeviceProcessEvents` table used by ps-enc / lolbin-download / webshell is a **Defender XDR** table. It only appears in Sentinel if the Microsoft 365 Defender connector is enabled. When you run those three in Sentinel, note whether the table resolves — that empirically confirms (or refutes) the tool's deployment note, which is itself a credibility point ("I found and documented this dependency").

---

## Demo Hunt 1 — Encoded / Base64 PowerShell (`ps-enc`, T1059.001)

**Atomic test to run first:** `T1059.001` test #1 or #2 (encoded command).
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1,2
```
This runs `powershell.exe` with an encoded/Base64 command — exactly what the hunt looks for.

**Then run the hunt query.**

### Splunk
```
index=edr process_name IN ("powershell.exe","powershell_ise.exe")
  (command_line="*-enc*" OR command_line="*FromBase64String*")
| table _time host user parent_process_name command_line
```
> Adjust `index=edr` to your actual index (e.g. `index=main` or `index=sysmon`), and confirm your Sysmon sourcetype maps `CommandLine`→`command_line` (the Splunk Sysmon TA does this). If your field is `Processes.process` (CIM/datamodel), swap accordingly.

### Sentinel / Defender (same KQL)
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe","powershell_ise.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```
> In **Defender XDR** advanced hunting this runs as-is. In **Sentinel** it requires the M365 Defender connector (see caveat above). If you don't have it, the Sentinel-native equivalent is `SecurityEvent | where EventID == 4688` with `CommandLine` (needs process-creation auditing + command-line logging GPO enabled).

### Elastic (ES|QL)
```esql
FROM logs-*
| WHERE event.category == "process" AND process.name IN ("powershell.exe","powershell_ise.exe")
  AND (process.command_line LIKE "*-enc*" OR process.command_line LIKE "*FromBase64String*")
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| LIMIT 200
```

**Expected result:** one or more rows showing your VM's hostname, the user, and the encoded `powershell.exe` command line from the atomic run. **Correct = the atomic execution appears.** If you get zero rows, check: is process-creation logging on? does your index/table actually have the data? is the command-line field populated?

**Record:** `ran` if it executes and returns your normal PowerShell activity cleanly; `atomic` if it catches the Atomic Red Team run.

---

## Demo Hunt 2 — LOLBin Remote Payload Download (`lolbin-download`, T1105)

**Atomic test:** `T1105` has several certutil/bitsadmin download tests.
```powershell
Invoke-AtomicTest T1105 -TestNumbers 1,6,9   # certutil, bitsadmin, curl variants (check `-ShowDetails` first)
```
Run `Invoke-AtomicTest T1105 -ShowDetailsBrief` to see which test numbers map to certutil/bitsadmin/curl on your OS.

### Splunk
```
index=edr process_name IN ("certutil.exe","bitsadmin.exe","mshta.exe","curl.exe","wget.exe")
  (command_line="*http://*" OR command_line="*https://*")
| table _time host user process_name command_line
```

### Sentinel / Defender
```kql
DeviceProcessEvents
| where FileName in~ ("certutil.exe","bitsadmin.exe","mshta.exe","curl.exe","wget.exe")
| where ProcessCommandLine has_any ("http://","https://","ftp://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Elastic
```esql
FROM logs-*
| WHERE event.category == "process"
  AND process.name IN ("certutil.exe","bitsadmin.exe","mshta.exe","curl.exe","wget.exe")
  AND (process.command_line LIKE "*http://*" OR process.command_line LIKE "*https://*" OR process.command_line LIKE "*ftp://*")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
```

**Expected result:** rows showing `certutil.exe` / `bitsadmin.exe` with an `http(s)://` URL in the command line from the atomic run. **This one is prone to false positives** in real environments (legit `curl` in scripts, `certutil` for cert operations) — that's expected and is exactly what the hunt's FP-tuning note calls out. For validation you only care that the atomic run is caught.

**Record:** `atomic` if the download atomic appears.

---

## Demo Hunt 3 — Impossible Travel (`impossible-travel`, T1078)

**No Atomic test for this one** — it's an identity/cloud analytic, not an endpoint behavior. Validate at the `ran` level against real sign-in logs, or simulate.

**How to get data:** if you have any Entra ID / Azure AD sign-in logs flowing (even from your own trial tenant logging in from your normal location), the query will run. To *simulate* impossible travel: sign in to the trial tenant, then sign in again through a VPN exit in another country within the same hour.

### Sentinel
```kql
SigninLogs
| where ResultType == 0
| summarize Countries=make_set(LocationDetails.countryOrRegion) by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
```

### Defender
```kql
AADSignInEventsBeta
| where ErrorCode == 0
| summarize Countries=make_set(Country) by AccountUpn, bin(Timestamp, 1h)
| where array_length(Countries) > 1
```

### Splunk (needs Azure AD add-on)
```
index=azuread sourcetype="azure:aad:signin" status.errorCode=0
| bucket _time span=1h
| stats dc(location.countryOrRegion) as geos values(location.countryOrRegion) as countries by user _time
| where geos > 1
```

**Expected result:** at the `ran` level, the query executes without schema errors and returns zero rows for normal single-location activity (correct — no impossible travel happened). After the VPN simulation, it returns one row with two countries. **Note:** production impossible-travel detection should account for VPNs/corporate egress; this is a starting point, which the tool states.

**Record:** `ran` (executes cleanly against real sign-in schema) or `atomic`-equivalent if you catch the VPN simulation — annotate the method as "sign-in simulation" since there's no ART test.

---

## Demo Hunt 4 — Web Shell (`webshell`, T1505.003)

**Atomic test:** `T1505.003` drops web shells (requires IIS/Apache on the test box).
```powershell
Invoke-AtomicTest T1505.003 -ShowDetailsBrief   # pick a test matching your web server
```
Simpler alternative if you don't want to stand up IIS: manually reproduce the signal — from a running web-server process context, spawn `cmd.exe`. The hunt detects *any* web-server process spawning a shell, so even a benign manual reproduction validates the logic.

### Splunk
```
index=edr parent_process_name IN ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat.exe","java.exe")
  process_name IN ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| table _time host parent_process_name process_name command_line
```

### Sentinel / Defender
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat.exe","java.exe")
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Elastic
```esql
FROM logs-*
| WHERE event.category == "process"
  AND process.parent.name IN ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat.exe","java.exe")
  AND process.name IN ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| KEEP @timestamp, host.name, process.parent.name, process.name, process.command_line
```

**Expected result:** a row showing a web-server process as parent and a shell as child. This is a **high-signal, low-FP** detection — in a healthy environment it should return nothing until you reproduce the behavior, which is what makes it a good demo (clean baseline → fire on the test).

**Record:** `atomic` if the ART test or manual web-shell reproduction is caught.

---

## After you've run them

You'll have, for each demo hunt, a specific factual claim you can defend:
- *"ps-enc: validated at Atomic level on Splunk — caught Invoke-AtomicTest T1059.001."*
- *"webshell: validated at Atomic level on Defender — caught a web-server-spawns-shell reproduction."*
- *"impossible-travel: validated at Ran level on Sentinel — executes against real SigninLogs schema."*

Set each hunt's in-app Validation field accordingly, export the program report (Coverage tab → program report), and that markdown becomes your evidence artifact. On the repo, a short `## Validation` section listing these results — with the platform and the Atomic test IDs — is what converts "I built a hunt tool" into "I built and validated detections."

**One honest framing note for the resume / README:** say "validated the demo hunts against [platforms] using Atomic Red Team" — scoped to what you actually ran. Don't generalize to "all 18 hunts validated" unless you run all 18. The specific, smaller claim is stronger because it's bulletproof.

---

## Software-correctness validation (separate from hunt validation)

The above proves the *hunts* work. To prove the *software* works — for the same "legit" claim — the ported repo should carry the test suite specified in `migration/04_TEST_PLAN.md` running in CI:
- Sigma round-trip (all 18 hunts export → re-import clean)
- Lint zero-false-positives invariant on all curated queries
- KEV matching against real-CVE fixtures
- The bug-fix regressions (ID uniqueness, import dedup, JSON extraction, prototype-pollution guard)

A green CI badge on the repo is third-party-legible proof of software correctness, the same way the Atomic results are proof of detection correctness. Together they cover both meanings of "does it work."
