---
title: "Suspicious PowerShell Execution"
part: 8
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 8 — Suspicious PowerShell Execution

## Why this part exists

**[CONCEPT]** PowerShell sits at almost every stage of a modern intrusion because it is already installed, already trusted by administrators, and capable of doing everything from downloading a second-stage payload to dumping credentials without ever writing an executable to disk. This part covers the shapes of PowerShell *invocation itself* that a hunter should treat as suspicious independent of what the script ultimately does: commands encoded or obfuscated to defeat casual review, one-liners that fetch and immediately execute remote content, invocations that patch or bypass AMSI before running, and script-block content matching known offensive-tooling markers. DEH Part 10 (PowerShell Detection Engineering) owns the telemetry mechanics this part assumes — how Event ID 4104 (PowerShell Script Block Logging) differs from Event ID 4103 (Module Logging), why script-block logging can span multiple log records for one script, and how AMSI's provider architecture creates the specific bypass surface QC-08-04 hunts. DEH Part 40's seeded naive-rule teardown of "PowerShell execution = malicious" is the standing warning behind every `[FALSE POSITIVE]` entry below: PowerShell is default tooling for SCCM, Intune, DSC, Exchange Management Shell, and most third-party RMM platforms, so every pattern here targets a specific invocation *shape*, never bare `powershell.exe` execution.

This part's boundary against its neighbors is deliberate. Part 9 (LOLBins & Living-off-the-Land Execution) owns non-PowerShell binary abuse (`rundll32`, `mshta`, `certutil`) even when a PowerShell cradle hands off to one of them — the hand-off itself is this part's pivot target, not its query target. Part 10 (Suspicious Scripting Hosts & Macro Execution) owns the Office-macro or WSH process that *launches* PowerShell as a child; this part starts at the PowerShell process itself, regardless of what spawned it. Part 16 (Lateral Movement via Admin Tools & Remote Services) owns PowerShell *remoting* (WinRM) as a lateral-movement mechanism between hosts; this part's patterns fire on the local invocation shape and apply equally whether that invocation arrived via remoting, a scheduled task, or an interactive session.

---

### QC-08-01 — Base64-encoded command-line invocation

| Field | Value |
|---|---|
| **Pattern ID** | `QC-08-01` |
| **MITRE** | T1027.010 (Obfuscated Files or Information: Command Obfuscation) |
| **Behavior** | PowerShell launched with a Base64-encoded argument via `-EncodedCommand` or an ambiguous abbreviation of it. |
| **DEH cross-ref** | DEH Part 10 §1 (PowerShell telemetry sources — command-line vs. script-block logging) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) |

**[HUNTER]** Attackers and off-the-shelf offensive tooling frequently launch PowerShell with `-EncodedCommand` (or an ambiguous abbreviation like `-e`, `-en`, `-enc`) to avoid embedding recognizable cmdlet names in a command line a simple string match might catch, and to survive the quoting limits of a macro, scheduled task, or registry Run key that would otherwise mangle special characters. A hunt beats waiting on a standing detection here because the encoded flag itself is rare enough on most fleets that a hunter can review a day's hits by hand and decode each payload inline, surfacing intent immediately rather than waiting on a slower detection-engineering cycle.

**[QUERY] Sigma** — targets Sysmon Event ID 1 (Process Create) or Windows Security Event ID 4688 (A new process has been created), normalized into Sigma's `process_creation` category.

CONCEPTUAL SAMPLE — field names and regex illustrative; validate against your own command-line normalization before use.

```yaml
title: PowerShell Invoked With an Encoded Command Flag
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flag:
    CommandLine|re: '(?i)[\-/]e[a-z]{0,15}\s'
  condition: selection_process and selection_flag
falsepositives:
  - See [FALSE POSITIVE] below.
level: medium
```

Expected result: a match returns the full command line including the flag variant used and the Base64 blob itself; on a fleet running routine RMM or SCCM deployment, this pattern might plausibly return anywhere from a handful to several hundred hits a day, most sharing a small number of parent processes. Interpretation: a hit is consistent with an attempt to obscure command content from casual review, not confirmation of malicious intent — the decoded payload and parent chain carry the actual signal.

**[QUERY] KQL (Sentinel/Defender)** — Microsoft Defender for Endpoint's `DeviceProcessEvents` table, or Sentinel's equivalent via the Defender XDR connector.

CONCEPTUAL SAMPLE — field names and regex illustrative; validate against your own schema before use.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @'(?i)[\-/]e[a-z]{0,15}\s'
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

Expected result: same shape as the Sigma block, with `InitiatingProcessFileName` added to make parent-process triage immediate. Interpretation: identical to the Sigma block above — this is the same analytic on a different backend, not a different claim.

**[QUERY] SPL** — Splunk over Sysmon `EventCode=1`, falling back to Windows Security `EventCode=4688` where Sysmon isn't deployed.

CONCEPTUAL SAMPLE — field names and regex illustrative; validate against your own index and sourcetype naming.

```spl
index=win_events (sourcetype="WinEventLog:Sysmon" EventCode=1) OR (sourcetype="WinEventLog:Security" EventCode=4688)
| search Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR New_Process_Name="*\\powershell.exe" OR New_Process_Name="*\\pwsh.exe"
| regex CommandLine="(?i)[\-/]e[a-z]{0,15}\s"
| table _time, host, User, CommandLine, ParentImage
```

Expected result: a table of hits spanning both telemetry sources, useful for fleets running a mix of Sysmon-instrumented and unmanaged hosts. Interpretation: unchanged from above.

**[QUERY] AQL (QRadar)** — this is AQL, not standard SQL; QRadar's `events` view over a WinCollect-normalized process-creation source.

CONCEPTUAL SAMPLE — property names illustrative; validate the "Command Line" custom property exists for your WinCollect source before use.

```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
       "Process Name" AS ProcessName,
       "Command Line" AS CommandLine,
       username
FROM events
WHERE ("Process Name" ILIKE '%powershell.exe%' OR "Process Name" ILIKE '%pwsh.exe%')
  AND "Command Line" MATCHES '(?i).*[\-/]e[a-z]{0,15}\s.*'
  AND devicetime > NOW() - 1 DAY
```

Expected result: identical logic to the above, gated entirely on whether your QRadar deployment has a mapped "Command Line" custom property — see [FALSE POSITIVE] below for what happens when it doesn't. Interpretation: unchanged from above.

**[QUERY] YARA-L (Google SecOps)** — UDM `PROCESS_LAUNCH` events, matching on `target.process.command_line`.

CONCEPTUAL SAMPLE — UDM field paths and regex illustrative; validate against your own parser's field mapping.

```yaral
rule powershell_encoded_command_flag {
  meta:
    description = "PowerShell launched with an encoded/abbreviated -EncodedCommand flag"
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /(?i)(powershell\.exe|pwsh\.exe)$/
    $e.target.process.command_line = /(?i)[\-\/]e[a-z]{0,15}\s/
  condition:
    $e
}
```

Expected result: unchanged in shape from the other backends. Interpretation: unchanged from above.

**[QUERY] Elastic (KQL)** — a single-event boolean match, so this uses Elastic KQL rather than EQL per the single-event decision rule; Elastic KQL has no regex operator, so this trades the other backends' single regex for an explicit list of common flag abbreviations.

CONCEPTUAL SAMPLE — wildcard list illustrative and looser than the regex used elsewhere; validate coverage against your own observed flag usage.

```kql
process.name : ("powershell.exe" or "pwsh.exe") and process.command_line : ("*-enc*" or "*-encodedcommand*" or "*-e *" or "*-ec*")
```

Expected result: a superset of the regex-based hits above, plus some the regex misses and some extra noise the wildcard list can't filter as precisely. Interpretation: treat a hit here as slightly lower-confidence than the regex-based backends until the flag context is confirmed.

**[FALSE POSITIVE]** `-EncodedCommand`'s abbreviation space collides with `-ExecutionPolicy`'s — both start with `-e`, so a regex anchored only on the letter `e` after the dash also matches `-ep bypass` or `-exec unrestricted`, which appears in nearly every RMM and CI/CD PowerShell invocation. Tighten the regex to require the payload look like Base64 (a long run of `[A-Za-z0-9+/=]` with no spaces) rather than trusting the flag name alone, and expect the untightened version to fire heavily on SCCM (parent `CcmExec.exe`), Intune's `IntuneManagementExtension.exe`, and any Ansible `win_shell`/`win_command` task — dozens to hundreds of times per patch cycle on a managed fleet. The AQL block above additionally depends on a normalized "Command Line" custom property existing for the WinCollect source; where it doesn't, the same regex has to run against the raw payload field instead, which is slower and easier to evade with encoding tricks in the raw log.

**[PIVOT]** Decode the Base64 blob (typically UTF-16LE) and re-run its content against QC-08-03's download-cradle markers and QC-08-04's AMSI-bypass markers — an encoded command that itself contains a fetch-and-execute pair or an `AmsiUtils` reference is a far stronger signal than the flag alone. Also check the immediate parent process (Sysmon Event ID 1's `ParentImage`) against Part 10's macro-execution patterns when the parent is `winword.exe` or `excel.exe`.

---

### QC-08-02 — Command-line obfuscation without an encoding flag

| Field | Value |
|---|---|
| **Pattern ID** | `QC-08-02` |
| **MITRE** | T1027.010 (Obfuscated Files or Information: Command Obfuscation) |
| **Behavior** | PowerShell command line obfuscated via backtick-splitting, character-code arrays, or `-join`/`-f`/`-bxor` reassembly, without the `-EncodedCommand` flag QC-08-01 targets. |
| **DEH cross-ref** | DEH Part 10 §1; cf. DEH Part 40 (seeded teardown, "PowerShell execution = malicious") |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (EQL) |

**[HUNTER]** Not every obfuscation attempt bothers with `-EncodedCommand` — backtick-splitting a cmdlet name (`` I`E`X ``), building a string from a `[char]` array, or reassembling a command with `-join`/`-f` defeats the same naive string-matching without tripping QC-08-01's flag-based signal at all. This pattern hunts the command line for the structural markers of that obfuscation, not any one tool's signature, since these techniques are shared across PowerSploit-derived frameworks, red-team tradecraft, and copy-pasted forum one-liners alike.

**[QUERY] Sigma** — Sysmon Event ID 1 / Event ID 4688 process creation.

CONCEPTUAL SAMPLE — regex encodes a snapshot of known idioms, not obfuscation as a concept; validate and expect to extend it.

```yaml
title: PowerShell Command Line With String Obfuscation Markers
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_obfuscation:
    CommandLine|re: '(?i)(`[a-z]){2,}|\[char\](\[\d{1,3}\]\s*){3,}|-join\s*\(|-bxor\s|-f\s*@\('
  condition: selection_process and selection_obfuscation
falsepositives:
  - See [FALSE POSITIVE] below.
level: medium
```

Expected result: a match surfaces a command line built from unusual punctuation density rather than any recognizable cmdlet name. Interpretation: consistent with an attempt to defeat casual string review; expect to read the flagged line by hand since the point of this obfuscation is that it doesn't look like PowerShell.

**[QUERY] KQL (Sentinel/Defender)** — `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — regex illustrative; validate against your own schema.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @'(?i)(`[a-z]){2,}|\[char\](\[\d{1,3}\]\s*){3,}|-join\s*\(|-bxor\s|-f\s*@\('
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

Expected result and interpretation: unchanged from the Sigma block.

**[QUERY] SPL** — Sysmon `EventCode=1`.

CONCEPTUAL SAMPLE — regex illustrative; validate against your own field extraction.

```spl
index=win_events sourcetype="WinEventLog:Sysmon" EventCode=1
| search Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| regex CommandLine="(?i)(`[a-z]){2,}|\[char\](\[\d{1,3}\]\s*){3,}|-join\s*\(|-bxor\s|-f\s*@\("
| table _time, host, User, CommandLine
```

Expected result and interpretation: unchanged from above.

**[QUERY] AQL (QRadar)** — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — property names and regex illustrative.

```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS EventTime, "Command Line" AS CommandLine, username
FROM events
WHERE ("Process Name" ILIKE '%powershell.exe%' OR "Process Name" ILIKE '%pwsh.exe%')
  AND "Command Line" MATCHES '(?i).*(`[a-z]){2,}.*|.*\[char\](\[\d{1,3}\]\s*){3,}.*|.*-join\s*\(.*|.*-bxor\s.*|.*-f\s*@\(.*'
```

Expected result and interpretation: unchanged from above, subject to the same custom-property dependency noted in QC-08-01.

**[QUERY] YARA-L (Google SecOps)** — UDM `PROCESS_LAUNCH`.

CONCEPTUAL SAMPLE — regex illustrative; validate against your parser's field mapping.

```yaral
rule powershell_string_obfuscation_markers {
  meta:
    description = "PowerShell command line built from backtick-split, char-array, join, or format-operator obfuscation"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /(?i)(powershell\.exe|pwsh\.exe)$/
    $e.target.process.command_line = /(?i)(`[a-z]){2,}|\[char\](\[\d{1,3}\]\s*){3,}|-join\s*\(|-bxor\s|-f\s*@\(/
  condition:
    $e
}
```

Expected result and interpretation: unchanged from above.

**[QUERY] Elastic (EQL)** — Elastic KQL has no regex operator, so this single-event match uses EQL's `match()` function instead; a regex-dependent single-event shape DEH Appendix A5's decision table doesn't score against KQL vs. EQL, so this book's own Appendix A5 logs the gap rather than asserting it's settled. `match()`'s availability depends on your Elastic Stack version — confirm before relying on it.

CONCEPTUAL SAMPLE — regex illustrative; validate `match()` availability on your Stack version.

```eql
process where process.name in ("powershell.exe", "pwsh.exe") and
  match(process.command_line,
    "(?i)(`[a-z]){2,}",
    "(?i)\\[char\\](\\[\\d{1,3}\\]\\s*){3,}",
    "(?i)-join\\s*\\(",
    "(?i)-bxor\\s",
    "(?i)-f\\s*@\\("
  )
```

Expected result and interpretation: unchanged from above.

**[FALSE POSITIVE]** Legitimate PowerShell code-golf and some minifying build steps use `-join` and `-f` for genuinely benign string construction, and a handful of module authors backtick-escape reserved words in string interpolation for reasons unrelated to evasion. This pattern's regex is brittle by construction — it encodes today's known obfuscation idioms, not obfuscation as a concept — so expect a maintenance burden closer to a threat-intel feed than a stable rule; treat a clean result as weak evidence of absence, not proof nothing was obfuscated a different way.

**[PIVOT]** Pull the Event ID 4104 script-block record for the same process (see QC-08-04/QC-08-05's telemetry source) — the reconstructed script PowerShell's own engine logs there is far easier to read than the raw command line, and the engine frequently logs the resolved form even when the invocation itself was obfuscated.

---

### QC-08-03 — Download cradle: fetch and execute in one line

| Field | Value |
|---|---|
| **Pattern ID** | `QC-08-03` |
| **MITRE** | T1059.001 (Command and Scripting Interpreter: PowerShell) |
| **Behavior** | PowerShell invocation combining a remote-content-fetch cmdlet with an execution primitive (`IEX`/`Invoke-Expression`) in the same command line. |
| **DEH cross-ref** | DEH Part 10 §2 (download-cradle telemetry); cf. DEH Part 11 (Ingress Tool Transfer hand-off to a LOLBin, owned by this book's Part 9) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) |

**[HUNTER]** A download cradle — a one-liner that fetches remote content and immediately executes it in memory — is the single most common way a phishing macro, a compromised scheduled task, or a dropped shortcut gets a second-stage payload onto a host without writing a file to disk first. Hunting the combination of a fetch primitive (`Net.WebClient`, `Invoke-WebRequest`, `Start-BitsTransfer`) and an execution primitive (`IEX`, `Invoke-Expression`) in the same line catches the cradle shape itself, independent of which domain or payload sits behind it on a given day.

**[QUERY] Sigma** — Sysmon Event ID 1 process creation.

CONCEPTUAL SAMPLE — cmdlet lists illustrative; extend with any fetch/execute aliases your environment uses.

```yaml
title: PowerShell Download Cradle - Fetch and Execute in One Line
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_fetch:
    CommandLine|contains:
      - 'Net.WebClient'
      - 'Invoke-WebRequest'
      - 'iwr '
      - 'Start-BitsTransfer'
      - 'wget '
      - 'curl '
  selection_exec:
    CommandLine|contains:
      - 'IEX'
      - 'Invoke-Expression'
      - 'DownloadString'
      - '| iex'
  condition: selection_process and selection_fetch and selection_exec
falsepositives:
  - See [FALSE POSITIVE] below.
level: high
```

Expected result: a match returns a single command line carrying both halves of the cradle — the fetch target and the execution call wrapping it. Interpretation: in an environment where PowerShell is mostly used for local administration, this shape is a strong signal of a fetch-and-run payload; where unmanaged software installers are common, see [FALSE POSITIVE].

**[QUERY] KQL (Sentinel/Defender)** — `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — cmdlet lists illustrative.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Net.WebClient", "Invoke-WebRequest", "Start-BitsTransfer", "wget ", "curl ")
| where ProcessCommandLine has_any ("IEX", "Invoke-Expression", "DownloadString", "| iex")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

Expected result and interpretation: unchanged from above.

**[QUERY] SPL** — Sysmon `EventCode=1`.

CONCEPTUAL SAMPLE — cmdlet lists illustrative.

```spl
index=win_events sourcetype="WinEventLog:Sysmon" EventCode=1
| search Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| search (CommandLine="*Net.WebClient*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*Start-BitsTransfer*" OR CommandLine="*wget *" OR CommandLine="*curl *")
| search (CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*" OR CommandLine="*DownloadString*" OR CommandLine="*| iex*")
| table _time, host, User, CommandLine, ParentImage
```

Expected result and interpretation: unchanged from above.

**[QUERY] AQL (QRadar)** — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — property names illustrative.

```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS EventTime, "Command Line" AS CommandLine, username
FROM events
WHERE ("Process Name" ILIKE '%powershell.exe%' OR "Process Name" ILIKE '%pwsh.exe%')
  AND ("Command Line" ILIKE '%Net.WebClient%' OR "Command Line" ILIKE '%Invoke-WebRequest%' OR "Command Line" ILIKE '%Start-BitsTransfer%')
  AND ("Command Line" ILIKE '%IEX%' OR "Command Line" ILIKE '%Invoke-Expression%' OR "Command Line" ILIKE '%DownloadString%')
```

Expected result and interpretation: unchanged from above, subject to the same custom-property dependency noted in QC-08-01.

**[QUERY] YARA-L (Google SecOps)** — UDM `PROCESS_LAUNCH`.

CONCEPTUAL SAMPLE — field paths illustrative.

```yaral
rule powershell_download_cradle {
  meta:
    description = "PowerShell command line combining a remote-fetch primitive with an execution primitive"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /(?i)(powershell\.exe|pwsh\.exe)$/
    $e.target.process.command_line = /(?i)(net\.webclient|invoke-webrequest|start-bitstransfer)/
    $e.target.process.command_line = /(?i)(iex|invoke-expression|downloadstring)/
  condition:
    $e
}
```

Expected result and interpretation: unchanged from above.

**[QUERY] Elastic (KQL)** — single-event AND of two wildcard groups, no regex needed, so Elastic KQL fits directly.

CONCEPTUAL SAMPLE — wildcard lists illustrative.

```kql
process.name : ("powershell.exe" or "pwsh.exe") and
process.command_line : ("*Net.WebClient*" or "*Invoke-WebRequest*" or "*Start-BitsTransfer*" or "*wget *" or "*curl *") and
process.command_line : ("*IEX*" or "*Invoke-Expression*" or "*DownloadString*")
```

Expected result and interpretation: unchanged from above.

**[FALSE POSITIVE]** A large number of legitimate one-line installer instructions published by vendors (Chocolatey, Docker Desktop, and various CLI "curl the install script" patterns ported to PowerShell) are structurally identical download cradles by design — `iwr https://get.example.com | iex` is the officially documented install command for more than one real product. Before tuning, check whether the destination domain is on an allowlist of known package-manager or vendor install endpoints, and whether the parent process is an interactive user session (consistent with an install) versus a scheduled task or an Office application (consistent with an attack).

**[PIVOT]** Pivot to Part 19's beaconing/rare-destination patterns on the fetched URL's domain — a cradle pulling from a domain no other host in the fleet has ever contacted is a far stronger signal than the cradle shape alone. If the parent process is an Office application, pivot to Part 10's macro-execution-chain patterns instead.

> **Blind Spot**
> This pattern only sees a cradle when both halves land in the same visible command line. A cradle split across two invocations — one process that fetches and writes to a variable or file, and a second, later process that executes it — defeats the AND-of-two-substrings shape entirely, and so does a cradle piped to `powershell.exe -Command -` over stdin, which some EDR command-line fields truncate or omit. Treat a clean result as "no single-line cradle seen," not "no cradle happened."

---

### QC-08-04 — Script-block content matching AMSI-bypass markers

| Field | Value |
|---|---|
| **Pattern ID** | `QC-08-04` |
| **MITRE** | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| **Behavior** | Script-block content referencing the specific internal AMSI fields/methods public bypass techniques target. |
| **DEH cross-ref** | DEH Part 10 §3 (AMSI architecture and detection blind spots) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, Elastic (KQL) — AQL and YARA-L: N/A, see below |

**[HUNTER]** AMSI (the Antimalware Scan Interface) is PowerShell's last content-inspection checkpoint before a script body executes, and public bypass techniques patch it in memory by targeting the same handful of internal fields and methods — `System.Management.Automation.AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer` — almost every time, because there are only so many ways to neuter one CLR type from inside a script. This pattern hunts script-block content directly rather than the process command line, because a bypass is almost never typed at a prompt — it arrives inside the very script a cradle (QC-08-03) or an encoded blob (QC-08-01) just pulled in.

**[QUERY] Sigma** — Event ID 4104 (PowerShell Script Block Logging), Sigma's `ps_script` category.

CONCEPTUAL SAMPLE — marker list illustrative; treat as a snapshot of public bypass technique names, not exhaustive.

```yaml
title: Script Block Content Matching Known AMSI-Bypass Markers
status: experimental
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - 'AmsiUtils'
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
      - 'AmsiContext'
  condition: selection
falsepositives:
  - See [FALSE POSITIVE] below.
level: high
```

Expected result: a match returns the full (possibly multi-part, since PowerShell splits long script blocks across several 4104 events) script content containing one of the marker strings, along with the host and account context of the launching process. Interpretation: one of the more specific signals in this part — legitimate code has essentially no reason to reference `AmsiUtils` or `AmsiScanBuffer` by name.

**[QUERY] KQL (Sentinel/Defender)** — Defender for Endpoint's `DeviceEvents` with `ActionType == "PowerShellCommand"`, script-block text surfaced from `AdditionalFields`.

CONCEPTUAL SAMPLE — field extraction illustrative; validate the `AdditionalFields` JSON shape against your own tenant.

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| extend ScriptBlockText = tostring(parse_json(AdditionalFields).ScriptBlockText)
| where ScriptBlockText has_any ("AmsiUtils", "amsiInitFailed", "AmsiScanBuffer", "AmsiContext")
| project Timestamp, DeviceName, AccountName, ScriptBlockText
```

Expected result and interpretation: unchanged from the Sigma block.

**[QUERY] SPL** — `Microsoft-Windows-PowerShell/Operational`, Event ID 4104.

CONCEPTUAL SAMPLE — field names illustrative; validate against your Windows PowerShell TA's parsing.

```spl
index=win_events sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*amsiInitFailed*" OR ScriptBlockText="*AmsiScanBuffer*" OR ScriptBlockText="*AmsiContext*"
| table _time, host, ScriptBlockText
```

Expected result and interpretation: unchanged from above.

**AQL (QRadar): N/A — missing schema field.** QRadar has no default DSM mapping of Microsoft-Windows-PowerShell/Operational's Event ID 4104 `ScriptBlockText` into a standard custom property; deployments that have one built it themselves, so no cross-environment query would be honest here.

**YARA-L (Google SecOps): N/A — missing schema field.** Chronicle's UDM has no confirmed dedicated field equivalent to `ScriptBlockText` — some deployments remap 4104 content into `principal.process.command_line` via a custom parser, but that mapping is deployment-specific, not a documented default, the same class of gap this book's `STYLE-GUIDE.md` §4.4 notes for YARA-L's unconfirmed `GrantedAccess` equivalent.

**[QUERY] Elastic (KQL)** — Elastic's Windows PowerShell integration maps script-block content into `powershell.file.script_block_text`, a confirmed field, so this stays a single-event Elastic KQL match.

CONCEPTUAL SAMPLE — field name illustrative; confirm against your installed integration version.

```kql
event.code : "4104" and powershell.file.script_block_text : ("*AmsiUtils*" or "*amsiInitFailed*" or "*AmsiScanBuffer*" or "*AmsiContext*")
```

Expected result and interpretation: unchanged from above.

**[FALSE POSITIVE]** Security tooling itself is the main legitimate source of these strings — EDR agents, PowerShell security modules, and blue-team AMSI-validation scripts reference `AmsiUtils` and `AmsiScanBuffer` directly to verify AMSI is loaded and functioning. Exclude by known security-tool script-block hashes or by the specific parent process (the EDR agent's own service) rather than by the string match alone. Because Event ID 4104 splits a long script across multiple records, a marker string split across a record boundary won't match a single-event query — see [PIVOT].

**[PIVOT]** Reassemble the full script by grouping all Event ID 4104 events sharing the same `ScriptBlockId` within the lookback window before concluding a marker string is genuinely absent, per DEH Part 10's script-block-reconstruction guidance. On a confirmed hit, check the process's immediately following 4104/4103 records for a subsequent download cradle (QC-08-03) or credential-access attempt — an AMSI bypass is a means, not an end.

> **Detection Autopsy**
> An early version of this pattern matched only the literal substring `amsiInitFailed` against script-block text and looked airtight in testing. It missed anything using QC-08-02's string-splitting tricks to build that identifier at runtime — `'amsi'+'InitFailed'` or a backtick-split variant resolves to the same field PowerShell's engine ultimately touches, but never appears as one contiguous string in logged text captured before resolution. Pairing this pattern with QC-08-02's structural-obfuscation markers on the same script block closes most of that gap; neither pattern alone does.

---

### QC-08-05 — Script-block content matching offensive-framework markers

| Field | Value |
|---|---|
| **Pattern ID** | `QC-08-05` |
| **MITRE** | T1059.001 (Command and Scripting Interpreter: PowerShell) — broad; the specific downstream technique varies by which marker matches, see [HUNTER] |
| **Behavior** | Script-block content matching a curated, maintained list of public offensive PowerShell framework markers, hunted at scale across a wide lookback window. |
| **DEH cross-ref** | DEH Part 10 §2 (script-block reconstruction); DEH Part 41 (coverage-tier framing, cited in [SOC MANAGEMENT] below) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, Elastic (ES\|QL) — AQL and YARA-L: N/A, see below |

**[HUNTER]** Beyond AMSI-specific markers, a range of public offensive PowerShell frameworks — PowerSploit, Empire-derived loaders, Covenant's PowerShell launchers — reuse distinctive function and module names verbatim, and those names show up in script-block content even after the framework has been recompiled, renamed on disk, or delivered fileless. This pattern trades precision for reach: a maintained keyword list run across a wide lookback window surfaces hits QC-08-04's narrower AMSI-specific pattern would miss, at the cost of needing the list itself kept current.

**[QUERY] Sigma** — Event ID 4104, Sigma's `ps_script` category.

CONCEPTUAL SAMPLE — marker list is an illustrative, dated snapshot; treat the list itself as the thing needing maintenance, per [SOC MANAGEMENT].

```yaml
title: Script Block Content Matching Public Offensive PowerShell Framework Markers
status: experimental
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-ReflectivePEInjection'
      - 'Invoke-TokenManipulation'
      - 'Invoke-Shellcode'
      - 'Invoke-Obfuscation'
      - 'PowerSploit'
      - 'Get-GPPPassword'
      - 'Invoke-Kerberoast'
  condition: selection
falsepositives:
  - See [FALSE POSITIVE] below.
level: high
```

Expected result: a match returns the specific marker matched, the host, and the account context. Interpretation: close to a direct identification of a specific public tool's presence in script content, not just PowerShell activity in general — high-confidence relative to the rest of this part, bounded by how current the list is.

**[QUERY] KQL (Sentinel/Defender)** — `DeviceEvents`, aggregated by host and account over a rolling window rather than returned as raw events, given this pattern's wide-lookback framing.

CONCEPTUAL SAMPLE — marker list and window illustrative.

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| extend ScriptBlockText = tostring(parse_json(AdditionalFields).ScriptBlockText)
| where ScriptBlockText has_any ("Invoke-Mimikatz", "Invoke-ReflectivePEInjection", "Invoke-TokenManipulation", "Invoke-Shellcode", "Invoke-Obfuscation", "PowerSploit", "Get-GPPPassword", "Invoke-Kerberoast")
| summarize HitCount = count(), Samples = make_set(ScriptBlockText, 3) by DeviceName, AccountName, bin(Timestamp, 1d)
```

Expected result and interpretation: unchanged from the Sigma block, with the per-host/per-day count helping prioritize triage on a fleet where this hunt runs weekly rather than continuously.

**[QUERY] SPL** — `Microsoft-Windows-PowerShell/Operational`, Event ID 4104, over a 7-day window.

CONCEPTUAL SAMPLE — marker list and window illustrative.

```spl
index=win_events sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 earliest=-7d
| search ScriptBlockText IN ("*Invoke-Mimikatz*","*Invoke-ReflectivePEInjection*","*Invoke-TokenManipulation*","*Invoke-Shellcode*","*Invoke-Obfuscation*","*PowerSploit*","*Get-GPPPassword*","*Invoke-Kerberoast*")
| stats count by host, ScriptBlockText
| sort - count
```

Expected result and interpretation: unchanged from above.

**AQL (QRadar): N/A — missing schema field**, the same gap noted under QC-08-04 for `ScriptBlockText`; it applies identically here since both patterns share the same telemetry source.

**YARA-L (Google SecOps): N/A — missing schema field**, same reasoning as QC-08-04.

**[QUERY] Elastic (ES\|QL)** — this pattern's shape is a wide-lookback aggregation rather than a single boolean match, so it uses ES\|QL instead of Elastic KQL, per the threshold/wide-lookback branch of the surface-choice decision table.

CONCEPTUAL SAMPLE — index pattern, marker list, and window illustrative.

```esql
FROM logs-windows.powershell_operational-*
| WHERE event.code == "4104"
| WHERE powershell.file.script_block_text RLIKE ".*(Invoke-Mimikatz|Invoke-ReflectivePEInjection|Invoke-TokenManipulation|Invoke-Shellcode|Invoke-Obfuscation|PowerSploit|Get-GPPPassword|Invoke-Kerberoast).*"
| STATS hit_count = COUNT(*) BY host.name, user.name
| SORT hit_count DESC
```

Expected result and interpretation: unchanged from above.

**[FALSE POSITIVE]** Authorized penetration tests and red-team engagements are, by a wide margin, the most common legitimate source of a hit here — these are literally the tools those engagements use. Cross-check any hit against the current authorized-testing calendar before escalating; a hit during an active engagement window is expected, not a genuine incident. The keyword list itself is a maintenance liability: it only catches markers known at authoring time, so a clean result means "no known-marker match," not "no offensive tooling present" — pair this pattern with QC-08-02's structural-obfuscation hunt for tooling renamed or repacked specifically to defeat a list like this one.

**[PIVOT]** On a hit outside a known testing window, pull the full process lineage for the hosting `powershell.exe` (Sysmon Event ID 1's `ParentImage`/`ParentCommandLine` chain) and check Part 15's discovery patterns and Part 22's malware-indicator patterns for the same host in the same window — a real hit here is rarely an isolated event.

**[SOC MANAGEMENT]** Refresh the keyword list on a fixed cadence — monthly is a reasonable default — against newly public offensive-tooling releases and conference material, and log each addition or removal the way DEH Part 43's Detection Debt ledger tracks a standing rule's staleness; an un-refreshed list is debt accruing silently, not a one-time investment. Consider graduating this pattern from a periodic hunt to a standing alert once the false-positive rate from authorized testing is well characterized enough to tune around it, per DEH Part 41's coverage-tier framing.

---

## Cross-references

DEH Part 10 (PowerShell Detection Engineering) for the telemetry mechanics — script-block reconstruction, the 4103/4104 distinction, and AMSI's provider architecture — underlying every pattern in this part; DEH Part 40 for the seeded "PowerShell execution = malicious" naive-rule teardown behind every `[FALSE POSITIVE]` entry above; DEH Parts 23–29 and DEH Appendix A5 for the query-language syntax and backend-translation-loss fundamentals this part assumes rather than re-teaches; DEH Parts 41–43 for the coverage/quality/debt scoring cited in QC-08-05's `[SOC MANAGEMENT]` entry. Within this book: Part 9 (LOLBins & Living-off-the-Land Execution) for the hand-off pivot out of QC-08-03; Part 10 (Suspicious Scripting Hosts & Macro Execution) for the parent-process pivot out of QC-08-01 and QC-08-03; Part 15 (Host & Directory Discovery) and Part 22 (Malware Indicators) for the QC-08-05 pivot; Part 16 (Lateral Movement via Admin Tools & Remote Services) for the PowerShell-remoting boundary stated in "Why this part exists"; Part 19 (C2 & Beaconing Detection) for the QC-08-03 domain pivot.
