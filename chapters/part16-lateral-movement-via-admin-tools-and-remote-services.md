---
title: "Lateral Movement via Admin Tools & Remote Services"
part: 16
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 16 — Lateral Movement via Admin Tools & Remote Services

## Why this part exists

**[CONCEPT]** Once an attacker holds one set of working credentials, the fastest way to reach a second host is almost never a novel exploit — it's a legitimate Windows administration mechanism the attacker's account already has rights to use: a remotely installed service (PsExec and its Impacket-family clones), a WMI method call, a PowerShell Remoting/WinRM session, or an interactive RDP logon. Each mechanism sits at the same point in the kill chain — the attacker already has credentials and is converting "access to one host" into "access to another host" — but leaves a structurally different telemetry signature, which is why this part carries six patterns instead of one. See DEH Part 44 (Adversary Behaviour for Defenders) for the broader kill-chain framing this part assumes rather than re-derives.

This part covers four admin-tool/remote-service families — PsExec-style service-based execution, WMI-based remote execution, WinRM/PowerShell remoting, and RDP — split into six named patterns because the service-creation shape and the RDP shape each split cleanly into two distinguishable query patterns (a single-event artifact versus a joined or aggregated multi-event shape). It does **not** cover:

- The *theft* of the Kerberos ticket, NTLM hash, or session token an attacker might instead use to authenticate — that's this book's Part 7 (Kerberos & Directory Credential Attacks).
- The *use* of a stolen ticket or hash (pass-the-hash, pass-the-ticket, token impersonation) to authenticate somewhere new — that's Part 17, split from this part on the same theft-vs-use boundary DEH's own domain parts use.
- The reconnaissance that typically precedes this part's patterns (`net`/`nltest`/BloodHound-style enumeration) — that's Part 15.
- Permanent WMI event-subscription persistence (`__EventFilter`/`CommandLineEventConsumer`) — that's Part 13. This part's WMI pattern (QC-16-03) is scoped to on-demand `Win32_Process.Create()` execution only, not persistence.

This part assumes the reader already knows what a Logon Type 3 versus Type 10 event means and how to read a Windows process-tree view — DEH Part 11's endpoint telemetry section and DEH Part 8's Windows Security log fundamentals own that teaching; this part cites them rather than re-explaining them.

## 1. Service- and admin-share-based remote execution (PsExec-style)

### QC-16-01 — Suspiciously named service installed and started on a remote host

| Field | Value |
|---|---|
| **Pattern ID** | `QC-16-01` |
| **MITRE** | T1569.002 (System Services: Service Execution) |
| **Behavior** | Remote installation and immediate start of a Windows service used to run an attacker-supplied binary or command, the classic PsExec/Impacket `psexec.py` artifact shape. |
| **DEH cross-ref** | DEH Part 11 §Endpoint (process-tree view); DEH Part 8 (Windows Security log fundamentals) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic KQL |

**[HUNTER]** A standing detection tuned to the literal string `PSEXESVC` catches the default case and nothing else — Impacket's `psexec.py` and most of its clones randomize both the service name and the dropped binary name by default. This hunt widens past the literal name to the *shape*: a short-lived service with a random alphanumeric name, an image path sitting under `ADMIN$` or `Windows\Temp`, and a demand-start type, so it still catches a renamed tool a literal-string rule would miss.

**[QUERY]** Sigma, targeting the Windows System log's service-installation event.

CONCEPTUAL SAMPLE — field names, the 8-character regex, and the path substrings are illustrative; validate against your own service-naming conventions before use.

```yaml
title: Suspiciously named service installed and started (PsExec-shaped)
status: experimental
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
  suspicious_name:
    ServiceName|re: '^[A-Za-z0-9]{8}$'
  suspicious_path:
    ImagePath|contains:
      - '\ADMIN$\'
      - '\Windows\Temp\'
  condition: selection and (suspicious_name or suspicious_path)
falsepositives:
  - Legitimate software deployment tools that install short-lived helper services
level: medium
```

Plausible expected result: hits on Event ID 7045 entries where `ServiceName` is an 8-character random alphanumeric string or `ImagePath` references `ADMIN$\` or `Windows\Temp\`. In a moderately sized fleet with deployment-tool exclusions already applied, a hunt window of a week typically surfaces single-digit matches. Interpretation: a match is consistent with a service-based remote-execution tool landing and starting on the host; it does not by itself distinguish authorized IT tooling from an intrusion.

**[QUERY]** KQL, Microsoft Sentinel, System log forwarded into the generic `Event` table.

CONCEPTUAL SAMPLE — assumes a connector that surfaces `ServiceName`/`ImagePath` as flattened columns; verify your own connector's schema before use.

```kql
Event
| where EventLog == "System" and EventID == 7045
| where ServiceName matches regex @"^[A-Za-z0-9]{8}$"
   or ImagePath has_any (@"\\ADMIN$\\", @"\\Windows\\Temp\\")
| project TimeGenerated, Computer, ServiceName, ImagePath, AccountName
```

Plausible expected result: a handful of rows per week naming the target `Computer`, the randomized `ServiceName`, and an `ImagePath` under a temp or admin-share directory. Interpretation: consistent with the same PsExec-style artifact described above; treat the count as illustrative, not a validated production baseline.

**[QUERY]** SPL, Splunk with the Windows TA ingesting the System log.

CONCEPTUAL SAMPLE — regex and field names illustrative; validate against your own TA's field extraction.

```spl
index=wineventlog sourcetype=WinEventLog:System EventCode=7045
| regex ServiceName="^[A-Za-z0-9]{8}$"
  OR ImagePath="(?i)(admin\$|windows\\\\temp)"
| table _time, ComputerName, ServiceName, ImagePath, AccountName
```

Plausible expected result: same shape as the KQL block above, one row per qualifying service-install event. Interpretation: unchanged from the Sigma/KQL entries — this is one analytic, three syntaxes.

**[QUERY]** AQL, QRadar — this is AQL, not standard SQL, searching a normalized Windows Security Event Log source.

CONCEPTUAL SAMPLE — custom property names (`"Service Name"`, `"Image Path"`) assume a DSM/QID mapping that exposes them; confirm your own source mapping.

```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS EventTime,
       sourceip, "Service Name", "Image Path", username
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Microsoft Windows Security Event Log'
  AND QIDNAME(qid) = 'A service was installed in the system'
  AND ("Service Name" IMATCHES '^[A-Za-z0-9]{8}$'
       OR "Image Path" ILIKE '%ADMIN$%' OR "Image Path" ILIKE '%Windows\Temp%')
LAST 7 DAYS
```

Plausible expected result: a small result set naming the source IP of the installing session, the service name, and the image path. Interpretation: same as above — a hit is a candidate, not a confirmed intrusion.

**[QUERY]** YARA-L, Google SecOps, over the Unified Data Model.

CONCEPTUAL SAMPLE — the `event_type` and resource-path field names are illustrative; confirm the equivalent UDM fields your own parser populates for service-install telemetry before relying on this.

```yaral
rule psexec_style_service_install {
  meta:
    author = "author-agent"
    description = "Conceptual sample: short-lived, randomly named service install consistent with PsExec-style remote execution"
    severity = "Medium"
  events:
    $e.metadata.event_type = "SERVICE_UNSPECIFIED"
    $e.target.resource.name = /^[A-Za-z0-9]{8}$/ or $e.target.file.full_path = /(?i)(admin\$|windows\\temp)/
  condition:
    $e
}
```

Plausible expected result: a small set of matched events naming the target resource and file path. Interpretation: unchanged from the other five implementations.

**[QUERY]** Elastic KQL — a single-event boolean match, the cheapest Elastic surface for this shape per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — `winlog.event_data.*` field names illustrative; confirm against your own Winlogbeat/ECS mapping.

```kql
winlog.event_id:7045 and (winlog.event_data.ServiceName:/[A-Za-z0-9]{8}/ or winlog.event_data.ImagePath:(*ADMIN$* or *Windows\\Temp*))
```

Plausible expected result: same shape as the other five languages. Interpretation: unchanged.

**[FALSE POSITIVE]** Legitimate software-deployment tooling is the dominant driver. SCCM/ConfigMgr client push, PDQ Deploy, and Ivanti all install short-lived, per-job helper services during normal patch cycles, and several of them (PDQ Deploy's `PDQDeployRunner-<random>` job services, for example) generate names that satisfy an 8-character random-alphanumeric filter about as often as a real intrusion would in an environment running nightly patch jobs. The fix is excluding known deployment-tool install paths or service-description strings, not loosening the random-name filter itself.

**[PIVOT]** Check whether the account that installed the service also authenticated over SMB to the same host in the preceding few minutes (`QC-16-02`), and pull the resulting child process spawned by `services.exe` to see whether its binary matches a known PsExec/Impacket signature or is simply unsigned.

> **Detection Autopsy**
>
> An early version of this exact pattern alerted on the literal service name `PSEXESVC` and nothing else. It missed every Impacket `psexec.py` run in a red-team validation exercise because the tool's default behavior randomizes the service name per invocation — the literal string was never present. Widening the match to the 8-character-random-name *shape* plus the `ADMIN$`/`Windows\Temp` path signal, rather than any specific string, is what closed that gap.

### QC-16-02 — Admin-share authentication immediately followed by remote service installation

| Field | Value |
|---|---|
| **Pattern ID** | `QC-16-02` |
| **MITRE** | T1021.002 (Remote Services: SMB/Windows Admin Shares); secondary: T1570 (Lateral Tool Transfer) |
| **Behavior** | An account touching a target host's `ADMIN$` or `C$` administrative share (Event ID 5145) and, within a short window, a new service appearing on that same host (Event ID 7045) — the two-step shape underneath most admin-tool lateral movement, independent of which specific tool performs the second step. |
| **DEH cross-ref** | DEH Part 8 (4624 Type 3 / share-access fundamentals); DEH Part 11 §Endpoint; cf. DEH DET-27-01 (QRadar Building Block/Reference Set precedent for multi-object correlation) |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL (investigative single-search only, see note), YARA-L, Elastic EQL — Sigma: `N/A`, see below |

**[HUNTER]** `QC-16-01`'s literal service-shape filter can still be evaded by a well-disguised service name and a plausible-looking path. The authentication-then-service-install *sequence* is harder to disguise, because it's a property of the delivery mechanism (SMB admin-share access, then a service start on the same host), not of any one tool's naming choices — this pattern catches tool variants the first pattern's shape filter misses. Note Event ID 5145 requires "Audit Detailed File Share" auditing enabled; where that's off, a coarser proxy is a Type 3 logon immediately followed by an `IPC$` connection to the same host.

Sigma: `N/A` — structurally poor fit, not impossible. This pattern needs a two-rule ordered correlation (share access, then a service install on the same host within 5 minutes). Sigma's correlation grammar has a `temporal_ordered` type nominally built for exactly this shape, but per-backend support for it is narrow enough — most converters target single-event or simple-aggregation correlation, per this style guide's own flagship example of the "structurally poor fit" category — that forcing this pattern through it would produce a rule most deployments can't actually execute. See STYLE-GUIDE.md §4.4.

**[QUERY]** KQL, Microsoft Sentinel, joining share-access and service-install events.

CONCEPTUAL SAMPLE — table/field names illustrative; the join key (`Computer`) assumes both event types resolve to the same hostname string in your environment.

```kql
let ShareAccess = SecurityEvent
| where EventID == 5145
| where ShareName has_any ("ADMIN$", "C$")
| project AccessTime = TimeGenerated, Computer, SubjectAccount = Account, IpAddress;
let Services = Event
| where EventLog == "System" and EventID == 7045
| project SvcTime = TimeGenerated, Computer, ServiceName, ImagePath;
ShareAccess
| join kind=inner Services on Computer
| where SvcTime between (AccessTime .. AccessTime + 5m)
| project AccessTime, SvcTime, Computer, SubjectAccount, IpAddress, ServiceName, ImagePath
```

Plausible expected result: paired rows showing the accessing account/IP and the resulting service within five minutes. Interpretation: consistent with a lateral-movement tool's arrival and execution, independent of which specific tool it was.

**[QUERY]** SPL, Splunk, using `join` across two event codes.

CONCEPTUAL SAMPLE — `join` is shown for readability; a `stats`/`transaction`-based rewrite is usually cheaper at scale, per DEH's own SPL semantics teaching (DEH Parts 24–29).

```spl
index=wineventlog EventCode=5145 ShareName IN ("ADMIN$","C$")
| rename _time as access_time, ComputerName as host
| join host [ search index=wineventlog EventCode=7045
  | rename _time as svc_time, ComputerName as host ]
| where svc_time >= access_time AND svc_time <= access_time + 300
| table access_time, svc_time, host, Account_Name, ServiceName, ImagePath
```

Plausible expected result: identical shape to the KQL block. Interpretation: unchanged.

**[QUERY]** AQL, QRadar — this is AQL, not standard SQL. Investigative single-search validation only: QRadar cannot express this two-event, same-host join as one standing AQL statement.

CONCEPTUAL SAMPLE — a standing correlated rule in QRadar needs a Reference Set of recent `ADMIN$`/`C$` accesses checked by a Custom Rule against new 7045 events (QRadar's Building Block/Reference Set/Rule model, per DEH Part 27 §2–§3; cf. DEH DET-27-01) — not a single AQL statement. This query is the manual validation step to run before building those standing objects.

```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS EventTime,
       sourceip, username, "Share Name", destinationip
FROM events
WHERE QIDNAME(qid) = 'A network share object was checked to see whether client can be granted desired access'
  AND "Share Name" IN ('ADMIN$', 'C$')
LAST 1 HOURS
```

Plausible expected result: a list of share-access events an analyst then manually checks against a second AQL search for 7045 events on the same destination host within the next five minutes. Interpretation: a manually confirmed pair is consistent with the same behavior the other four covered languages express as a single correlated query.

**[QUERY]** YARA-L, Google SecOps, using a `match` window across two event roles.

CONCEPTUAL SAMPLE — event-role field names illustrative; confirm the equivalent UDM fields for share-access and service-install events your own parser populates.

```yaral
rule admin_share_access_then_service_install {
  meta:
    description = "Conceptual sample: ADMIN$/C$ share access followed by new service on same host within 5 minutes"
  events:
    $share.metadata.event_type = "NETWORK_CONNECTION"
    $share.target.resource.name = "ADMIN$" or $share.target.resource.name = "C$"
    $service.metadata.event_type = "SERVICE_UNSPECIFIED"
    $share.target.hostname = $service.target.hostname
  match:
    $share.target.hostname over 5m
  condition:
    $share and $service and $service.metadata.event_timestamp.seconds > $share.metadata.event_timestamp.seconds
}
```

Plausible expected result: matched pairs on the shared hostname within the window. Interpretation: unchanged from the other implementations.

**[QUERY]** Elastic EQL — an ordered, joined multi-event pattern is exactly what `sequence` is for, per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — event-category and field names illustrative; confirm against your own ECS mapping for share-access and service-install events.

```eql
sequence by host.name with maxspan=5m
  [ file where event.action == "network_share_object_checked" and file.share.name in ("ADMIN$", "C$") ]
  [ process where event.action == "service-installed" ]
```

Plausible expected result: sequences matched on `host.name` within the five-minute span. Interpretation: unchanged.

**[FALSE POSITIVE]** IT patch and deployment tooling is the dominant driver, more so than for `QC-16-01` alone: SCCM distribution points, PDQ Deploy, and Ivanti all legitimately connect to `ADMIN$` and install a helper service as part of every normal patch cycle, meaning this two-event correlation fires on every patch-Tuesday maintenance window unless the deployment tool's own service accounts are excluded. A single SCCM distribution-point account can generate dozens of matching pairs in one patch night — allowlist that account rather than loosening the time window.

**[PIVOT]** Pull the resulting service's binary via `QC-16-01`'s process-tree pivot, and check whether the source account/host pair appears in the deployment tool's own job log for a scheduled maintenance window; if it doesn't, escalate the process-creation chain rooted at `services.exe` for that specific service.

## 2. Remote-execution-framework movement: WMI and WinRM

### QC-16-03 — Process spawned as a child of WmiPrvSE.exe

| Field | Value |
|---|---|
| **Pattern ID** | `QC-16-03` |
| **MITRE** | T1047 (Windows Management Instrumentation) |
| **Behavior** | A new process spawned as a direct child of `WmiPrvSE.exe` on a target host, consistent with a remote `Win32_Process.Create()` call (`wmic /node:`, PowerShell `Invoke-WmiMethod`, or an Impacket `wmiexec.py`-style tool) rather than local WMI tooling use. |
| **DEH cross-ref** | DEH Part 11 §Endpoint (process-tree view). Explicit boundary: this pattern targets on-demand remote execution via WMI, not the permanent WMI event-subscription persistence mechanism owned by this book's Part 13. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic KQL |

**[HUNTER]** On-demand WMI execution doesn't drop a file the way PsExec does, so it evades every pattern in §1 of this part entirely — the reliable tell is the process tree, not the network transport. Any interactive shell (`cmd.exe`, `powershell.exe`, `rundll32.exe`) whose parent is `WmiPrvSE.exe` on a host with no legitimate local admin script doing the same thing is worth a look, especially when the spawning account doesn't match your known WMI-based monitoring tool's service account.

**[QUERY]** Sigma, process-creation telemetry (Sysmon Event ID 1 or Security 4688).

CONCEPTUAL SAMPLE — the known-tool exclusion path is illustrative; substitute your own environment's legitimate WMI-based RMM tooling.

```yaml
title: Suspicious child process of WmiPrvSE.exe
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\rundll32.exe'
  filter_known_mgmt_tools:
    CommandLine|contains: 'C:\Program Files\KnownRMM\'
  condition: selection and not filter_known_mgmt_tools
```

Plausible expected result: a small number of process-creation events per week naming `cmd.exe`/`powershell.exe`/`rundll32.exe` with a `WmiPrvSE.exe` parent, once the known-RMM exclusion is tuned. Interpretation: consistent with remote WMI-based command execution; a well-instrumented environment might settle to low single digits daily once tuned, but this book has not validated that count against production telemetry.

**[QUERY]** KQL, Microsoft Defender for Endpoint, `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — table and column names illustrative for Defender's schema; confirm against your own tenant.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

Plausible expected result: same shape as the Sigma entry. Interpretation: unchanged.

**[QUERY]** SPL, Splunk, Sysmon Event ID 1.

CONCEPTUAL SAMPLE — index/sourcetype names illustrative.

```spl
index=edr sourcetype=sysmon EventCode=1 ParentImage="*\\WmiPrvSE.exe"
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\rundll32.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentUser
```

Plausible expected result: same shape as the previous two entries. Interpretation: unchanged.

**[QUERY]** AQL, QRadar — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — custom property names assume a DSM mapping exposing parent/child process fields; confirm your own mapping.

```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS EventTime,
       "Process Name", "Parent Process Name", "Command Line", username, sourceip
FROM events
WHERE QIDNAME(qid) = 'Process Create'
  AND "Parent Process Name" ILIKE '%WmiPrvSE.exe%'
  AND ("Process Name" ILIKE '%cmd.exe%' OR "Process Name" ILIKE '%powershell.exe%')
LAST 7 DAYS
```

Plausible expected result: same shape as the other implementations. Interpretation: unchanged.

**[QUERY]** YARA-L, Google SecOps.

CONCEPTUAL SAMPLE — UDM field names illustrative; confirm your parser's process-parent field mapping.

```yaral
rule wmi_remote_process_execution {
  meta:
    description = "Conceptual sample: cmd/powershell spawned as a child of WmiPrvSE.exe"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.parent_process.file.full_path = /(?i)wmiprvse\.exe$/
    $e.target.process.file.full_path = /(?i)(cmd\.exe|powershell\.exe)$/
  condition:
    $e
}
```

Plausible expected result: same shape. Interpretation: unchanged.

**[QUERY]** Elastic KQL — single-event boolean match, the cheapest Elastic surface for this shape.

CONCEPTUAL SAMPLE — ECS field names illustrative.

```kql
process.parent.name:"WmiPrvSE.exe" and process.name:("cmd.exe" or "powershell.exe" or "rundll32.exe")
```

Plausible expected result: same shape as the other five languages. Interpretation: unchanged.

**[FALSE POSITIVE]** Legitimate systems-management and monitoring tools are the dominant driver — SCCM hardware inventory, many RMM agents, and some backup software routinely invoke WMI methods that spawn a short `cmd.exe` under `WmiPrvSE.exe` on a schedule. Fix by allowlisting the known tool's service account and its typical command-line pattern (for example, a specific inventory-script path), not by excluding `WmiPrvSE.exe` children altogether — that would blind the hunt to the exact behavior it's built to catch.

**[PIVOT]** Check the spawning account against the connecting source's normal WMI/RPC traffic (TCP 135 plus a dynamic RPC port) for that admin session, and inspect the resulting child process's own command line for an encoded PowerShell payload or a download cradle (see DEH Part 10 and this book's Part 8).

### QC-16-04 — Process spawned under a WinRM/PowerShell Remoting host

| Field | Value |
|---|---|
| **Pattern ID** | `QC-16-04` |
| **MITRE** | T1021.006 (Remote Services: Windows Remote Management) |
| **Behavior** | A process spawned as a child of `wsmprovhost.exe` on a target host, consistent with an attacker-established PowerShell Remoting or WinRM session used to run commands on that host. |
| **DEH cross-ref** | DEH Part 10 (PowerShell Detection Engineering); DEH Part 8 (4624 Type 3); DEH Part 11 §Endpoint |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic KQL |

**[HUNTER]** WinRM is enabled by default on many server builds and is the transport for a large share of legitimate remote administration, so a standing detection tuned to any `wsmprovhost.exe` activity is unworkable. This hunt looks for that transport being used from a source host, account, or time-of-day combination that doesn't match your own remote-administration jump-host inventory, then reads the resulting child-process tree for anything beyond routine admin commands.

**[QUERY]** Sigma, process-creation telemetry.

CONCEPTUAL SAMPLE — the jump-host exclusion list is illustrative; substitute your own inventory.

```yaml
title: Process spawned under a WinRM remoting host
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\wsmprovhost.exe'
  filter_known_jumphosts:
    ComputerName:
      - 'JUMP-ADMIN-01'
  condition: selection and not filter_known_jumphosts
```

Plausible expected result: a small number of process-creation events naming a `wsmprovhost.exe` parent on hosts outside the known jump-host list. Interpretation: consistent with a PowerShell Remoting/WinRM session running commands; not distinguishable on its own from an approved but unlisted admin workstation.

**[QUERY]** KQL, Microsoft Defender for Endpoint.

CONCEPTUAL SAMPLE — table/column names illustrative.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where DeviceName !in ("JUMP-ADMIN-01")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

Plausible expected result: same shape as the Sigma entry. Interpretation: unchanged.

**[QUERY]** SPL, Splunk.

CONCEPTUAL SAMPLE — index/field names illustrative.

```spl
index=edr EventCode=1 ParentImage="*\\wsmprovhost.exe"
  NOT ComputerName IN ("JUMP-ADMIN-01")
| table _time, ComputerName, User, Image, CommandLine
```

Plausible expected result: unchanged from the prior two entries. Interpretation: unchanged.

**[QUERY]** AQL, QRadar — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — custom property names illustrative.

```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS EventTime,
       "Parent Process Name", "Process Name", "Command Line", username
FROM events
WHERE QIDNAME(qid) = 'Process Create'
  AND "Parent Process Name" ILIKE '%wsmprovhost.exe%'
LAST 7 DAYS
```

Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY]** YARA-L, Google SecOps.

CONCEPTUAL SAMPLE — UDM field names illustrative.

```yaral
rule winrm_remoting_child_process {
  meta:
    description = "Conceptual sample: process spawned under wsmprovhost.exe, the PowerShell Remoting host"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.parent_process.file.full_path = /(?i)wsmprovhost\.exe$/
  condition:
    $e
}
```

Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY]** Elastic KQL — single-event boolean match.

CONCEPTUAL SAMPLE — ECS field names illustrative.

```kql
process.parent.name:"wsmprovhost.exe" and not host.name:"JUMP-ADMIN-01"
```

Plausible expected result: unchanged. Interpretation: unchanged.

**[FALSE POSITIVE]** Approved remote-admin jump hosts and scheduled-orchestration tools are the dominant driver — Ansible's WinRM connection plugin and Azure Automation hybrid runbook workers both live entirely inside `wsmprovhost.exe` sessions by design. Fix by allowlisting the known jump-host and orchestration-tool source inventory, not the child-process shape itself.

**[PIVOT]** Check the Windows Remote Management operational log (Event ID 91, session created) on the target for the true originating IP, since `wsmprovhost.exe`'s own process record doesn't carry it, then compare that source against DEH Part 8's 4624 Type 3 record for the same session to confirm the authenticating account.

> **Blind Spot**
>
> WinRM over HTTPS (port 5986) and Kerberos's double-hop restriction mean a session hopping through an intermediate jump host into a resource that itself makes a further authenticated call frequently falls back to a cached or delegated credential your logging doesn't clearly separate from the operator's own session. A hunt built only on `wsmprovhost.exe`'s local process tree will not surface that third hop at all — it has to be pieced together from the downstream resource's own authentication log.

## 3. RDP-based movement

### QC-16-05 — Single-source RDP fan-out across many destination hosts

| Field | Value |
|---|---|
| **Pattern ID** | `QC-16-05` |
| **MITRE** | T1021.001 (Remote Services: Remote Desktop Protocol) |
| **Behavior** | One account or source host establishing Type 10 (RemoteInteractive) logons against an unusually high number of distinct destination hosts within a short window — horizontal RDP spread rather than a single hop. |
| **DEH cross-ref** | DEH Part 8 (4624 Type 10); DEH Part 31 (Baselining — "unusual count" needs a baseline to mean anything) |
| **Languages covered** | Sigma (value_count correlation — note limited backend support), KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic ES\|QL |

**[HUNTER]** An attacker who already holds one working set of credentials often RDPs into several hosts quickly, looking for one with the access or data they need. That fan-out shape is a wide-lookback aggregation question — how many distinct destinations did this source hit in an hour — not a single-event match, and it needs a real per-environment baseline for what a legitimate jump-host or helpdesk account normally touches. DEH Part 31 owns building that baseline; this pattern assumes a threshold has already been set against it, and the `8` used below is illustrative, not a validated cutoff.

**[QUERY]** Sigma, a base Type 10 logon detection feeding a `value_count` correlation.

CONCEPTUAL SAMPLE — the threshold of 8 distinct hosts per hour is illustrative; `value_count` correlation support varies by backend converter.

```yaml
title: rdp_type10_logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 10
  condition: selection
---
title: Single source RDP fan-out across many destination hosts
status: experimental
correlation:
  type: value_count
  rules:
    - rdp_type10_logon
  group-by:
    - IpAddress
  distinct: Computer
  condition:
    gte: 8
  timespan: 1h
```

Plausible expected result: a small number of source IPs per week crossing the distinct-host threshold within an hour. Interpretation: consistent with an attacker probing several hosts from one foothold; also consistent with a helpdesk technician's normal shift — see `[FALSE POSITIVE]`.

**[QUERY]** KQL, Microsoft Sentinel.

CONCEPTUAL SAMPLE — threshold and bin size illustrative.

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 10
| summarize DistinctHosts = dcount(Computer), Hosts = make_set(Computer) by IpAddress, Account, bin(TimeGenerated, 1h)
| where DistinctHosts >= 8
```

Plausible expected result: rows naming the source IP/account pair and the set of distinct destination hosts reached inside the hour. Interpretation: unchanged from the Sigma entry.

**[QUERY]** SPL, Splunk.

CONCEPTUAL SAMPLE — field names illustrative.

```spl
index=wineventlog EventCode=4624 Logon_Type=10
| bucket _time span=1h
| stats dc(ComputerName) as distinct_hosts values(ComputerName) as hosts by _time, Source_Network_Address, Account_Name
| where distinct_hosts >= 8
```

Plausible expected result: unchanged from the KQL entry. Interpretation: unchanged.

**[QUERY]** AQL, QRadar — this is AQL, not standard SQL. Aggregation with `GROUP BY`/`HAVING` is natively supported here, unlike the joined shapes in `QC-16-02`/`QC-16-06`.

CONCEPTUAL SAMPLE — custom property name for logon type illustrative.

```sql
SELECT sourceip, username, UNIQUECOUNT(destinationip) AS distinct_hosts
FROM events
WHERE QIDNAME(qid) = 'An account was successfully logged on'
  AND "Logon Type" = 10
GROUP BY sourceip, username
HAVING UNIQUECOUNT(destinationip) >= 8
LAST 1 HOURS
```

Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY]** YARA-L, Google SecOps, using an `outcome` variable for the distinct-host count.

CONCEPTUAL SAMPLE — UDM field names and the `LogonType` custom field path illustrative.

```yaral
rule rdp_fanout_single_source {
  meta:
    description = "Conceptual sample: one source authenticating Type 10 RDP to 8+ distinct destination hosts within 1 hour"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.additional.fields["LogonType"] = "10"
  match:
    $e.principal.ip over 1h
  outcome:
    $distinct_hosts = count_distinct($e.target.hostname)
  condition:
    $e and $distinct_hosts >= 8
}
```

Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY]** Elastic ES\|QL — a threshold/wide-lookback aggregation pattern is exactly what ES\|QL is for, per DEH Appendix A5 §8's decision table; plain EQL has no aggregation stage for this shape.

CONCEPTUAL SAMPLE — index pattern and field names illustrative.

```esql
FROM logs-windows.security-*
| WHERE event.code == "4624" AND winlog.event_data.LogonType == "10"
| STATS distinct_hosts = COUNT_DISTINCT(host.name) BY source.ip, user.name, BUCKET(@timestamp, 1h)
| WHERE distinct_hosts >= 8
```

Plausible expected result: unchanged from the other five implementations. Interpretation: unchanged.

**[FALSE POSITIVE]** Helpdesk and support-desk accounts are the dominant driver — a technician legitimately RDPs into a dozen workstations during a morning shift. Fix by baselining and excluding known support-desk accounts/source hosts, or by comparing the count against that specific account's own trailing 30-day norm rather than one fleet-wide threshold (ties directly to DEH Part 31's baselining approach).

**[PIVOT]** For a flagged source, check whether the same account also shows `QC-16-06`'s directional hopping-chain shape rather than a flat fan-out, and pull the process-creation record on each destination to see whether the session ran only `explorer.exe` (routine interactive use) or a scripted tool.

### QC-16-06 — Sequential RDP hopping chain via the same account

| Field | Value |
|---|---|
| **Pattern ID** | `QC-16-06` |
| **MITRE** | T1021.001 (Remote Services: Remote Desktop Protocol) |
| **Behavior** | The same account authenticating via Type 10 RDP into host B, and shortly after, that same account authenticating via Type 10 RDP into host C from a source resolving to host B — a directional chain rather than a flat fan-out, consistent with using each newly reached host as the next jump point. |
| **DEH cross-ref** | DEH Part 8 (4624 Type 10); cf. DEH DET-27-01 (QRadar Building Block/Reference Set precedent for multi-object correlation) |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL (investigative single-search only, see note), YARA-L, Elastic EQL — Sigma: `N/A`, see below |

**[HUNTER]** `QC-16-05`'s fan-out catches one source hitting many destinations at once; it misses an attacker who deliberately moves one hop at a time to stay under a per-source threshold. The tell here is directional: host B shows up as a destination in one logon and then, within a short window, as the source of the next logon for the same account — a chain, not a burst.

Sigma: `N/A` — structurally poor fit, not impossible. Sigma's correlation grammar has a `temporal_ordered` type built for exactly this ordered-event shape, but per-backend support for it is narrow enough — most converters target single-event or simple-aggregation correlation — that forcing this chain through it would produce a rule most deployments can't actually execute. See STYLE-GUIDE.md §4.4.

**[QUERY]** KQL, Microsoft Sentinel, self-joining Type 10 logons on account and a 30-minute window.

CONCEPTUAL SAMPLE — resolving a logon's source IP to a previous logon's destination hostname is shown schematically; a real implementation needs a DNS/IP-to-hostname lookup step this block only gestures at.

```kql
let RdpLogons = SecurityEvent
| where EventID == 4624 and LogonType == 10
| project LogonTime = TimeGenerated, DestHost = Computer, SourceIp = IpAddress, Account;
RdpLogons
| join kind=inner (RdpLogons | project NextLogonTime = LogonTime, NextDestHost = DestHost, NextSourceIp = SourceIp, Account) on Account
| where NextLogonTime between (LogonTime .. LogonTime + 30m)
| where NextSourceIp == DestHost // illustrative: assumes SourceIp resolves to a hostname matching DestHost
| project Account, DestHost, NextDestHost, LogonTime, NextLogonTime
```

Plausible expected result: a small number of account/host-pair chains per week, each naming the first destination, the second destination, and the elapsed time between hops. Interpretation: consistent with one account moving hop-to-hop rather than one session touching many hosts at once; the join-key caveat above means a real hit still needs manual IP-to-hostname confirmation before acting on it.

**[QUERY]** SPL, Splunk, using `streamstats` to carry the previous destination forward per account.

CONCEPTUAL SAMPLE — `Source_Network_Address_resolved` assumes a lookup that resolves the source IP to a hostname; confirm this exists in your own pipeline.

```spl
index=wineventlog EventCode=4624 Logon_Type=10
| sort 0 _time
| streamstats current=f window=1 last(ComputerName) as prev_dest last(_time) as prev_time by Account_Name
| where Source_Network_Address_resolved=prev_dest AND (_time - prev_time) <= 1800
| table _time, Account_Name, prev_dest, ComputerName
```

Plausible expected result: unchanged from the KQL entry. Interpretation: unchanged, including the same join-key caveat.

**[QUERY]** AQL, QRadar — this is AQL, not standard SQL. Investigative single-search validation only: QRadar cannot express a directional, self-referencing chain as one standing AQL statement.

CONCEPTUAL SAMPLE — a standing chained-hop rule needs a Reference Set tracking "hosts reached via RDP in the last 30 minutes" fed by a Custom Rule (QRadar's Building Block/Reference Set/Rule model, per DEH Part 27 §2–§3; cf. DEH DET-27-01), not a single AQL statement. This query pulls the raw sequence for manual chain-walking.

```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS EventTime,
       sourceip, destinationip, username
FROM events
WHERE QIDNAME(qid) = 'An account was successfully logged on'
  AND "Logon Type" = 10
ORDER BY username, starttime ASC
LAST 4 HOURS
```

Plausible expected result: a time-ordered list of every Type 10 logon in the lookback window, which an analyst walks by eye or script for destination-becomes-next-source pairs. Interpretation: a manually confirmed chain is consistent with the same behavior the other languages express as a single query.

**[QUERY]** YARA-L, Google SecOps, matching two logon roles for the same principal.

CONCEPTUAL SAMPLE — the field used to compare a logon's destination hostname against the next logon's source hostname is illustrative and depends on your parser populating both consistently.

```yaral
rule rdp_hop_chain {
  meta:
    description = "Conceptual sample: same account's RDP destination host becomes the source of its next RDP hop within 30 minutes"
  events:
    $hop1.metadata.event_type = "USER_LOGIN"
    $hop1.additional.fields["LogonType"] = "10"
    $hop2.metadata.event_type = "USER_LOGIN"
    $hop2.additional.fields["LogonType"] = "10"
    $hop1.principal.user.userid = $hop2.principal.user.userid
    $hop1.target.hostname = $hop2.principal.hostname
  match:
    $hop1.principal.user.userid over 30m
  condition:
    $hop1 and $hop2 and $hop2.metadata.event_timestamp.seconds > $hop1.metadata.event_timestamp.seconds
}
```

Plausible expected result: unchanged. Interpretation: unchanged.

**[QUERY]** Elastic EQL — an ordered, joined multi-event pattern is `sequence`'s designed use case.

CONCEPTUAL SAMPLE — the join keys across the two `sequence` stages (`winlog.computerName` then `source.ip`) are shown schematically; real IP-to-hostname resolution is still required and not modeled here.

```eql
sequence by user.name with maxspan=30m
  [ authentication where winlog.event_data.LogonType == "10" ] by winlog.computerName
  [ authentication where winlog.event_data.LogonType == "10" ] by source.ip
```

Plausible expected result: unchanged from the other four implementations. Interpretation: unchanged.

**[FALSE POSITIVE]** IT staff performing a multi-host maintenance run are the dominant driver — a sysadmin legitimately RDPs host-to-host in sequence while patching a chain of adjacent servers in one session. A bastion or approved jump host will also constantly appear as both a destination and a source by design. Fix by excluding known bastion/jump-host identities from the "source becomes destination" join, not by excluding the whole account or widening the time window.

**[PIVOT]** For each hop, pull the interactive session's process tree — an `explorer.exe`-only session looks different from one that immediately launches another `mstsc.exe` or a scripted tool — and check whether the account's normal role plausibly needs access to every host in the chain.

**[SOC MANAGEMENT]** This pattern is exploratory by design: the join key (a source IP resolving to a previous hop's destination hostname) is fragile enough across NAT and hostname-resolution edge cases that most teams should run it as a periodic hunt — weekly is a reasonable starting cadence — rather than graduate it straight to a standing high-severity alert. Graduate it only after a baseline period confirms the bastion/jump-host false-positive rate is genuinely tunable in your environment; per DEH Part 41's coverage tiers, this pattern tends to sit at "exploratory" for months before earning "standing, tuned" status.

## Cross-references

This part's four analytics (PsExec-style service execution, WMI execution, WinRM/PowerShell remoting, RDP) build directly on telemetry mechanics taught in DEH Part 8 (Windows Security log fundamentals, especially 4624 Type 3/10) and DEH Part 11 §Endpoint (the process-tree view); query-language semantics for the joins and correlations used above are taught in DEH Parts 24–29 and DEH Appendix A5, and the multi-object QRadar precedent cited for `QC-16-02`/`QC-16-06` is DEH DET-27-01 (DEH Part 27 §2–§3). For hunt-cadence and graduation-to-detection scoring, see DEH Parts 41–43. Within this book, see Part 7 for the credential-theft techniques that often precede this part's patterns, Part 15 for the discovery activity that typically precedes lateral movement, and Part 17 for the stolen-token/ticket-reuse variant of lateral movement this part deliberately excludes; `QC-27-0x` in Part 27 stitches several of this part's patterns into worked end-to-end hunt chains.
