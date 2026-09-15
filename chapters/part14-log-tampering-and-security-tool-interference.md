---
title: "Log Tampering & Security Tool Interference"
part: 14
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 14 — Log Tampering & Security Tool Interference

## Why this part exists

**[CONCEPT]** An attacker who believes they've been noticed, or who has reached a stage where continued stealth stops paying off (immediately before encryption, immediately after establishing a durable foothold), will often trade stealth for capability: clear the evidence, kill the thing that would have caught them, or quietly narrow what gets logged in the first place. This is the "someone is trying to go dark" behavior class — audit-log clearing, EDR/AV tampering or uninstall attempts, and agent/telemetry-service-stop patterns — and it is simultaneously a defense-evasion technique in its own right and one of the highest-confidence signals available in a SOC, because almost nothing legitimate does any of this outside a documented maintenance window. DEH Part 11 §7 covers the underlying mechanics in depth; this part does not re-teach them, only cites the four query-pattern shapes that follow from that behavior class.

This part covers four patterns, at the bottom of this book's 4–6 pattern budget (per `BOOK-INDEX.md`) because the behavior class itself, while high-confidence, is narrower in query-shape variety than a part like brute force or C2 beaconing — most of the interesting variation here is in *which* telemetry source goes dark, not in a large number of distinct query logics. Two explicit boundaries against neighboring parts: Part 9 (LOLBins & Living-off-the-Land Execution) owns the general binary-abuse angle — `taskkill.exe`, `sc.exe`, and their kin appear there for execution and defense-evasion purposes broadly; this part owns the specific *outcome* of a security tool or log being silenced, regardless of which binary produced it. Part 23 (Ransomware Precursors) owns the pre-encryption *sequence* — discovery, credential access, and backup/shadow-copy tampering as a bundled early-warning chain; this part's patterns are cited into that chain (and into Part 27's hunt-chain narratives) rather than duplicated there, since a security-tool stop or log clear is a generic tampering signal independent of what follows it.

This part does not teach Sigma, KQL, SPL, AQL, YARA-L, or EQL syntax fundamentals — see DEH Parts 24–29 for language semantics and DEH Part 23 for the cross-language translation-loss framework each query below is implicitly built on. It also does not score these patterns' Detection Coverage, Quality, or Debt tier — see DEH Parts 41–43 for that methodology and this book's own Part 28 for how it applies to the cookbook's pattern catalog specifically.

## Patterns in this part

### QC-14-01 — Security event log cleared

| Field | Value |
|---|---|
| **Pattern ID** | `QC-14-01` |
| **MITRE** | T1070.001 (Indicator Removal: Clear Windows Event Logs) |
| **Behavior** | The Windows Security event log is explicitly cleared through the documented clear-log API, producing Event ID 1102 as the first record in the now-empty log. |
| **DEH cross-ref** | DEH Part 8 §9 (Log tampering: 1102; DET-08-03); DEH Part 45 (Ransomware Detection Model — 1102 as a late-stage "cover tracks" indicator) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** DEH Part 8 §9 already argues this should be a zero-tuning, always-page standing rule, so the case for *hunting* it rather than only waiting on that rule is narrower but real: confirming the standing rule is actually wired correctly end to end (right table, right forwarding path, right scope) across every collection point in the estate, since a broken pipeline here is invisible until the day it matters, and sweeping historical data after a suspected intrusion for a 1102 that predates when the detection was enabled, or that fired on a host outside the standing rule's scope — a newly onboarded subsidiary, an out-of-band jump box.

**[QUERY]** Sigma rule targeting the Windows Security channel wherever the backend lands it (Sentinel, Elastic, or a Splunk-via-Sigma-backend translation).

```yaml
# CONCEPTUAL SAMPLE — illustrative rule shape; validate against your own Sigma backend's Windows Security-log mapping before use
title: Windows Security Audit Log Cleared
id: 8e2d4b9a-14e1-4a2b-9a2f-6a1c0f140101
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
falsepositives:
  - Documented log-retention or disk-space maintenance run through a change-managed process
level: high
```

**Plausible expected result:** on a well-run estate this rule fires close to never over a 90-day lookback; a genuine hit returns exactly one record per clear action with `SubjectUserName` populated.

**Interpretation:** consistent with someone invoking the documented clear-log API — a well-instrumented environment would treat any hit outside a known maintenance ticket as a high-confidence indicator-removal event, not a "maybe."

**[QUERY]** Sentinel/Defender KQL against the `SecurityEvent` table, assuming ingestion via the Azure Monitor Agent or an equivalent Windows Security connector.

```kql
// CONCEPTUAL SAMPLE — assumes SecurityEvent table via AMA; verify table name if ingesting via WEF or a different connector
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account = SubjectUserName, SubjectDomainName
| order by TimeGenerated desc
```

**Plausible expected result:** a handful of rows at most across a 90-day window in a healthy estate; each row names a specific account and host.

**Interpretation:** any row outside a documented maintenance window warrants immediate Tier 2 escalation per DEH Part 8 §9's own SOC Management View framing.

**[QUERY]** Splunk SPL against a `WinEventLog:Security` sourcetype ingested through the standard Windows TA.

CONCEPTUAL SAMPLE — sourcetype and field names illustrative; validate against your own Windows TA's field extraction before use.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=1102
| table _time, ComputerName, user, EventCode
| sort - _time
```

**Plausible expected result:** near-zero daily hit rate; a genuine event returns `ComputerName` and `user` populated straight from the raw event.

**Interpretation:** same high-confidence read as above — treat any hit as indicator removal absent a documented ticket.

**[QUERY]** The following is AQL, QRadar's Ariel Query Language, not standard SQL. DEH Part 8 §9's own framing for this event — "no correlation needed, the event alone is the alert condition" — means the plain search below is sufficient without QRadar's multi-object Building Block/Reference Set/Rule chain (DEH Part 27 §2–§3).

CONCEPTUAL SAMPLE — field and log-source-name matching illustrative; validate against your own QRadar DSM's normalized fields for this log source before use.

```sql
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS eventTime,
       sourceip, username, "EventID" AS eventId
FROM events
WHERE "EventID" = 1102
  AND logsourcename(logsourceid) ILIKE '%Security%'
LAST 7 DAYS
```

**Plausible expected result:** typically zero rows in a 7-day window; a hit surfaces the acting username and source host directly.

**Interpretation:** same high-confidence read as above.

**[QUERY]** Google SecOps YARA-L, where a Windows Security-log clear normalizes into the UDM event type `SYSTEM_AUDIT_LOG_WIPE`.

```yaral
// CONCEPTUAL SAMPLE — UDM field/event-type mapping illustrative; validate against your own parser's normalization of Event ID 1102
rule security_log_cleared {
  meta:
    description = "Windows Security audit log cleared (Event ID 1102)"
    severity = "High"
  events:
    $e.metadata.event_type = "SYSTEM_AUDIT_LOG_WIPE"
    $e.metadata.product_event_type = "1102"
  condition:
    $e
}
```

**Plausible expected result:** one UDM match per clear action, with `principal.user.userid` populated from the acting account.

**Interpretation:** same high-confidence read — validate that your ingestion label actually maps 1102 into `SYSTEM_AUDIT_LOG_WIPE` before trusting a silent zero-result count as "clean," since an unmapped parser drops this event with no error.

**[QUERY]** A single-event boolean match is the cheapest Elastic surface for this pattern's shape (per DEH Appendix A5 §8's own decision table), so Elastic KQL is used here over a Winlogbeat- or Elastic-Agent-ingested Security channel.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own Winlogbeat/Elastic Agent mapping before use.

```kql
event.code : "1102" and winlog.channel : "Security"
```

**Plausible expected result:** near-zero background hits; a match returns `winlog.event_data.SubjectUserName` and `host.name`.

**Interpretation:** same high-confidence read as every other language above.

**[FALSE POSITIVE]** The only common legitimate trigger is a documented log-retention or disk-space-remediation action, almost always run by a named administrator during a change window — cross-check the acting account and timestamp against the change-ticket queue rather than building an exclusion list, since exempting any account by name (including a backup or maintenance service account) creates exactly the blind spot an attacker who compromises that same account would walk through. A narrower secondary driver: some third-party log-management or SIEM-agent installers clear the Security log once, as a step in their own initial deployment. Treat "within 24 hours of a new agent install" as a context flag worth checking, not a blanket exclusion.

**[PIVOT]** A 1102 hit only tells you the log was cleared, not what it was hiding. Pull the acting account's authentication history (4624/4625) and process-creation events from any telemetry source that predates the clear and survives independently of the local Security log — a network-based log shipper, an EDR cloud console, or a neighboring host's view of the same session. Cross-reference `QC-14-02`: a log clear alongside an EDR/AV service stop in the same session is a materially stronger going-dark signal than either alone.

> **SOC Management View**
> DEH Part 8 §9 already makes the case for a zero-tuning, always-page standing rule on 1102. This part's addition is the retrospective angle: after any confirmed intrusion, budget time for a full-estate historical sweep for 1102 predating the incident's known start date, reaching further back than your standard hot-retention window covers — a clear event sitting in cold storage from months earlier that nobody escalated at the time is a documented gap-discovery outcome this book has actually seen occur, not a hypothetical worst case.

---

### QC-14-02 — EDR/AV agent service stop, process kill, or uninstall attempt

| Field | Value |
|---|---|
| **Pattern ID** | `QC-14-02` |
| **MITRE** | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| **Behavior** | A known AV/EDR service is stopped through the Service Control Manager, a monitored agent process is killed via `taskkill`/`Stop-Process`, or the agent's own uninstall/repair tooling runs outside a change-managed patch window. |
| **DEH cross-ref** | DEH Part 11 §7 (Defense evasion and security-tool tampering) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Standing detections for this behavior typically allowlist the vendor's own signed update process — exactly the gap DEH Part 11 §7's own False Positive Trap names as the one an attacker abusing that same vendor's repair or uninstall tooling would walk through. A hunt that pulls every AV/EDR service-stop or process-kill event over a longer lookback and manually checks the initiating process's signer and path — rather than trusting the standing rule's allowlist — surfaces exactly the cases that rule was tuned to ignore.

**[QUERY]** Sigma rule against Windows process-creation telemetry, matching either a `taskkill`/`Stop-Process` invocation or an `sc.exe`/`net.exe` stop command referencing a known security-product name.

```yaml
# CONCEPTUAL SAMPLE — process/service name list illustrative; replace with your own EDR/AV vendor's actual process and service names
title: Security Product Process or Service Stopped
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_kill:
    Image|endswith: '\taskkill.exe'
    CommandLine|contains:
      - 'MsMpEng.exe'
      - 'SentinelAgent.exe'
      - 'CSFalconService.exe'
  selection_scstop:
    Image|endswith: '\sc.exe'
    CommandLine|contains: 'stop'
    CommandLine|re: '(?i)(defender|sense|sentinelone|crowdstrike|falcon)'
  condition: 1 of selection_*
falsepositives:
  - Signed vendor update or repair process stopping its own service during a scheduled upgrade
level: high
```

**Plausible expected result:** a match returns the command line invoking `taskkill` or `sc.exe` against a named security process or service, plus the parent process (commonly `cmd.exe` or `powershell.exe`) and the acting account.

**Interpretation:** consistent with an attempt to disable endpoint visibility — how strong that read is depends heavily on whether the initiating process is the vendor's own signed updater, covered in [FALSE POSITIVE] below.

**[QUERY]** Sentinel/Defender KQL against `DeviceProcessEvents` (Microsoft Defender for Endpoint's advanced-hunting schema).

```kql
// CONCEPTUAL SAMPLE — process/service name list illustrative; align with your own EDR vendor's binary and service names
DeviceProcessEvents
| where FileName in~ ("taskkill.exe", "sc.exe", "net.exe", "net1.exe")
| where ProcessCommandLine has_any ("MsMpEng", "SentinelAgent", "CSFalconService", "defender", "sense")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**Plausible expected result:** sparse rows; each names the host, acting account, and the parent process that spawned the kill/stop command.

**Interpretation:** a genuine hit outside a documented patch window is a strong going-dark signal, consistent with the Sigma read above.

**[QUERY]** Splunk SPL correlating Sysmon process-creation data against the same command-line indicators.

CONCEPTUAL SAMPLE — process/service name list illustrative; replace with your own EDR/AV vendor's actual process and service names.

```spl
index=sysmon (Image="*\\taskkill.exe" OR Image="*\\sc.exe" OR Image="*\\net.exe")
CommandLine="*MsMpEng*" OR CommandLine="*SentinelAgent*" OR CommandLine="*CSFalconService*" OR CommandLine="*defender*"
| table _time, ComputerName, User, ParentImage, Image, CommandLine
| sort - _time
```

**Plausible expected result:** rows show the parent-child pair (for example, `cmd.exe` spawning `taskkill.exe`) and the specific vendor string matched.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, not standard SQL. A plain event search suffices for the investigative hunt shown here; a standing rule that also cross-checks a signed-installer allowlist genuinely benefits from a QRadar Reference Set of known vendor-updater hashes — a lighter step up than the full Building Block/Reference Set/Rule chain DEH Part 27 §2–§3 describes for stateful multi-event sequences, since this pattern's core logic is still a single-event match.

CONCEPTUAL SAMPLE — process/service name list illustrative; replace with your own EDR/AV vendor's actual process and service names.

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS eventTime,
       username, "Process Name" AS processName, "Command" AS commandLine
FROM events
WHERE ("Process Name" ILIKE '%taskkill.exe%' OR "Process Name" ILIKE '%sc.exe%')
  AND ("Command" ILIKE '%MsMpEng%' OR "Command" ILIKE '%SentinelAgent%' OR "Command" ILIKE '%CSFalconService%' OR "Command" ILIKE '%defender%')
LAST 14 DAYS
```

**Plausible expected result:** a small result set; each row identifies the acting account and the matched vendor string.

**Interpretation:** same read as above.

**[QUERY]** Google SecOps YARA-L against UDM process-launch events.

```yaral
// CONCEPTUAL SAMPLE — UDM field/process-name list illustrative
rule security_tool_stopped {
  meta:
    description = "Known AV/EDR process or service stopped via CLI"
    severity = "High"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /(taskkill\.exe|sc\.exe)$/i
    $e.target.process.command_line = /(MsMpEng|SentinelAgent|CSFalconService|defender|sense)/i
  condition:
    $e
}
```

**Plausible expected result:** one match per kill/stop attempt, with the acting principal and command line intact.

**Interpretation:** same read as above — confirm your UDM parser actually populates `command_line` for this log source before trusting an empty result as clean.

**[QUERY]** Elastic KQL, chosen as the single-event boolean surface per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — process/service name list illustrative; align with your own EDR vendor's binary and service names.

```kql
event.category : "process" and process.name : ("taskkill.exe" or "sc.exe") and process.command_line : (*MsMpEng* or *SentinelAgent* or *CSFalconService* or *defender* or *sense*)
```

**Plausible expected result:** the same shape as the SPL/KQL variants above, surfaced through `process.parent.name` and `user.name`.

**Interpretation:** same read as every language above.

**[FALSE POSITIVE]** This is the one pattern in this part where the standing-detection allowlist is itself the trap, named directly in DEH Part 11 §7's own False Positive Trap: vendor agents routinely stop and relaunch their own service during a signed, scheduled upgrade — the identical stop-then-restart shape this hunt targets. Resolve it by checking the initiating process's signer and on-disk path against the vendor's known installer location and a change-managed patch window, not by exempting the service or process name outright; a bare name exemption is exactly the gap an attacker abusing that same vendor's own uninstall or repair flow would walk through.

**[PIVOT]** Check whether the same session also produced an audit-log clear (`QC-14-01`) or an audit-policy change (`QC-14-04`) — attackers rarely disable only one layer of visibility. Pull the parent-process tree back to the initial foothold (DEH Part 11 §2's lineage view), and check the EDR console's own tamper-protection or heartbeat status directly, since a successfully disabled agent stops reporting its own disablement.

> **Blind Spot**
> Every query above keys on a command-line string or the literal `taskkill.exe`/`sc.exe` binary name. An attacker who calls the Win32 `OpenSCManager`/`ControlService` APIs directly from a custom binary or a scripting host's P/Invoke wrapper, or who simply renames the CLI tool before running it, still stops the service — but produces process-creation and command-line telemetry with no matching string in it at all, and none of the six queries above fire. Pair this pattern with the Service Control Manager's own System-log event (7036, service entered the stopped state) keyed on the *service name* rather than the stopping process, as a second, tool-independent detection layer.

---

### QC-14-03 — Telemetry pipeline killed outright, with no corresponding log-clear event

| Field | Value |
|---|---|
| **Pattern ID** | `QC-14-03` |
| **MITRE** | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| **Behavior** | The logging/telemetry-generation pipeline itself — the Sysmon service, an EDR driver, the Linux `auditd` daemon, or a syslog/log-forwarder process — is stopped or unloaded outright, producing a drop in expected telemetry volume rather than a discrete "log cleared" event. |
| **DEH cross-ref** | DEH Part 11 §7–§7.1 (security-tool tampering; the forwarding-race Blind Spot); DEH Part 3 §5.2 (Telemetry Engineering I: Host and Identity Sources — the auditd service-stop vs. rule-disable boundary) |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL, Elastic (ES\|QL) — Sigma and YARA-L: `N/A`, see below |

**[HUNTER]** The whole point of this behavior is that the tampering event itself may never leave the host — DEH Part 11 §7.1's own Blind Spot names this directly: a locally stopped logging agent doesn't get to forward its own "I was just stopped" event. This pattern hunts the effect instead of the cause: a host that was producing a steady baseline volume of Sysmon or auditd events suddenly drops to zero while other telemetry from the same host — network flow, a domain controller's view of its authentication traffic, an EDR cloud heartbeat — shows it is still up and reachable. That gap, not any single event, is the signal.

*Sigma: `N/A` — Aggregation ceiling. Sigma's correlation object model expresses group-by count thresholds (the `event_count` correlation type) but has no reference-implementation primitive for a sub-threshold, "fewer events than an expected baseline" condition across most backends — a map-reduce-style translation target has no row to filter when the count is genuinely zero, absent an explicit expected-population join the correlation spec doesn't model. This pattern is a backend-specific custom build here, not portable Sigma.*

**[QUERY]** Sentinel/Defender KQL, joining hourly Sysmon-sourced event volume against `Heartbeat` table liveness for the same host and window.

```kql
// CONCEPTUAL SAMPLE — bucket width and drop condition illustrative; baseline against your own per-host Sysmon volume before trusting this as a cutoff
let bucket = 1h;
let sysmonVolume = Event
    | where Source == "Microsoft-Windows-Sysmon"
    | summarize SysmonEvents = count() by Computer, bin(TimeGenerated, bucket);
let hostUp = Heartbeat
    | summarize HeartbeatCount = count() by Computer, bin(TimeGenerated, bucket);
hostUp
| join kind=leftouter sysmonVolume on Computer, TimeGenerated
| where HeartbeatCount > 0 and isnull(SysmonEvents)
| project TimeGenerated, Computer, HeartbeatCount
```

**Plausible expected result:** an empty result set on a fleet with healthy Sysmon coverage; a hit names a specific host and hour where the agent heartbeat continued but Sysmon volume fell to zero.

**Interpretation:** consistent with the Sysmon service or its ETW provider being stopped or unloaded on an otherwise-live host — this threshold is illustrative and needs validation against your own steady-state per-host volume before use as a cutoff, per this book's honesty standard.

**[QUERY]** Splunk SPL, comparing hourly Sysmon volume against a separate EDR-agent heartbeat index for the same host.

CONCEPTUAL SAMPLE — index names and bucket width illustrative; baseline against your own per-host Sysmon volume before trusting this as a cutoff.

```spl
| tstats count as sysmon_count where index=sysmon by host, _time span=1h
| append
    [ | tstats count as heartbeat_count where index=edr_heartbeat by host, _time span=1h ]
| stats sum(sysmon_count) as sysmon_count, sum(heartbeat_count) as heartbeat_count by host, _time
| where heartbeat_count > 0 AND sysmon_count=0
```

**Plausible expected result:** near-zero rows on a healthy estate; a hit shows a specific host-hour with a live heartbeat and zero Sysmon volume.

**Interpretation:** same read as the KQL block above.

**[QUERY]** The following is AQL, not standard SQL. This search validates the pattern for a single investigative pull; graduating it into a standing alert on live data genuinely needs QRadar's Anomaly Detection Rule object — a time-series baseline-and-deviation engine, a different multi-object model than the Building Block/Reference Set/Rule chain DEH Part 27 §2–§3 describes for stateful sequences, but a multi-object step up from the plain search below all the same (per this book's "still show the investigative search" convention rather than marking the language `N/A` for this reason).

CONCEPTUAL SAMPLE — bucket width illustrative; validate against your own per-host Sysmon volume baseline before use.

```sql
SELECT hostname, HOUR(starttime) AS hourBucket, COUNT(*) AS sysmonEvents
FROM events
WHERE logsourcename(logsourceid) ILIKE '%Sysmon%'
GROUP BY hostname, hourBucket
LAST 24 HOURS
```

**Plausible expected result:** a per-host, per-hour count; a bucket with zero rows for a host that is present elsewhere in the SIEM over the same window (in an authentication or heartbeat search, for instance) is the signal, not any single returned row.

**Interpretation:** consistent with a Sysmon outage on that host for that hour — a genuine finding requires cross-checking against a second, independent presence signal, since AQL's own result set cannot natively express "this host should have rows here and doesn't."

*YARA-L: `N/A` — Structurally poor fit, not impossible. YARA-L's `events:`/`condition:` block matches events that occurred; expressing "zero Sysmon events for a host that's otherwise active" requires joining against an external expected-activity or entity-presence table the single-rule model doesn't natively carry. It is achievable only by pairing a YARA-L rule with a separate Risk Analytics or entity-graph job outside this pattern's one-rule skeleton, per DEH Part 28 §1.1's precedent for YARA-L schema gaps.*

**[QUERY]** Elastic ES\|QL, chosen because this pattern's shape is a threshold/wide-lookback aggregation across two data streams, which ES\|QL's `STATS ... BY` bucketing fits directly per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — index pattern and bucket width illustrative; validate against your own installed ES\|QL version and data-stream naming before use.

```esql
FROM logs-sysmon*, metrics-endpoint.heartbeat*
| STATS sysmon_events = COUNT(*) WHERE data_stream.dataset == "sysmon",
        heartbeat_events = COUNT(*) WHERE data_stream.dataset == "heartbeat"
        BY host.name, BUCKET(@timestamp, 1h)
| WHERE heartbeat_events > 0 AND sysmon_events == 0
```

**Plausible expected result:** the same shape as the KQL/SPL variants — a host-hour with a live heartbeat and zero Sysmon documents.

**Interpretation:** same read as above; the multi-index `STATS`-with-filter syntax shown here is illustrative and should be checked against your installed ES\|QL version, since aggregation-with-filter syntax has changed across recent Elastic releases.

**[FALSE POSITIVE]** Patch-window reboots, agent upgrades that briefly restart the Sysmon service or the `auditd` daemon, and any host genuinely powered off for maintenance all produce the same zero-volume signature. The heartbeat/liveness cross-check built into every query above resolves the reboot case specifically — a host with no heartbeat either is simply down, not tampered with — but it does not distinguish a legitimate agent upgrade from a malicious stop. Correlate the gap's start time against your patch-management calendar before escalating, and treat any gap without a matching documented change as the higher-priority read.

**[PIVOT]** Once a genuine gap is confirmed, check the host's System log (Windows) or `systemd` journal (Linux) for a service-stop event naming the specific agent — Event ID 7036 for Sysmon on Windows, or a `systemctl` unit-stop entry or `CONFIG_CHANGE` audit record for `auditd` on Linux — at the gap's start boundary; that record usually survives even though the agent's own telemetry doesn't, because a different subsystem writes it. Also check `QC-14-02` for a co-occurring AV/EDR stop in the same window; a simultaneous drop across both the logging pipeline and the detection engine is a materially stronger going-dark signal than either alone.

> **Engineering Reality**
> A workstation that's genuinely idle overnight can produce a real Sysmon volume of zero for an hour without anything being wrong — process creation, network connection, and image-load events all depend on something actually happening on the box. Treating any single zero-count hour as an alert on a per-host basis, without first establishing that host's own idle-hours baseline (DEH Part 31), produces a flood of overnight false positives on laptops and lightly used workstations; this pattern reads far more reliably against servers and always-on infrastructure with a known non-zero idle floor.

---

### QC-14-04 — Audit policy or auditd rules weakened without a full clear

| Field | Value |
|---|---|
| **Pattern ID** | `QC-14-04` |
| **MITRE** | T1562.002 (Impair Defenses: Disable Windows Event Logging) for the Windows form; T1562.006 (Impair Defenses: Indicator Blocking) for the Linux `auditd` variant |
| **Behavior** | The audit policy itself is narrowed rather than cleared or stopped — Windows `auditpol.exe` disables a logging subcategory (Event ID 4719), or Linux `auditctl` disables auditing (`-e 0`) or flushes existing rules (`-D`) — while the logging daemon or service keeps running, so nothing visibly disappears. |
| **DEH cross-ref** | DEH Part 8 §7 (Account, group, and audit policy changes: 4719); DEH Part 11 §7 (DET-11-06, the `auditctl -e 0` Detection Test); DEH Part 3 §5.2 (why this is T1562, not T1070.002, on Linux) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** 4719 and `auditctl -e 0`/`-D` are quieter than a full log clear or a service stop, because nothing visibly disappears — the daemon is still running and the log file still exists, it's simply no longer being fed the categories that matter. DEH Part 8 §7 names the hard part directly: a legitimate audit-policy retune and an attacker narrowing coverage to cover tracks produce an identical event; the hunt has to read the resulting policy state, not just the fact that a change happened.

#### Variant: Windows audit-policy subcategory disable (Event ID 4719)

**[QUERY]** Sigma rule matching a 4719 where the `AuditPolicyChanges` field shows a subcategory being removed rather than added.

```yaml
# CONCEPTUAL SAMPLE — subcategory-change field illustrative; align with your own Advanced Audit Policy baseline
title: Audit Policy Subcategory Disabled
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4719
    AuditPolicyChanges|contains: 'REMOVED'
  condition: selection
falsepositives:
  - Documented audit-policy retune reducing genuinely over-logging noise (e.g., trimming a chatty Object Access subcategory)
level: medium
```

**Plausible expected result:** a match returns the acting account and the affected subcategory ID whenever the recorded change removes a logging category.

**Interpretation:** worth queuing for review on its own, weighted heavily by which subcategory was touched — see [FALSE POSITIVE] below for why this alone isn't a verdict.

**[QUERY]** Sentinel/Defender KQL against `SecurityEvent`.

```kql
// CONCEPTUAL SAMPLE — validate the SubcategoryGuid-to-name mapping against your own environment before relying on a name filter
SecurityEvent
| where EventID == 4719
| where AuditPolicyChanges has "Removed"
| project TimeGenerated, Computer, SubjectUserName, SubcategoryGuid, AuditPolicyChanges
```

**Plausible expected result:** sparse rows; each names the account and the specific subcategory GUID that lost logging coverage.

**Interpretation:** same read as the Sigma block above.

**[QUERY]** Splunk SPL against `WinEventLog:Security`.

CONCEPTUAL SAMPLE — field names illustrative; align with your own Windows TA's `AuditPolicyChanges` field extraction before use.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4719 AuditPolicyChanges="*Removed*"
| table _time, ComputerName, user, Subcategory, AuditPolicyChanges
```

**Plausible expected result:** the same shape as the KQL block.

**Interpretation:** same read.

**[QUERY]** The following is AQL, not standard SQL.

CONCEPTUAL SAMPLE — raw-payload field access illustrative; validate against your own QRadar normalization for this event before use.

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS eventTime,
       username, "EventID" AS eventId, UTF8(payload) AS rawPayload
FROM events
WHERE "EventID" = 4719
  AND UTF8(payload) ILIKE '%Removed%'
LAST 14 DAYS
```

**Plausible expected result:** sparse rows; `rawPayload` carries the raw `AuditPolicyChanges` text needed to confirm which subcategory lost coverage, since QRadar's default normalized fields often don't expose this event's changed-category detail directly.

**Interpretation:** same read — queue for review weighted by subcategory.

**[QUERY]** Google SecOps YARA-L.

```yaral
// CONCEPTUAL SAMPLE — UDM event type/field names illustrative
rule audit_policy_subcategory_removed {
  meta:
    description = "Windows audit policy subcategory logging disabled (Event ID 4719)"
    severity = "Medium"
  events:
    $e.metadata.event_type = "USER_CHANGE_PERMISSIONS"
    $e.metadata.product_event_type = "4719"
    $e.security_result.summary = /Removed/i
  condition:
    $e
}
```

**Plausible expected result:** one match per policy change where the summary field indicates a removed category.

**Interpretation:** same read; verify your parser actually maps 4719 into a UDM event carrying the removed/added detail before trusting a zero-result count as clean.

**[QUERY]** Elastic KQL, chosen as the single-event boolean surface.

CONCEPTUAL SAMPLE — field name illustrative; validate against your own Winlogbeat/Elastic Agent mapping before use.

```kql
event.code : "4719" and winlog.event_data.AuditPolicyChanges : *Removed*
```

**Plausible expected result:** the same shape as the other blocks above.

**Interpretation:** same read.

#### Variant: Linux auditd rule disable or flush (`auditctl -e 0` / `-D`)

**[QUERY]** Sigma rule against a Linux `auditd` logsource, matching either the auditing-disabled config-change record or an all-rules-deleted marker.

```yaml
# CONCEPTUAL SAMPLE — key/field names illustrative for an auditd-via-auditbeat or ausearch pipeline
title: Auditd Rules Disabled or Flushed
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection_disable:
    type: 'CONFIG_CHANGE'
    audit_enabled: '0'
  selection_flush:
    key: 'delete-all-rules'
  condition: 1 of selection_*
falsepositives:
  - Documented auditd rule-set redeploy through a configuration-management run
level: medium
```

**Plausible expected result:** a `CONFIG_CHANGE` record showing `audit_enabled` transitioning from 1 to 0, or a delete-all-rules marker, tied to the acting UID.

**Interpretation:** consistent with an attempt to blind the audit trail without stopping the daemon outright. DEH Part 11 §7's DET-11-06 Detection Test validates the local-record side of this; confirming the record left the host before the forwarder itself would have gone dark is the harder, separate check described in that same section's Blind Spot.

**[QUERY]** Splunk SPL against a Linux audit index.

CONCEPTUAL SAMPLE — index and field names illustrative for a Linux audit pipeline; validate against your own ingestion before use.

```spl
index=linux_audit type=CONFIG_CHANGE (audit_enabled=0 OR key="delete-all-rules")
| table _time, host, uid, type, audit_enabled, key
```

**Plausible expected result:** the same shape as the Sigma match above.

**Interpretation:** same read.

**[QUERY]** Elastic KQL against `auditd`-sourced documents.

CONCEPTUAL SAMPLE — field names illustrative for an auditd-via-auditbeat pipeline; validate against your own mapping before use.

```kql
event.dataset : "auditd.log" and auditd.data.audit_enabled : "0"
```

**Plausible expected result:** the same shape as above.

**Interpretation:** same read. The KQL (Sentinel), AQL, and YARA-L equivalents follow the same logic against each platform's own Linux-audit ingestion path and are not repeated here in full — the Windows-variant blocks above already establish this pattern's coverage across all six languages.

**[FALSE POSITIVE]** A routine audit-policy retune that trims a genuinely over-logging subcategory (Object Access on a file server with verbose SACLs, for example) and a legitimate configuration-management run that redeploys an intentionally narrower `auditd` rule set both produce the exact events this pattern targets. DEH Part 8 §7 names the only real distinguishing signal: whether the resulting policy state makes operational sense. A narrowed Logon or credential-related subcategory immediately preceding other suspicious activity is not routine; require a change ticket for every legitimate retune and treat any change without one as the higher-priority read, rather than trying to build a keyword-based exclusion.

**[PIVOT]** Pull the full `AuditPolicyChanges` detail (Windows) or the surrounding `auditctl -l`/rule-file diff (Linux) to see exactly which categories lost coverage, not just that a change occurred — a change touching only a noisy, low-value subcategory reads very differently from one that strips Logon or Object Access coverage right before a suspected lateral-movement window. Cross-reference `QC-14-01` and `QC-14-03`: an audit-policy narrowing that co-occurs with either a log clear or an outright agent stop in the same session is a strong three-signal pattern, not three unrelated findings.

> **What Would Change My Mind**
> This pattern treats any undocumented narrowing of Logon or Object Access auditing as high-priority. If a production audit showed that a large fraction of legitimate retunes routinely touch exactly those two subcategories for ordinary noise-reduction reasons — rather than the credential- and lateral-movement-adjacent categories this pattern assumes attackers target — the priority weighting above would need to shift toward a subcategory-specific allowlist built from real change-ticket history, not a blanket "these two categories matter more" assumption.

---

## Cross-references

- DEH Part 8 §7 and §9 (Windows Detection Engineering — 4719 and 1102) for the underlying event mechanics behind `QC-14-01` and `QC-14-04`.
- DEH Part 11 §7–§7.1 (Endpoint Detection Engineering — defense evasion and security-tool tampering, including DET-11-06 and the forwarding-race Blind Spot) for the mechanics behind `QC-14-02` and `QC-14-03`.
- DEH Part 3 §5.2 (Telemetry Engineering I: Host and Identity Sources) for the T1562.001-vs-T1070.002 boundary this part relies on for the Linux `auditd` variant of `QC-14-04`.
- DEH Part 31 (Baselining) for constructing the per-host idle-hours baseline `QC-14-03`'s Engineering Reality box depends on.
- DEH Parts 24–29 and Appendix A5 for the Sigma/KQL/SPL/AQL/YARA-L/EQL syntax fundamentals this part assumes rather than teaches.
- DEH Parts 41–43 and this book's own Part 28 for how these four patterns would be scored on the Detection Coverage/Quality/Debt scales rather than this part inventing its own scoring.
- This book's Part 9 (LOLBins & Living-off-the-Land Execution) and Part 23 (Ransomware Precursors) for the explicit scope boundaries stated in "Why this part exists" above.
- This book's Part 27 (Multi-Behavior Hunt Chains) as the likely destination for a chain that cites `QC-14-01` through `QC-14-04` alongside earlier-stage patterns from Parts 15, 22, and 23.
