---
title: "Ransomware Precursors"
part: 23
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 23 — Ransomware Precursors

## Why this part exists

**[CONCEPT]** Human-operated ransomware is not one event; it's a sequence of stages, and by the time file content is actually being encrypted, detection can only affect containment speed, not the outcome. DEH Part 45 §1 builds the full six-stage kill-chain model behind that claim — initial access, discovery, credential access, lateral movement, backup/shadow-copy tampering, and encryption — and weights the backup/shadow-copy stage as the single highest-value pre-encryption signal, because inhibiting recovery is close to mandatory for an attacker who wants leverage, unlike discovery or lateral movement, where a narrow operation might skip steps. This part assumes that model and goes straight to query shapes for the three stages a hunter can still act on before anything is lost: backup/shadow-copy tampering, and the specifically ransomware-shaped slices of discovery and credential access that precede it.

This part's scope is deliberately narrow, and the boundary against neighboring parts is explicit rather than assumed. It does not re-hunt generic host and directory enumeration — `net view`, `nltest`, BloodHound-shaped queries run for any reason — which is this book's Part 15 (Host & Directory Discovery); this part only covers the discovery shape that specifically converges on recovery infrastructure. It does not re-hunt Kerberoasting, DCSync, or ticket theft mechanics, which are this book's Part 7 (Kerberos & Directory Credential Attacks); this part only covers what happens *after* a theft signal already exists, when the same host or account turns toward backup-admin targeting. It does not cover mass file staging or archival with ambiguous intent, which is this book's Part 21 (Insider Threat & Data Staging). And it explicitly does not include an encryption-stage query pattern: DEH Part 45 §7's mass file-modification-rate detection (DET-45-04) is framed there as containment on a case that has already failed, and restating it here as a ready-to-adapt pattern would contradict the pre-encryption weighting this entire part is built around — a hunter looking for that stage's detection should read DEH Part 45 §7 directly.

**[SOC MANAGEMENT]** Two of this part's five patterns (QC-23-01, QC-23-02) sit close enough to the point of no return that DEH Part 45 §10's zero-tolerance, immediate-escalation policy for backup-tampering alerts applies to their cookbook form too — a false-positive rate on either one is a scoping problem to fix in the allowlist, not a reason to route the alert through a normal queue. QC-23-03 and QC-23-05 are join/hunt-shaped patterns that depend on another pattern's own output; they make sense as a scheduled hunt run against recent history, not as standing rules with their own independent cadence. QC-23-04 tunes into a standing correlation rule once its backup/hypervisor-naming keyword list is validated against your own environment, following the same graduation logic this book's Part 5 (Password Spraying) applies to its own density-based patterns.

## 1. Backup and shadow-copy tampering patterns

### QC-23-01 — Destructive shadow-copy or backup-catalog command

| Field | Value |
|---|---|
| **Pattern ID** | `QC-23-01` |
| **MITRE** | T1490 (Inhibit System Recovery) |
| **Behavior** | A process invokes a destructive Volume Shadow Copy or Windows Server Backup command (delete or shrinking resize) from a parent process that isn't an allowlisted backup agent. |
| **DEH cross-ref** | DEH Part 45 §6.1 (DET-45-01 — Volume Shadow Copy and Windows Backup deletion) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** Deleting shadow copies and backup catalogs is close to a mandatory step for an operator who wants ransom leverage — a victim with intact, reachable backups can often just restore and ignore the demand. Hunt this ahead of trusting a standing rule's own tuning, because the discriminator that actually matters is parent-process identity, not binary name, and that allowlist is rarely complete on day one. Reach for this specifically once QC-23-03's enumeration-without-deletion hunt, or any of Part 7's credential-theft patterns, has already flagged the host — a destructive VSS command with no such company is a colder lead than one that has some.

**[QUERY]** Windows Sysmon Event ID 1 (Process Create) or Event ID 4688 (A new process has been created), expressed as a Sigma detection with an explicit backup-agent exclusion.

```yaml
title: Destructive Volume Shadow Copy or Backup Catalog Command
id: 9d2f7a3e-1b4c-4e2a-8f6d-2c7b1a9e3d54
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\vssadmin.exe'
      - '\wmic.exe'
      - '\diskshadow.exe'
      - '\wbadmin.exe'
  selection_verbs:
    CommandLine|contains:
      - 'delete shadows'
      - 'delete catalog'
      - 'delete systemstatebackup'
      - 'shadowcopy delete'
      - 'resize shadowstorage'
  filter_backup_agent:
    ParentImage|endswith:
      - '\veeam.backup.service.exe'
      - '\wbengine.exe'
  condition: selection_image and selection_verbs and not filter_backup_agent
```

CONCEPTUAL SAMPLE — binary list, verb list, and parent-process allowlist illustrative, adapted from DEH Part 45 §6.1's DET-45-01; validate against your own backup-agent inventory before deploying.

Plausible expected result: with the allowlist reasonably complete, low single digits of matches per month across a mid-sized estate. Interpretation: a match from a non-allowlisted parent is consistent with active recovery-inhibition ahead of encryption — treat it as high-confidence regardless of time of day, not as routine backup-job noise.

**[QUERY]** Microsoft Defender for Endpoint's `DeviceProcessEvents` table via Sentinel.

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("vssadmin.exe", "wmic.exe", "diskshadow.exe", "wbadmin.exe")
| where ProcessCommandLine has_any (
      "delete shadows", "delete catalog", "delete systemstatebackup",
      "shadowcopy delete", "resize shadowstorage")
| where InitiatingProcessFileName !in~ ("veeam.backup.service.exe", "wbengine.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

CONCEPTUAL SAMPLE — field names and allowlist illustrative, adapted from DEH Part 45 §6.1's DET-45-01; validate the allowlist against your own backup tooling.

Plausible expected result: rows carrying the full `ProcessCommandLine` with a destructive verb and an `InitiatingProcessFileName` that reads as an ordinary shell or scheduled-task host, not a known backup binary. Interpretation: unchanged from the Sigma form above.

**[QUERY]** Splunk SPL against a Sysmon-for-Windows index.

```spl
index=wineventlog (EventCode=1 OR EventCode=4688) Image IN ("*\\vssadmin.exe","*\\wmic.exe","*\\diskshadow.exe","*\\wbadmin.exe")
| search CommandLine="*delete shadows*" OR CommandLine="*delete catalog*" OR CommandLine="*delete systemstatebackup*" OR CommandLine="*shadowcopy delete*" OR CommandLine="*resize shadowstorage*"
| search NOT ParentImage IN ("*veeam.backup.service.exe","*wbengine.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
```

CONCEPTUAL SAMPLE — field names assume a standard Sysmon-for-Windows TA mapping; verify against your own field extraction.

Plausible expected result and interpretation: the same shape as the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL, per this book's disambiguation convention) against a process-creation event source.

```sql
SELECT devicetime, username, hostname, "process name", "command line", "parent process name"
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Microsoft Windows Security Event Log'
  AND "process name" IN ('vssadmin.exe','wmic.exe','diskshadow.exe','wbadmin.exe')
  AND ("command line" ILIKE '%delete shadows%' OR "command line" ILIKE '%delete catalog%' OR "command line" ILIKE '%delete systemstatebackup%' OR "command line" ILIKE '%shadowcopy delete%' OR "command line" ILIKE '%resize shadowstorage%')
  AND "parent process name" NOT IN ('veeam.backup.service.exe','wbengine.exe')
LAST 1 HOURS
```

CONCEPTUAL SAMPLE — assumes a process-creation DSM extension already exposes `"process name"`, `"command line"`, and `"parent process name"` as queryable fields; without that extension these arrive as unparsed payload text, not columns.

Plausible expected result: one row per offending event inside the search window. Interpretation: identical to the other surfaces above; a zero-result run is only trustworthy once the DSM mapping is confirmed current.

**[QUERY]** Google SecOps YARA-L over `PROCESS_LAUNCH` UDM events.

```yaral
rule destructive_vss_backup_deletion {
  meta:
    description = "Destructive VSS or backup-catalog command from a non-allowlisted parent"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = $image
    $e.target.process.command_line = $cmd
    $e.principal.process.file.full_path = $parent
  match:
    $image, $cmd, $parent over 5m
  outcome:
    $risk_score = 85
  condition:
    $e and $image in %vss_backup_binaries and $cmd in %destructive_verbs and $parent not in %allowlisted_backup_agents
}
```

CONCEPTUAL SAMPLE — `%vss_backup_binaries`, `%destructive_verbs`, and `%allowlisted_backup_agents` assume reference lists defined elsewhere in your rule set; UDM field paths illustrative.

Plausible expected result: a single detection instance per qualifying event, bound to the offending image/command/parent triple. Interpretation: unchanged from the other surfaces above.

**[QUERY]** Elastic KQL, chosen over EQL or ES\|QL because this is a single-event boolean match with a simple exclusion, not a sequence or an aggregation (per DEH Appendix A5 §8's decision table).

```kql
process.name : ("vssadmin.exe" or "wmic.exe" or "diskshadow.exe" or "wbadmin.exe") and process.command_line : ("*delete shadows*" or "*delete catalog*" or "*delete systemstatebackup*" or "*shadowcopy delete*" or "*resize shadowstorage*") and not process.parent.name : ("veeam.backup.service.exe" or "wbengine.exe")
```

CONCEPTUAL SAMPLE — field names assume a standard ECS process mapping; disambiguated here as Elastic KQL, not Sentinel/Defender KQL.

Plausible expected result and interpretation: unchanged from the other surfaces above.

**[FALSE POSITIVE]** Backup agents legitimately issue these exact destructive verbs as part of ordinary retention-policy pruning; a spike in hits from one specific parent process almost always means new or reconfigured backup tooling nobody added to the allowlist yet, not a sudden change in attacker behavior — fix the allowlist rather than suppressing the rule. Separately, every language above depends entirely on process-creation telemetry reaching the pipeline: a host with its EDR sensor or Sysmon service stopped or tampered with (T1562) produces zero events from every query shown here, indistinguishable from "no tampering occurred." Pair this pattern with a log-source heartbeat check (DEH Part 5's canary-event monitoring) and treat a previously-reporting host going silent as its own alert, not a clean result.

**[PIVOT]** Check whether the same host or account produced a QC-23-03 enumeration hit in the preceding 72 hours, or a QC-23-05 credential-theft-to-backup-targeting chain. Check for an Event ID 1102 (The audit log was cleared) near the same timestamp. Note this pattern only matches four named binaries — an operator who deletes shadow copies via the `Win32_ShadowCopy` WMI class's own `Delete()` method (for example `Get-CimInstance Win32_ShadowCopy | Remove-CimInstance`) spawns none of them and evades every query above while achieving the identical outcome; treat this pattern as covering the common case, not the ceiling of shadow-copy deletion techniques.

> **Detection Autopsy — "alert on any execution of vssadmin.exe"**
>
> **The rule:** Fires on every process-creation event where the image name is `vssadmin.exe`, regardless of arguments or parent process.
>
> **Why it shipped:** VSS deletion is the headline ransomware behavior, `vssadmin.exe` is the tool nearly every write-up names, and matching the binary name alone is a one-line filter that's trivial to justify in a design review.
>
> **How it failed:** Windows Server Backup, Veeam, and most enterprise backup agents invoke `vssadmin.exe` constantly for ordinary snapshot creation, listing, and retention-driven pruning. On an estate with backup agents deployed broadly, this fires dozens of times a night, every night, none of it an attacker — and the analyst who has to triage it learns within a week that a `vssadmin.exe` alert means "check if it's the backup job," at which point the rule has trained its own dismissal.
>
> **The fix:** Restrict to the destructive verbs and exclude by parent-process identity against a reviewed backup-agent allowlist, exactly as the six query forms above do — not by excluding the binary name itself, which would blind the rule to an attacker who happens to run it from an allowlisted-looking process.

---

### QC-23-02 — Backup or hypervisor service stopped with no matching restart

| Field | Value |
|---|---|
| **Pattern ID** | `QC-23-02` |
| **MITRE** | T1489 (Service Stop) |
| **Behavior** | A backup-agent or hypervisor-management service transitions to stopped and produces no matching start within a validated maintenance-window baseline (illustrated here as 30 minutes). |
| **DEH cross-ref** | DEH Part 45 §6.2 (DET-45-02 — Backup/hypervisor service stopped with no matching restart); DEH Part 31 (Baselining, for the legitimate restart-cycle baseline this pattern depends on) |
| **Languages covered** | Sigma — `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L — `N/A`, see below; Elastic (ES\|QL) |

**[HUNTER]** An attacker who stops a backup agent ahead of encryption produces exactly half the sequence a legitimate deploy or patch cycle produces — the stop, with nothing coming back. Hunt this by comparing each service's most recent stop against its most recent start, rather than alerting on any stop in isolation, since a lone stop event is indistinguishable from routine maintenance; the absence of a matching start past a validated baseline window is the actual signal. Run this ahead of trusting a standing rule's maintenance-window suppression list, since that list is usually built for application servers first and rarely covers backup infrastructure completely.

> **N/A note — Sigma.** *Aggregation ceiling.* None of Sigma's four correlation types (`value_count`, `event_count`, `temporal`, `temporal_ordered` — DEH Appendix A5 §4) assert the *absence* of a later event; all four confirm that something did happen within a window, not that something failed to happen, which is exactly what "a stop with no matching start" needs to express.

**[QUERY]** Sentinel KQL against a service-state-change table (Windows Event ID 7036, "The service entered the running/stopped state," or an equivalent forwarded source).

```kql
ServiceStateEvents
| where ServiceName in ("veeam-agent", "backup-agent", "wbengine", "vmware-hostd")
| summarize LastStop = maxif(TimeGenerated, EventType == "stop"),
            LastStart = maxif(TimeGenerated, EventType == "start")
      by Host, ServiceName
| where isnotempty(LastStop) and (isempty(LastStart) or LastStart < LastStop)
| extend MinutesWithoutRestart = datetime_diff('minute', now(), LastStop)
| where MinutesWithoutRestart > 30
```

CONCEPTUAL SAMPLE — table and field names illustrative, adapted from DEH Part 45 §6.2's DET-45-02; map `ServiceStateEvents` to whatever ingests your Windows Event ID 7036 or syslog service-state events.

Plausible expected result: a small number of host/service pairs per run, each with a `LastStop` timestamp and no `LastStart` after it, `MinutesWithoutRestart` comfortably over 30. Interpretation: consistent with a service deliberately stopped and left down; cross-check against any active, ticketed maintenance window before escalating.

**[QUERY]** Splunk SPL against forwarded syslog/journald from Linux hosts running backup agents.

```spl
index=linux_syslog sourcetype IN ("journald","syslog") service_name IN ("veeam-agent","backup-agent")
| eval event_type=case(
    match(_raw, "(?i)stopping|deactivated|stopped"), "stop",
    match(_raw, "(?i)starting|started"), "start")
| stats latest(eval(if(event_type="stop", _time, null()))) as last_stop_time
        latest(eval(if(event_type="start", _time, null()))) as last_start_time
      by host service_name
| where isnotnull(last_stop_time) AND (isnull(last_start_time) OR last_start_time < last_stop_time)
| eval minutes_without_restart = (now() - last_stop_time) / 60
| where minutes_without_restart > 30
```

CONCEPTUAL SAMPLE — directly adapted from DEH Part 45 §6.2's DET-45-02; the `latest()` construction must reference each event type's own most recent timestamp, not the search window's earliest event, or a host with multiple stop/restart cycles gets mislabeled as never having restarted.

Plausible expected result and interpretation: the same framing as the KQL form above. ESXi's `hostd` telemetry needs a separate query against its own syslog format — it is not Linux and does not emit journald, so this exact regex does not extend to it unmodified.

**[QUERY]** QRadar AQL (not standard SQL) — the investigative single-host check an analyst runs by hand before building the standing multi-object version. A deployed QRadar detection for this pattern needs a Reference Set tracking each service's last-stop time, updated by a Building Block, with a second rule testing elapsed time since that reference-set entry (DEH Part 27 §2's model); AQL alone cannot compute "the latest of two event types per entity, compared, with an elapsed-time filter" as one query.

```sql
SELECT devicetime, hostname, "service name", "service state"
FROM events
WHERE "service name" IN ('veeam-agent','backup-agent','wbengine','vmware-hostd') -- paste in the flagged service
  AND hostname = 'backupsrv01' -- paste in the flagged host
ORDER BY devicetime DESC
LAST 1 DAYS
```

CONCEPTUAL SAMPLE — hostname and service name are illustrative placeholders; this pulls the raw state-change history for one host/service pair so an analyst can read the stop/start sequence directly.

Plausible expected result: an ordered list of state-change rows. Interpretation: unchanged from the other surfaces — the finding is the same, only the mechanism producing it differs.

> **N/A note — YARA-L.** *Aggregation ceiling.* YARA-L's `outcome` section aggregates over events that did match; it has no construction for "the most recent start event for this entity is missing or older than the most recent stop," the same class of gap the Sigma note above documents for a negative, absence-based condition.

**[QUERY]** Elastic ES\|QL, chosen because this is a threshold/comparison shape over the whole lookback rather than an ordered sequence.

```esql
FROM logs-service.state*
| WHERE service.name IN ("veeam-agent", "backup-agent", "wbengine", "vmware-hostd")
| STATS last_stop = MAX(CASE(event.action == "stop", @timestamp, NULL)),
        last_start = MAX(CASE(event.action == "start", @timestamp, NULL))
      BY host.name, service.name
| WHERE last_stop IS NOT NULL AND (last_start IS NULL OR last_start < last_stop)
| EVAL minutes_without_restart = DATE_DIFF("minutes", last_stop, NOW())
| WHERE minutes_without_restart > 30
```

CONCEPTUAL SAMPLE — field and index names illustrative; ES\|QL's single `STATS` stage with conditional `CASE` aggregates is what keeps this a one-query shape where Sigma and YARA-L cannot follow.

Plausible expected result and interpretation: unchanged from the KQL/SPL forms above.

**[FALSE POSITIVE]** An OS patch-cycle reboot stops the backup-agent service as a side effect of shutdown, and if the reboot plus post-boot service-startup-ordering delay exceeds the 30-minute threshold, this fires on ordinary maintenance. Exclude hosts inside an active, ticketed maintenance window rather than raising the threshold across the board — a longer threshold gives a real attacker more time before the alert fires too.

**[PIVOT]** Check whether the same host produced a QC-23-01 destructive-VSS hit or a QC-23-05 credential-theft chain around the same time. Check for T1562 defense-tampering events on the same host. Confirm against the change-management ticket system for an active, approved maintenance window before escalating.

> **Engineering Reality**
> Treating "Linux backup agent" and "ESXi hypervisor management" as the same query with a bigger service-name list is the mistake this pattern's SPL form warns against explicitly. ESXi's `hostd` does not run systemd or journald; its stop/start wording, timestamp format, and forwarding path (typically a syslog export or a vCenter/vSphere-specific collector) are structurally different from the Linux journal lines this pattern's regex matches. A query that "covers" hypervisor infrastructure by adding `vmware-hostd` to a Linux-shaped service-name list will silently produce zero rows for that host forever, and a silent zero looks identical to "the hypervisor was never touched."

---

### QC-23-03 — Shadow-copy or snapshot enumeration without a follow-on deletion

| Field | Value |
|---|---|
| **Pattern ID** | `QC-23-03` |
| **MITRE** | T1490 (Inhibit System Recovery) |
| **Behavior** | A shadow-copy or snapshot *listing* command runs from a non-allowlisted parent, with no matching QC-23-01 destructive command following on the same host within 72 hours. |
| **DEH cross-ref** | DEH Part 45 §9.1 (HUNT-45-01 — Shadow-copy and snapshot enumeration without deletion) |
| **Languages covered** | Sigma — `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L — `N/A`, see below; Elastic (ES\|QL) |

**[HUNTER]** QC-23-01 only ever matches the destructive verb, so an operator who lists existing shadow copies to plan the deletion — or who lists them and hasn't run the destructive step yet — produces nothing for that pattern to catch. This hunt closes that gap by pulling every listing-style command and checking whether a matching destructive hit ever follows, so a negative finding ("this enumeration never escalated") is itself useful evidence, and a positive finding (no destructive hit yet, but the listing already happened) is a genuine leading indicator worth acting on before deletion occurs.

> **N/A note — Sigma.** *Aggregation ceiling.* This pattern needs a negated join between two independently-matched base rules across a 72-hour window — an absence-of-a-later-match-from-a-different-rule condition none of Sigma's correlation types express, the same structural gap QC-23-02 names for the single-rule version of this problem.

**[QUERY]** Sentinel KQL, joining an enumeration event list against a materialized destructive-event list.

```kql
let Enumeration = DeviceProcessEvents
| where FileName in~ ("vssadmin.exe", "wmic.exe")
| where ProcessCommandLine has_any ("list shadows", "shadowcopy list")
| where InitiatingProcessFileName !in~ ("veeam.backup.service.exe", "wbengine.exe");
let Destructive = DeviceProcessEvents
| where FileName in~ ("vssadmin.exe", "wmic.exe", "diskshadow.exe", "wbadmin.exe")
| where ProcessCommandLine has_any ("delete shadows", "delete catalog", "shadowcopy delete");
Enumeration
| join kind=leftanti (Destructive) on DeviceName
| where Timestamp > ago(30d)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

CONCEPTUAL SAMPLE — the 72-hour destructive-follow-up window is collapsed to a whole-history `leftanti` join by host here for readability; bind `Destructive` to the 72 hours after each `Enumeration` row's own timestamp rather than the full 30-day window, or the join will over-exclude hosts that were destructively hit long before or after an unrelated enumeration event.

Plausible expected result: a handful of listing events per month with no matching destructive event on the same host in the lookback. Interpretation: a hit is a leading indicator, not a confirmed compromise — most will turn out to be a backup administrator manually checking snapshot state, which is exactly why parent-process allowlisting still matters here.

**[QUERY]** Splunk SPL, approximating the same join with a subsearch.

```spl
index=wineventlog (EventCode=1 OR EventCode=4688) Image IN ("*\\vssadmin.exe","*\\wmic.exe")
| search (CommandLine="*list shadows*" OR CommandLine="*shadowcopy list*")
| search NOT ParentImage IN ("*veeam.backup.service.exe","*wbengine.exe")
| eval enum_time=_time
| join type=left ComputerName
    [ search index=wineventlog (EventCode=1 OR EventCode=4688) (CommandLine="*delete shadows*" OR CommandLine="*delete catalog*" OR CommandLine="*shadowcopy delete*")
      | eval destructive_time=_time | fields ComputerName destructive_time ]
| where isnull(destructive_time) OR destructive_time > enum_time + 259200
| table enum_time, ComputerName, User, CommandLine
```

CONCEPTUAL SAMPLE — the 259200-second (72-hour) bound and the subsearch join are illustrative; SPL's `join` here is a coarse approximation, not a guaranteed per-event pairing.

Plausible expected result and interpretation: the same shape as the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL) — the investigative single-host check. A standing QRadar version needs a Reference Set recording each enumeration event's timestamp per host and a second rule checking for a destructive match inside the following 72 hours (DEH Part 27 §2's model), since AQL cannot express the negated cross-rule join as one query.

```sql
SELECT devicetime, username, "process name", "command line", "parent process name"
FROM events
WHERE "process name" IN ('vssadmin.exe','wmic.exe','diskshadow.exe','wbadmin.exe')
  AND hostname = 'fileserver03' -- paste in the flagged host
ORDER BY devicetime ASC
LAST 30 DAYS
```

CONCEPTUAL SAMPLE — pulls every VSS-related command for one host across 30 days so an analyst can read the listing-then-deletion sequence directly.

Plausible expected result: an ordered command history for the flagged host. Interpretation: unchanged from the KQL/SPL forms above.

> **N/A note — YARA-L.** *Aggregation ceiling.* Same gap as QC-23-02's YARA-L note, compounded here by needing to reference a second rule's own non-match rather than a second event type inside one rule's `events` block.

**[QUERY]** Elastic ES\|QL, chosen over EQL because this is a negated join — EQL's `sequence` stage confirms events that did happen and has no construction for "no matching second event followed," the same absence-based gap the Sigma and YARA-L notes above name; a `LOOKUP JOIN` against a materialized index of QC-23-01's own hits.

```esql
FROM logs-endpoint.events.process*
| WHERE process.name IN ("vssadmin.exe", "wmic.exe") AND process.command_line RLIKE ".*(list shadows|shadowcopy list).*"
| RENAME @timestamp AS enum_time
| LOOKUP JOIN destructive_vss_hits ON host.name
| WHERE destructive_time IS NULL OR destructive_time > enum_time + 259200000
| KEEP enum_time, host.name, user.name, process.command_line
```

CONCEPTUAL SAMPLE — `destructive_vss_hits` assumes a materialized lookup index of QC-23-01's own output already exists; ES\|QL's `LOOKUP JOIN` needs that index built ahead of time, and the 259200000-millisecond bound is illustrative.

Plausible expected result and interpretation: unchanged from the KQL/SPL forms above.

**[FALSE POSITIVE]** A backup administrator checking existing restore points before pruning old snapshots runs the identical listing command an attacker would run for reconnaissance — the parent-process allowlist narrows this the same way it does for QC-23-01, but a manual interactive check from an admin's own workstation won't carry a backup-agent parent process and will still surface here. Treat a hit from a known admin account with no destructive follow-up as low-confidence unless it recurs against hosts that account doesn't normally manage.

**[PIVOT]** Watch the flagged host for a QC-23-01 hit specifically over the following 72 hours — this pattern's entire value is the early warning before that destructive hit lands. Cross-check whether the account running the enumeration also appears in an open QC-23-05 credential-theft chain.

> **Blind Spot**
> This pattern only sees enumeration performed as a local process on the Windows host running the listing binary. An operator who lists VM snapshots through vCenter's own API or PowerCLI against the hypervisor management plane, rather than `vssadmin.exe`/`wmic.exe` on the guest, produces no local process-creation event for any query above to catch — the actual reconnaissance happens entirely inside vCenter's own audit log, a telemetry source this pattern doesn't query at all. Extending coverage to the hypervisor-native path needs a separate query against vCenter/ESXi audit events, not a variant of this one.

## 2. Discovery and credential-access precursor patterns

### QC-23-04 — Discovery command density targeting recovery infrastructure

| Field | Value |
|---|---|
| **Pattern ID** | `QC-23-04` |
| **MITRE** | No clean single-technique mapping — see [HUNTER] framing (spans T1082, T1083, T1018, T1087) |
| **Behavior** | A single host/session runs several distinct discovery-shaped commands in a short window, with at least one command referencing a backup, hypervisor, or disaster-recovery naming pattern. |
| **DEH cross-ref** | DEH Part 45 §3 (Discovery stage — sequence-and-density framing); DEH Part 30 (Correlation Engineering, entity keys); DEH Part 31 (Baselining) |
| **Languages covered** | Sigma — `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (ES\|QL) |

**[HUNTER]** No individual command here is rare enough to alert on alone — `net view`, `nltest /domain_trusts`, and `whoami /all` run constantly in help-desk scripts. What distinguishes ransomware staging is density (several distinct discovery command types from one session in a tight window) combined with a target that reads as recovery infrastructure specifically. This differs from this book's Part 15, which hunts the same command family without requiring that backup/hypervisor-naming signal and would flag broad IT enumeration this pattern deliberately ignores. Reach for this hunt once a host has already shown up in QC-23-01 through QC-23-03, or ahead of them as an earlier-stage lead in its own right.

> **N/A note — Sigma.** *Aggregation ceiling.* `value_count` can threshold a distinct-value count for one field, but it has no way to additionally require that at least one contributing event also satisfy a second, different predicate within the same group. Pre-filtering the base rule to only backup/hypervisor-keyword commands (as an earlier draft of this pattern did) doesn't substitute for that — it silently changes the requirement to "five distinct commands that *all* reference the keyword," which is a much narrower, rarely-occurring condition than this pattern's stated "several distinct commands, at least one referencing recovery infrastructure." Expressing the compound condition correctly needs two aggregates evaluated together, which none of Sigma's four correlation types support in a single rule object.

**[QUERY]** Sentinel KQL. Counts distinct discovery-tool commands regardless of content, then separately checks that at least one of them carried a backup/hypervisor keyword — the two conditions are deliberately kept apart so the density threshold isn't silently restricted to keyword-bearing commands only.

```kql
DeviceProcessEvents
| where FileName in~ ("net.exe","net1.exe","nltest.exe","whoami.exe","dsquery.exe","arp.exe")
| summarize DistinctCommands = dcount(ProcessCommandLine),
            Commands = make_set(ProcessCommandLine, 10),
            BackupKeywordHits = countif(ProcessCommandLine has_any ("backup","veeam","esxi","vcenter","dr-"))
      by DeviceName, AccountName, bin(Timestamp, 15m)
| where DistinctCommands >= 5 and BackupKeywordHits >= 1
```

CONCEPTUAL SAMPLE — keyword list and both thresholds illustrative; adapt the naming-pattern list to your own environment's backup/hypervisor host and share names.

Plausible expected result: a `Commands` set spanning several discovery tool types, not repeated invocations of one tool, with `BackupKeywordHits` at 1 or more. Interpretation: repeated calls to the same single tool (a monitoring agent polling `whoami` on a fixed schedule, for example) should not count toward the density threshold — the distinct-command-type framing is deliberate, and a hit built entirely from one tool run many times is a weaker lead than one spanning several tools.

**[QUERY]** Splunk SPL, with the same density-plus-keyword split as the KQL form above.

```spl
index=wineventlog (EventCode=1 OR EventCode=4688) Image IN ("*\\net.exe","*\\net1.exe","*\\nltest.exe","*\\whoami.exe","*\\dsquery.exe","*\\arp.exe")
| bin _time span=15m
| stats dc(CommandLine) as distinct_commands values(CommandLine) as commands
        count(eval(match(CommandLine, "(?i)backup|veeam|esxi|vcenter|dr-"))) as backup_keyword_hits
      by ComputerName, User, _time
| where distinct_commands >= 5 AND backup_keyword_hits >= 1
```

CONCEPTUAL SAMPLE — field names and keyword list illustrative.

Plausible expected result and interpretation: the same shape as the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL), same split: an overall distinct-command count and a separate count of how many of those commands carried a backup/hypervisor keyword.

```sql
SELECT hostname, username, UNIQUECOUNT("command line") AS distinct_commands,
       SUM(CASE WHEN "command line" ILIKE '%backup%' OR "command line" ILIKE '%veeam%' OR "command line" ILIKE '%esxi%' OR "command line" ILIKE '%vcenter%' OR "command line" ILIKE '%dr-%' THEN 1 ELSE 0 END) AS backup_keyword_hits
FROM events
WHERE "process name" IN ('net.exe','net1.exe','nltest.exe','whoami.exe','dsquery.exe','arp.exe')
GROUP BY hostname, username
HAVING distinct_commands >= 5 AND backup_keyword_hits >= 1
LAST 15 MINUTES
```

CONCEPTUAL SAMPLE — assumes the same process-creation DSM extension as QC-23-01's AQL form; the conditional `SUM(CASE ...)` aggregate is illustrative syntax, not a verified AQL construct — validate against your own QRadar version. `HAVING` filters on the `distinct_commands`/`backup_keyword_hits` aliases rather than the raw aggregate expressions, per IBM's only documented AQL `HAVING` pattern (IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5: https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html).

Plausible expected result and interpretation: the same shape as the other surfaces above.

**[QUERY]** Google SecOps YARA-L, computing the overall distinct-command count and the keyword-matching subset as two separate outcome variables rather than gating the whole match on the keyword.

```yaral
rule discovery_density_targeting_backup_infra {
  meta:
    description = "Several distinct discovery commands from one session, at least one referencing backup/hypervisor naming"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = $image
    $e.target.process.command_line = $cmd
    $e.principal.hostname = $host
    $e.principal.user.userid = $user
  match:
    $host, $user over 15m
  outcome:
    $distinct_commands = count_distinct($cmd)
    $backup_keyword_hits = count_distinct($cmd, $cmd in %backup_naming_keywords)
  condition:
    $e and $image in %discovery_tools and $distinct_commands >= 5 and $backup_keyword_hits >= 1
}
```

CONCEPTUAL SAMPLE — `%discovery_tools` and `%backup_naming_keywords` assume reference lists defined elsewhere; UDM field paths illustrative; the conditional form of `count_distinct` shown for `$backup_keyword_hits` approximates "distinct count among only the keyword-matching events" and should be checked against your own YARA-L version's supported aggregate syntax.

Plausible expected result and interpretation: unchanged from the other surfaces above.

**[QUERY]** Elastic ES\|QL (threshold/aggregation shape), with the density count and the keyword-hit count computed as two separate `STATS` aggregates rather than pre-filtering rows to keyword matches before counting.

```esql
FROM logs-endpoint.events.process*
| WHERE process.name IN ("net.exe","net1.exe","nltest.exe","whoami.exe","dsquery.exe","arp.exe")
| STATS distinct_commands = COUNT_DISTINCT(process.command_line),
        backup_keyword_hits = COUNT(CASE(process.command_line RLIKE ".*(backup|veeam|esxi|vcenter|dr-).*", 1, NULL))
      BY host.name, user.name, BUCKET(@timestamp, 15 minutes)
| WHERE distinct_commands >= 5 AND backup_keyword_hits >= 1
```

CONCEPTUAL SAMPLE — same keyword and threshold caveats as the other surfaces above.

Plausible expected result and interpretation: unchanged from the other surfaces above.

**[FALSE POSITIVE]** A backup or virtualization administrator's own routine troubleshooting session produces the identical shape — several distinct discovery commands, naturally referencing backup/hypervisor names, because that's their actual job. Baseline which accounts belong to the backup/virtualization team and exclude their routine hours and known jump hosts explicitly, rather than raising the distinct-command threshold, which would just make an attacker who already knows to spread commands out slightly harder to catch for no real gain against the admin-noise case.

**[PIVOT]** Check whether the session's account also appears in QC-23-05's credential-theft chain, or shows up as the initiating account in a later QC-23-01/QC-23-02 hit — density plus naming alone is a lead, not a confirmed precursor, and its value comes almost entirely from what it connects to next.

---

### QC-23-05 — Credential theft followed by backup-admin targeting

| Field | Value |
|---|---|
| **Pattern ID** | `QC-23-05` |
| **MITRE** | T1552 (Unsecured Credentials) — following an upstream credential-theft event whose own mapping is this book's Part 7 territory |
| **Behavior** | A host or account already flagged by an existing credential-theft signal subsequently enumerates a "Backup Operators"-equivalent privileged group, or accesses a known backup-product credential store, within 24 hours. |
| **DEH cross-ref** | DEH Part 45 §4 (Credential access stage — what the combination means); this book's Part 7 (Kerberos & Directory Credential Attacks) for the upstream theft event this pattern joins against |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (EQL) |

**[HUNTER]** Credential-theft telemetry — LSASS access, Kerberoasting, DCSync — is already Part 7's territory, and alone it says nothing about intent, since most credential access never touches backup infrastructure at all. What's worth a dedicated hunt is the combination: a host that already produced a credential-theft signal, followed within a day by that same host or account enumerating a backup-admin group or touching a Veeam/Backup Exec credential-manager path, is a materially stronger ransomware-precursor lead than either event alone — mirroring DEH Part 45 §4's own point that this stage's value is in the join, not in re-deriving detections Part 7 already owns.

**[QUERY]** Sigma `temporal_ordered` correlation between an upstream credential-theft base rule and a backup-targeting base rule, same host, ordered, within 24 hours.

```yaml
title: Credential Theft Followed by Backup-Admin Targeting
id: 7a1e9c3b-4d2f-4b8a-9e6c-3f1a7d2b9c48
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - lsass_access_credential_theft
    - backup_credential_or_group_targeting
  group-by:
    - ComputerName
  timespan: 24h
---
title: LSASS Access Consistent with Credential Theft
id: lsass_access_credential_theft
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1010'
  condition: selection
---
title: Backup Credential Store or Privileged Group Targeting
id: backup_credential_or_group_targeting
logsource:
  category: process_creation
  product: windows
detection:
  selection_group:
    CommandLine|contains: 'Backup Operators'
  selection_credstore:
    CommandLine|contains:
      - 'Veeam\Backup\CredsManager'
      - 'CredsManager'
  condition: 1 of selection_*
```

CONCEPTUAL SAMPLE — the LSASS `GrantedAccess` value and the backup-targeting command-line strings are illustrative, adapted from DEH Part 45 §4's framing and DEH Part 11's own LSASS-access canonical example; validate against your own Sysmon Event ID 10 configuration.

Plausible expected result: a correlation instance naming one `ComputerName` with both base rules firing in order inside the 24-hour window. Interpretation: consistent with an operator pivoting from a fresh credential straight into backup-admin reconnaissance; treat this as a materially higher-confidence lead than either base rule alone.

**[QUERY]** Sentinel KQL, joining an existing credential-theft output against a later backup-targeting event on the same host.

```kql
let CredentialTheftHosts = SecurityEvent
| where EventID == 10 and TargetImage endswith "lsass.exe" and GrantedAccess == "0x1010"
| project DeviceName = Computer, TheftTime = TimeGenerated;
DeviceProcessEvents
| where ProcessCommandLine has "Backup Operators" or ProcessCommandLine has "CredsManager"
| join kind=inner CredentialTheftHosts on DeviceName
| where Timestamp between (TheftTime .. (TheftTime + 24h))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, TheftTime
```

CONCEPTUAL SAMPLE — `CredentialTheftHosts` is written here as a direct LSASS-access query for illustration; in practice, point this at whichever of Part 7's own tables or saved queries already materializes your credential-theft output, rather than re-deriving that logic in this pattern.

Plausible expected result and interpretation: the same as the Sigma form above; a row here pairs a specific backup-targeting command with the theft event that preceded it on the same host.

**[QUERY]** Splunk SPL, joining a saved credential-theft search against later backup-targeting activity.

```spl
| savedsearch part7_credential_theft_hits
| rename Computer as theft_host, _time as theft_time
| join type=inner theft_host
    [ search index=wineventlog (EventCode=1 OR EventCode=4688) (CommandLine="*Backup Operators*" OR CommandLine="*CredsManager*")
      | rename ComputerName as theft_host ]
| where _time <= theft_time + 86400
| table _time, theft_host, User, CommandLine, theft_time
```

CONCEPTUAL SAMPLE — assumes a saved search named `part7_credential_theft_hits` already materializes an upstream Part 7 pattern's output; build that search first.

Plausible expected result and interpretation: unchanged from the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL) — the investigative single-host check. A standing QRadar version needs a Reference Set populated by Part 7's own credential-theft rule, tested against by a second rule here (DEH Part 27 §2's model), since AQL cannot join two independently-scored rules' outputs as one query.

```sql
SELECT logontime, username, "command line"
FROM events
WHERE ("command line" ILIKE '%Backup Operators%' OR "command line" ILIKE '%CredsManager%')
  AND hostname = 'jumphost04' -- paste in the host a Part 7 pattern already flagged
LAST 1 DAYS
```

CONCEPTUAL SAMPLE — the hostname is an illustrative placeholder pasted in from whatever Part 7 pattern's output already flagged the host.

Plausible expected result and interpretation: unchanged from the other surfaces above.

**[QUERY]** Google SecOps YARA-L, matching an LSASS-access event followed by backup-targeting on the same host.

```yaral
rule credential_theft_then_backup_targeting {
  meta:
    description = "LSASS access followed by backup-admin group or credential-store targeting on the same host"
  events:
    $theft.metadata.event_type = "PROCESS_OPEN"
    $theft.target.process.file.full_path = "%lsass_path%"
    $theft.principal.hostname = $host
    $target.metadata.event_type = "PROCESS_LAUNCH"
    $target.target.process.command_line = $cmd
    $target.principal.hostname = $host
    $target.metadata.event_timestamp.seconds > $theft.metadata.event_timestamp.seconds
  match:
    $host over 24h
  condition:
    $theft and $target and $cmd in %backup_targeting_strings
}
```

CONCEPTUAL SAMPLE — `%lsass_path%` and `%backup_targeting_strings` assume reference values defined elsewhere; UDM field paths illustrative.

Plausible expected result and interpretation: unchanged from the other surfaces above.

**[QUERY]** Elastic EQL, chosen because this is an ordered, joined multi-event shape rather than a threshold aggregation (per DEH Appendix A5 §8's decision table).

```eql
sequence by host.name with maxspan=24h
  [process where event.action == "open" and process.name == "lsass.exe" and winlog.event_data.GrantedAccess == "0x1010"]
  [process where process.command_line : ("*Backup Operators*", "*CredsManager*")]
```

CONCEPTUAL SAMPLE — `GrantedAccess` value illustrative; validate against your own Sysmon Event ID 10 configuration.

Plausible expected result and interpretation: unchanged from the other surfaces above.

**[FALSE POSITIVE]** A help-desk or backup-team member who legitimately has both LSASS-adjacent tooling (an EDR agent's own scan, a credential-vault sync client) and a real job function enumerating "Backup Operators" membership produces the same two-event shape with no theft occurring. The LSASS-access half of this join inherits whatever false-positive population Part 7's own upstream pattern already carries — this pattern adds nothing to filter that half out on its own. Cross-check the account's normal role before escalating; an account with a documented backup-administration function triggering this chain during business hours is a much weaker lead than the same chain on an account with no such function.

**[PIVOT]** Pull the account's authentication history against the actual backup management console or API in the following hours — a successful login there is the strongest available confirmation that this chain escalated beyond reconnaissance. Also check whether the same host appears in QC-23-03's enumeration-without-deletion hunt.

> **What Would Change My Mind**
> This pattern's 24-hour join window assumes a ransomware operator moves from credential theft to backup-admin targeting inside roughly a day. DEH Part 45 §8 already flags that human-operated crews documented in incident retrospectives routinely take days to weeks between stages on this exact kill chain. If that slower pacing turns out to dominate the crews actually targeting your environment, this pattern's window would need to widen well past 24 hours, at the cost of a weaker join — and at some window length the two events stop being meaningfully connected at all, at which point this pattern's value degrades back to evaluating Part 7's upstream signal alone.

## Cross-references

This part's queries adapt DEH Part 45 in full — §1 for the kill-chain weighting behind why three stages get five patterns here and encryption gets none, §6.1/§6.2 for QC-23-01/QC-23-02's direct DET-45-01/DET-45-02 adaptations, §9.1 for QC-23-03's HUNT-45-01 adaptation, §3 for QC-23-04's discovery-density framing, and §4 for QC-23-05's credential-access-combination framing — plus DEH Part 11 (Endpoint Detection Engineering) for LSASS-access mechanics, DEH Part 30 (Correlation Engineering) and DEH Part 31 (Baselining) for the entity-resolution and restart-cycle-baseline dependencies named throughout, DEH Part 5 (Parsers) for the log-source heartbeat monitoring cited against silent sensor loss, DEH Part 27 §2 (QRadar AQL) for the Building Block/Reference Set model behind every AQL investigative-only query in this part, and DEH Appendix A5 §4/§8 for the aggregation-ceiling and Elastic-surface-selection reasoning cited throughout. See this book's Part 7 (Kerberos & Directory Credential Attacks) for the upstream credential-theft mechanics QC-23-05 joins against, Part 15 (Host & Directory Discovery) for the generic enumeration hunting this part's discovery patterns deliberately don't duplicate, Part 21 (Insider Threat & Data Staging) for mass-archival behavior with ambiguous rather than ransomware-specific intent, Part 22 (Malware Indicators) for general-purpose malicious-execution artifact hunting once a host is already compromised, and Part 5 (Password Spraying) for the graduation-to-standing-detection cadence this part's own `[SOC MANAGEMENT]` note follows.
