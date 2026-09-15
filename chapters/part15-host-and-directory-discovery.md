---
title: "Host & Directory Discovery"
part: 15
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 15 — Host & Directory Discovery

## Why this part exists

**[CONCEPT]** Discovery (ATT&CK tactic TA0007) is the step between landing on a host and doing anything consequential with that foothold: an attacker who has just gained code execution does not yet know what account they are, what that account can reach, or what the domain around them looks like, and every one of the behaviors below is a way of answering one of those three questions using tools the operating system or the directory service already ships. None of the five patterns in this part require the attacker to bring anything custom — that is exactly what makes them worth hunting rather than waiting on a signature.

This part's scope is native and directory-service discovery run from an already-landed foothold: Windows built-in account/group/host enumeration (`whoami`, `net`, `systeminfo`), domain-trust and controller-topology enumeration (`nltest`), BloodHound/SharpHound-shaped LDAP directory walks, PowerShell/.NET-based directory-services reconnaissance, and the Linux equivalents of the same orientation checklist. It draws an explicit boundary against four neighboring parts so none of them silently overlaps:

- **Part 3 (Scanning & Enumeration)** owns network- and service-level scanning and share/service enumeration across the wire; this part owns commands run *on* a host or *against* the directory from a single already-compromised identity, not port- or service-sweep behavior.
- **Part 7 (Kerberos & Directory Credential Attacks)** owns the credential-*theft* events (Kerberoasting, AS-REP roasting, DCSync) that a directory walk in this part frequently precedes and informs; this part stops at reconnaissance and does not re-cover the theft itself.
- **Part 11 (Account Creation & Privilege Escalation)** owns what an attacker does to create or escalate an account; this part owns the discovery of accounts, groups, and trust relationships that already exist.
- **Part 16 (Lateral Movement via Admin Tools & Remote Services)** owns what happens once an attacker acts on a discovery hit to reach a second host; every `[PIVOT]` below hands off to that part rather than re-deriving it.

Primary DEH cross-references for this part: DEH Part 11 §2 (Process trees and lineage classification) for the command-line/process-creation detection model every pattern here leans on, and DEH Part 13 §7 (LDAP enumeration and directory reconnaissance) for the directory-specific telemetry reasoning behind `QC-15-03` and `QC-15-04`.

---

### QC-15-01 — Native Windows account, group, and host discovery command burst

| Field | Value |
|---|---|
| **Pattern ID** | `QC-15-01` |
| **MITRE** | T1087.001 (Account Discovery: Local Account) — the same burst commonly also serves T1033 (System Owner/User Discovery) and T1069.001 (Permission Groups Discovery: Local Group); tag an individual hit against whichever technique its specific command fits, and treat this header's mapping as the burst-level umbrella. |
| **Behavior** | Two or more of `whoami`, `net user`, `net localgroup administrators`, and `systeminfo` run from one process lineage on one host inside a short window. |
| **DEH cross-ref** | DEH Part 11 §2 (Process trees and lineage classification) — the process-command-line detection model this pattern's telemetry depends on. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) — all six covered. |

**[HUNTER]** A foothold that has just landed almost always needs to answer "what account am I, what can I do, and what is this box" before doing anything else, and the fastest way to answer that with zero custom tooling is the four commands above. Waiting on a standing detection tuned to a fleet-wide count threshold means accepting whatever false-negative rate that threshold buys; a hunt run directly against a specific host right after a suspected initial-access event doesn't need a threshold at all, because a human reviewing the raw hits can treat two of these commands from one lineage inside a few minutes as worth a look, well below the volume a fleet-wide rule would need to avoid drowning in helpdesk noise.

**[QUERY]** Sigma — targets Sysmon Event ID 1 (Process Create) or Event ID 4688 (A new process has been created) with command-line auditing enabled, matching any single discovery binary and leaving the multi-binary correlation to the analyst reviewing raw hits grouped by parent lineage.

CONCEPTUAL SAMPLE — binary and parent-process exclusion lists illustrative; validate both against your own RMM/helpdesk inventory before use.

```yaml
title: Windows discovery-binary execution (whoami/net/systeminfo)
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\whoami.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\systeminfo.exe'
  filter_known_tools:
    ParentImage|endswith:
      - '\CcmExec.exe'
      - '\ConnectWiseControl.ClientService.exe'
  condition: selection and not filter_known_tools
fields:
  - ParentProcessGuid
  - CommandLine
```

**Expected result:** one row per discovery-binary launch, with `ParentProcessGuid` as the grouping key an analyst uses to spot two or more distinct binaries sharing one lineage. **Interpretation:** a single row from a known admin or monitoring tool's lineage is routine; two or more distinct binaries from the same non-admin lineage inside a few minutes is consistent with an attacker orienting on a newly landed host.

**[QUERY]** KQL (Sentinel/Defender) — targets `DeviceProcessEvents` in Microsoft Defender Advanced Hunting.

CONCEPTUAL SAMPLE — window size and threshold illustrative; validate against your own baseline before use.

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("whoami.exe", "net.exe", "net1.exe", "systeminfo.exe")
| summarize DistinctTools = dcount(FileName), Tools = make_set(FileName),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, InitiatingProcessId
| where DistinctTools >= 2 and LastSeen - FirstSeen <= 10m
```

**Expected result:** rows keyed by device and initiating-process ID where two or more distinct discovery tools ran inside a 10-minute span. **Interpretation:** the same orientation behavior the Sigma rule flags, surfaced here as one aggregated row instead of several raw hits an analyst has to group by hand.

**[QUERY]** SPL — targets Splunk with the Windows TA's default 4688 field extraction or a forwarded Sysmon Event ID 1 sourcetype.

CONCEPTUAL SAMPLE — field names illustrative; verify against your own TA's extraction before use.

```spl
index=windows (EventCode=4688 OR (sourcetype=XmlWinEventLog:Sysmon EventCode=1))
    (Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\systeminfo.exe")
| stats dc(Image) as distinct_tools, values(Image) as tools,
    earliest(_time) as first_seen, latest(_time) as last_seen by ComputerName, ParentProcessGuid
| eval window_seconds = last_seen - first_seen
| where distinct_tools >= 2 AND window_seconds <= 600
```

**Expected result:** one row per host/parent-lineage pair with a `distinct_tools` count and the raw tool list. **Interpretation:** consistent with a foothold's first orientation pass; a value of 1 with a long `window_seconds` is more likely routine scripted use.

**[QUERY]** AQL (QRadar) — this is AQL, not standard SQL. AQL natively supports a post-aggregation `HAVING` clause, filtered on the aggregate's alias rather than the raw aggregate expression (IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5: https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html), so the distinct-tool threshold below is filtered inline with `HAVING distinct_tools >= 2` rather than read from unfiltered output. IBM's one documented `HAVING` gap — unsupported in a saved search feeding a scheduled report or time-series graph — doesn't apply to this ad hoc investigative form; a standing detection would still promote the pattern into QRadar's own "at least N events... in Y minutes" Rule Test (DEH Part 27 §4) rather than rely on a saved `HAVING` search.

CONCEPTUAL SAMPLE — custom property names illustrative; verify against your own DSM's field list before use.

```sql
SELECT "Computer Name" AS host, "Parent Process GUID" AS parent_lineage,
       UNIQUECOUNT("Process Name") AS distinct_tools, COUNT(*) AS occurrences
FROM events
WHERE "Process Name" IN ('whoami.exe','net.exe','net1.exe','systeminfo.exe')
GROUP BY host, parent_lineage
HAVING distinct_tools >= 2
LAST 10 MINUTES
```

**Expected result:** one row per host/lineage pair that clears the `distinct_tools >= 2` floor. **Interpretation:** same as above — this search validates the pattern exists before it's worth building the standing Rule.

**[QUERY]** YARA-L (Google SecOps) — targets UDM `PROCESS_LAUNCH` events, matched on host and parent-process path over a short window.

CONCEPTUAL SAMPLE — illustrative YARA-L syntax, not validated against a live tenant; field paths illustrative.

```yaral
rule qc_15_01_discovery_binary_burst {
  meta:
    author = "soc-query-cookbook"
    description = "Two or more built-in discovery binaries launched from one lineage in a short window"
    mitre_technique_id = "T1087.001"
    severity = "LOW"

  events:
    $launch.metadata.event_type = "PROCESS_LAUNCH"
    $launch.target.process.file.full_path = /\\(whoami|net|net1|systeminfo)\.exe$/ nocase
    $launch.principal.process.file.full_path = $parent_path
    $launch.principal.hostname = $hostname

  match:
    $hostname, $parent_path over 10m

  condition:
    #launch >= 2

  outcome:
    $risk_score = 25
    $distinct_tools = count_distinct($launch.target.process.file.full_path)
}
```

**Expected result:** a detection instance once two qualifying launches share a host and parent path inside the window, with `outcome.distinct_tools` reporting how many different binaries fired. **Interpretation:** same as the KQL/SPL forms above, expressed as a standing multi-event rule rather than an ad hoc search.

**[QUERY]** Elastic (ES\|QL) — targets an ECS-normalized endpoint index (Elastic Defend or the Winlogbeat Sysmon module); ES\|QL fits this pattern's distinct-count-over-a-window shape better than a strict EQL `sequence`, which would need the tool order fixed rather than merely co-occurring.

CONCEPTUAL SAMPLE — illustrative ES\|QL, not validated against a live cluster.

```esql
FROM logs-endpoint.events.process-*
| WHERE process.name IN ("whoami.exe", "net.exe", "net1.exe", "systeminfo.exe")
| STATS distinct_tools = count_distinct(process.name), first_seen = min(@timestamp), last_seen = max(@timestamp)
    BY host.name, process.parent.entity_id
| WHERE distinct_tools >= 2 AND DATE_DIFF("minutes", first_seen, last_seen) <= 10
```

**Expected result:** rows keyed by host and parent-process entity ID with a `distinct_tools` count of 2 or more inside a 10-minute span. **Interpretation:** same as the KQL form — this is the aggregation-shaped Elastic surface, not the single-event or sequence one.

**[FALSE POSITIVE]** Helpdesk scripts, RMM tools, and imaging/onboarding automation call `whoami` and `systeminfo` routinely as part of asset inventory and remote-support sessions, and any estate running SCCM, an RMM agent, or a login script shows a baseline rate of these binaries firing from one lineage all day. Scope the exclusion to the specific RMM/SCCM service binary's path (as the Sigma filter block above does) rather than lowering the distinct-tool threshold — a threshold low enough to catch a careful attacker also catches nearly every scripted admin session.

**[PIVOT]** Pull the full command-line history for the flagged parent lineage across the surrounding 30 minutes. A hit that's part of a broader chain — a spawned PowerShell process, a subsequent `nltest` or LDAP query (`QC-15-02`/`QC-15-03`), or a lateral-movement attempt (Part 16) — reads very differently from an isolated pair of commands with nothing else around it.

**[SOC MANAGEMENT]** This pattern is cheap to run as a standing low-severity detection once the RMM/helpdesk exclusion list is maintained, because the underlying commands rarely change and the false-positive driver is narrow and identity-based rather than behavioral — a reasonable first candidate in this part to graduate from an ad hoc hunt into a tuned, always-on rule rather than a recurring manual query.

---

### QC-15-02 — Domain trust and controller topology enumeration via nltest/net

| Field | Value |
|---|---|
| **Pattern ID** | `QC-15-02` |
| **MITRE** | T1482 (Domain Trust Discovery) |
| **Behavior** | `nltest /domain_trusts`, `nltest /dclist:<domain>`, or `net group "domain admins" /domain` run from a host with no administrative role in domain management. |
| **DEH cross-ref** | DEH Part 13 §7 (LDAP enumeration and directory reconnaissance) — its own MITRE line names T1482 for the same domain-topology reconnaissance goal this non-LDAP command-line pattern serves; DEH Part 11 §2 for the underlying process-lineage detection model. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) — all six covered. |

**[HUNTER]** An attacker who has landed inside a domain-joined estate needs to know which domains trust this one and where the domain controllers are before planning any cross-domain or cross-forest move, and `nltest` answers both in one built-in call with no privilege beyond an authenticated domain session. Running this hunt immediately against a specific suspected-compromised host is worth doing before any volume-based rule would consider the activity worth an alert, because `nltest` from a workstation with no domain-management function is rare enough that even one hit deserves a human look.

**[QUERY]** Sigma — targets Sysmon Event ID 1 (Process Create) or Event ID 4688 with command-line auditing enabled.

CONCEPTUAL SAMPLE — argument list illustrative; extend it against your own environment's `nltest`/`net` usage before trusting it as exhaustive.

```yaml
title: Domain trust or controller topology enumeration via nltest or net
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\nltest.exe'
      - '\net.exe'
      - '\net1.exe'
  selection_cli:
    CommandLine|contains:
      - '/domain_trusts'
      - '/dclist'
      - '/domain_admins'
  selection_group:
    CommandLine|re: 'group\s+.*\s*/domain'
  condition: selection_img and (selection_cli or selection_group)
```

**Expected result:** matches on the specific trust/topology-enumeration argument, not on `net.exe`/`nltest.exe` alone. **Interpretation:** a hit from a workstation with no domain-management role is consistent with an attacker mapping the domain before a cross-domain move; the same command from a documented IT-admin host during a scheduled audit is expected.

**[QUERY]** KQL (Sentinel/Defender) — targets `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — regex and argument list illustrative.

```kql
DeviceProcessEvents
| where FileName in~ ("nltest.exe", "net.exe", "net1.exe")
| where ProcessCommandLine has_any ("/domain_trusts", "/dclist", "/domain_admins")
     or ProcessCommandLine matches regex @"(?i)group\s+.*\s*/domain"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

**Expected result:** individual rows, one per qualifying command, with the requesting account and device. **Interpretation:** same as the Sigma form above.

**[QUERY]** SPL — targets Splunk with the Windows TA's default 4688 field extraction or a forwarded Sysmon sourcetype.

CONCEPTUAL SAMPLE — field names illustrative.

```spl
index=windows (EventCode=4688 OR (sourcetype=XmlWinEventLog:Sysmon EventCode=1))
    (Image="*\\nltest.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe")
    (CommandLine="*\/domain_trusts*" OR CommandLine="*\/dclist*" OR CommandLine="*\/domain_admins*"
     OR CommandLine="*group*\/domain*")
| table _time ComputerName user Image CommandLine ParentImage
```

**Expected result:** a table of raw hits, one row per invocation. **Interpretation:** same as above.

**[QUERY]** AQL (QRadar) — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — custom property names illustrative; verify against your own DSM's field list.

```sql
SELECT starttime, "Computer Name" AS host, username, "Process Name" AS tool, "Command Line" AS commandline
FROM events
WHERE "Process Name" IN ('nltest.exe','net.exe','net1.exe')
  AND ("Command Line" ILIKE '%domain_trusts%' OR "Command Line" ILIKE '%dclist%'
       OR "Command Line" ILIKE '%domain_admins%' OR "Command Line" ILIKE '%group%/domain%')
LAST 24 HOURS
```

**Expected result:** a row per matching invocation across the last day. **Interpretation:** same as above.

**[QUERY]** YARA-L (Google SecOps) — targets UDM `PROCESS_LAUNCH` events.

CONCEPTUAL SAMPLE — illustrative YARA-L syntax, not validated against a live tenant.

```yaral
rule qc_15_02_domain_trust_enumeration {
  meta:
    author = "soc-query-cookbook"
    description = "nltest or net used to enumerate domain trusts or controller topology"
    mitre_technique_id = "T1482"
    severity = "MEDIUM"

  events:
    $launch.metadata.event_type = "PROCESS_LAUNCH"
    $launch.target.process.file.full_path = /\\(nltest|net|net1)\.exe$/ nocase
    $launch.target.process.command_line = /(\/domain_trusts|\/dclist|\/domain_admins|group\s+.*\/domain)/ nocase

  condition:
    $launch

  outcome:
    $risk_score = 40
}
```

**Expected result:** a detection instance per qualifying launch. **Interpretation:** same as above.

**[QUERY]** Elastic KQL — a single-event boolean match is the cheapest correct surface here; nothing about this pattern needs EQL's sequencing or ES\|QL's aggregation. Not Sentinel/Defender KQL — this is the Elastic search-bar/detection-rule dialect.

CONCEPTUAL SAMPLE — illustrative Elastic KQL, not validated against a live cluster.

```kql
process.name: ("nltest.exe" or "net.exe" or "net1.exe") and
  process.command_line: (*domain_trusts* or *dclist* or *domain_admins* or *group*domain*)
```

**Expected result:** matching documents in Discover/a custom-query detection rule. **Interpretation:** same as above.

**[FALSE POSITIVE]** Domain-health monitoring tools, backup/replication software validating a trust path, and IT admins troubleshooting a trust relationship or a DC outage all run these exact commands legitimately. Unlike `QC-15-01`'s helpdesk-driven noise, this activity is genuinely rare on most estates, so the fix is a short allowlist of specific admin accounts and jump-host names — anyone outside that list running this command is the anomaly this pattern exists to surface, not a candidate for a broader process exclusion.

**[PIVOT]** Check the same host and account for a subsequent authentication attempt against a different domain or forest named in the trust list `nltest` just returned. A successful cross-domain logon shortly after the enumeration is a materially stronger signal than the enumeration alone, and it hands directly to Part 16's lateral-movement patterns if it fires.

> **Engineering Reality**
> `nltest`/`net` command-line arguments only appear in Event ID 4688 if "Include command line in process creation events" is enabled via Group Policy — off by default on most builds — while Sysmon Event ID 1 captures the command line unconditionally once Sysmon itself is installed. An estate relying on native 4688 alone with that GPO unset gets an empty `CommandLine` field on every hit, indistinguishable from the tool never having run at all.

---

### QC-15-03 — BloodHound/SharpHound-shaped LDAP enumeration volume

| Field | Value |
|---|---|
| **Pattern ID** | `QC-15-03` |
| **MITRE** | T1087.002 (Account Discovery: Domain Account) — overlaps T1069.002 (Permission Groups Discovery: Domain Groups) and T1482 (Domain Trust Discovery), since a single SharpHound collection run gathers all three object categories in one pass, mirroring DEH Part 13 §7's own combined MITRE line for this reconnaissance goal. |
| **Behavior** | A single security principal issuing an abnormally large number of LDAP search requests against a domain controller in a short window, consistent with SharpHound/BloodHound-style attack-path collection. |
| **DEH cross-ref** | DEH Part 13 §7 (LDAP enumeration and directory reconnaissance), including its own Blind Spot on native-API-based reconnaissance producing no command-line signature at all. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, Elastic (ES\|QL) — AQL and YARA-L: `N/A`, see below. |

**[CONCEPT]** BloodHound's model is genuinely different in kind from a single targeted directory question. SharpHound doesn't ask "does this one user have this one attribute" — it walks the entire domain, every user, group, computer, session, and ACL, and hands the result to BloodHound's graph engine so an attacker can compute the shortest path to Domain Admin offline. That volume signature is what this pattern targets; the individual-query shape of a single reconnaissance-flavored cmdlet call is `QC-15-04`'s territory instead.

**[HUNTER]** SharpHound's default collection methods generate LDAP search-request volume an order of magnitude above a single legitimate admin query in the same span, and that volume signature survives even when the collector binary itself is renamed, run in memory, or replaced by a newer tool built on the same LDAP-walk primitive — none of which a process-name-based hunt like `QC-15-01`'s shape ever sees. The cost of hunting the volume directly instead is telemetry most estates have not turned on by default; per DEH Part 13 §7, standard Windows Security auditing does not log ordinary LDAP search-request content, so this pattern depends on a directory-aware sensor (most commonly Microsoft Defender for Identity) rather than native auditing alone.

**[QUERY]** Sigma — no standard Sigma `logsource` category exists for raw LDAP search volume as of this writing (the same telemetry gap DEH Part 13 §7 names generically), so this rule targets Microsoft Defender for Identity's reconnaissance-shaped output via a product-specific pipeline instead of a generic process/network category. It's written as a base rule plus a correlation rule, the same two-part shape DEH Part 24 §4.1 uses for its own SSH burst analytic, because the signal here is a *count* of matches per principal, not any single match.

CONCEPTUAL SAMPLE — `ActionType` value and threshold illustrative; both depend entirely on the specific identity-telemetry pipeline feeding this rule and must be verified against real output before use.

```yaml
title: LDAP directory search event
id: 4d9a7e21-6b3c-4a1e-8f2d-1a9c6e4b7d33
status: experimental
logsource:
  category: application
  product: m365_defender
  definition: 'Targets Microsoft Defender for Identity reconnaissance telemetry; no standard Sigma logsource category exists for raw LDAP search volume.'
detection:
  selection:
    ActionType: 'LDAP search'
  condition: selection
```

CONCEPTUAL SAMPLE — correlation threshold (200 events / 15 minutes) illustrative; tune against your own tenant's baseline before use.

```yaml
title: High-volume LDAP search activity from one security principal
id: 8e2c5f13-9a4d-4b7e-9c1f-3d6a8e2b5c44
status: experimental
description: >
  Correlates the LDAP-search base rule (id 4d9a7e21-...) into a volume
  pattern: 200 or more LDAP search events from the same principal within
  15 minutes, consistent with a SharpHound/BloodHound-style collection run.
correlation:
  type: event_count
  rules:
    - 4d9a7e21-6b3c-4a1e-8f2d-1a9c6e4b7d33
  group-by:
    - AccountUpn
  timespan: 15m
  condition:
    gte: 200
level: medium
```

**Expected result:** a correlation match naming the principal and the 15-minute window once its LDAP-search count crosses the threshold. **Interpretation:** consistent with an automated directory-walk collection run; the same principal's routine daily activity should sit far below this threshold in an environment where the threshold was tuned against real baseline volume, which this book has not measured.

**[QUERY]** KQL (Sentinel/Defender) — targets Microsoft Sentinel's `IdentityDirectoryEvents` table, populated by Microsoft Defender for Identity sensors on domain controllers.

CONCEPTUAL SAMPLE — `ActionType` strings and threshold illustrative; verify both against your own tenant's actual `IdentityDirectoryEvents` output before reuse.

```kql
IdentityDirectoryEvents
| where Timestamp > ago(1h)
| where ActionType in ("LDAP search", "SAM name reconnaissance")
| summarize SearchCount = count(), DistinctTargets = dcount(TargetAccountUpn)
    by AccountUpn, bin(Timestamp, 15m)
| where SearchCount >= 200
```

**Expected result:** rows naming a principal and a 15-minute bucket where LDAP search volume crossed 200 events, alongside how many distinct target accounts those searches touched. **Interpretation:** a high `DistinctTargets` value alongside a high `SearchCount` is more consistent with a broad directory walk than with a narrow, repeated query against one object.

**[QUERY]** SPL — targets Splunk ingesting Microsoft Defender for Identity data via its own add-on, or an equivalent LDAP-proxy/audit log source mapped to comparable fields.

CONCEPTUAL SAMPLE — sourcetype and field names illustrative; this book has not validated them against a live Defender for Identity Splunk add-on.

```spl
index=identity sourcetype=MicrosoftDefenderIdentity ActionType="LDAP search"
| bin _time span=15m
| stats count as search_count, dc(TargetAccountUpn) as distinct_targets by AccountUpn, _time
| where search_count >= 200
```

**Expected result:** rows naming a principal, a 15-minute bucket, and a search count. **Interpretation:** same as the KQL form above.

AQL and YARA-L are both `N/A` for this pattern — **missing schema field**. Neither platform has a confirmed default field surfacing per-principal LDAP-search volume the way Sentinel's `IdentityDirectoryEvents` table does natively: QRadar has no out-of-box DSM mapping for Defender-for-Identity-style reconnaissance counts absent a custom extension, and Google SecOps's UDM has no confirmed event type or field for raw LDAP search-request volume as of this writing (the same category of gap DEH Part 28 §1.1 names for YARA-L's unconfirmed `GrantedAccess` equivalent). A QRadar or Google SecOps deployment that already forwards Defender-for-Identity-equivalent telemetry through a custom parser could adapt the KQL query's logic once that field is confirmed present — this omission is about telemetry availability, not about either language's structural capability.

**[QUERY]** Elastic (ES\|QL) — targets a hypothetical identity-telemetry index fed by a Defender for Identity or equivalent connector; ES\|QL is the natural fit for this pattern's threshold/wide-lookback shape.

CONCEPTUAL SAMPLE — index pattern and field names illustrative; no ECS standard guarantees an equivalent field on every platform, the same caveat DEH Part 29 §5 names for its own honeypot-credential field.

```esql
FROM logs-identity.directory-*
| WHERE event.action == "ldap-search"
| STATS search_count = count(), distinct_targets = count_distinct(target.user.name)
    BY source.user.name, BUCKET(@timestamp, 15 minutes)
| WHERE search_count >= 200
```

**Expected result:** rows naming a principal and a 15-minute bucket where search volume crossed the threshold. **Interpretation:** same as the KQL/SPL forms above.

**[FALSE POSITIVE]** Identity-governance/access-review tools, a scheduled Entra Connect/Azure AD Connect directory sync, and vulnerability scanners with an AD module all generate high LDAP query volume from one service account on a predictable schedule. Allowlist the specific known service account and its documented sync window rather than raising the count threshold — a higher threshold just gives a real SharpHound run more room to finish before it's caught.

**[PIVOT]** Check whether the flagged principal's account subsequently authenticates to any of the computers, groups, or service accounts a directory walk of this shape would have surfaced. A real attack-path traversal following a BloodHound-shaped enumeration run is the corroborating signal that turns this from "someone ran a heavy query" into "someone is executing the plan the query built" — hand off to Part 16 if a follow-on lateral move appears.

> **Blind Spot**
> SharpHound's own stealth collection options (limiting `--CollectionMethod` to a narrow set, or substituting SAMR-based session enumeration for some LDAP-heavy collection methods) can bring a collection run's LDAP volume down closer to a legitimate admin's baseline, and an attacker querying a read-only domain controller or a global-catalog replica the sensor doesn't cover produces no volume signal on the monitored DC at all. This pattern catches the default, loud collection behavior; it does not catch an operator who has already read the same public tooling documentation and tuned around it.

---

### QC-15-04 — AD reconnaissance via PowerShell/.NET directory-services cmdlets

| Field | Value |
|---|---|
| **Pattern ID** | `QC-15-04` |
| **MITRE** | T1069.002 (Permission Groups Discovery: Domain Groups) — overlaps T1087.002 (Account Discovery: Domain Account), the same pairing DEH Part 13 §7 uses for `Get-ADUser`/`Get-ADGroup` reconnaissance-shaped filter arguments. |
| **Behavior** | `Get-ADUser`/`Get-ADGroup`/`Get-ADComputer`, or a raw `[adsisearcher]`/`New-Object DirectoryServices.DirectorySearcher` call, run with a reconnaissance-shaped filter (`-Filter *`, `-Properties *`, or a nested group-membership walk) from a host with no administrative reason to query the directory broadly. |
| **DEH cross-ref** | DEH Part 13 §7, which names exactly this cmdlet-and-filter combination as the process-based detection path for LDAP reconnaissance and cross-references DEH Part 11 for the command-line telemetry it depends on; DEH Part 11 §2 directly. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) — all six covered. |

**[HUNTER]** `Get-ADUser -Filter * -Properties *` and a raw `DirectorySearcher` call against the same directory both answer the same question BloodHound's graph answers at scale, just one object at a time and without needing SharpHound present on disk — including as a manually typed command in an interactive session with no script file to find afterward. Hunting the cmdlet-and-filter combination directly, rather than waiting for a named collector binary, catches an operator working entirely from memorized built-in tooling, which is common enough in real intrusions that this pattern is worth running on its own, separately from `QC-15-03`'s volume-based signal.

**[QUERY]** Sigma — targets Sysmon Event ID 1 (Process Create) or Event ID 4688 for the command line, and Event ID 4104 (Creating Scriptblock text) as a complementary source when the command line itself is truncated or the call is wrapped in a script block.

CONCEPTUAL SAMPLE — cmdlet and filter-argument lists illustrative; extend against your own environment's legitimate AD-tooling usage before trusting this as tuned.

```yaml
title: PowerShell or .NET directory-services reconnaissance
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_cmdlet:
    CommandLine|contains:
      - 'Get-ADUser'
      - 'Get-ADGroup'
      - 'Get-ADComputer'
      - 'adsisearcher'
      - 'DirectorySearcher'
  selection_broad:
    CommandLine|contains:
      - '-Filter *'
      - '-Filter {*}'
      - '-Properties *'
  condition: selection_cmdlet and selection_broad
```

**Expected result:** a match on a command line combining a directory cmdlet or raw .NET searcher with a wildcard filter or full-property pull. **Interpretation:** consistent with an attacker or a red-team operator walking the directory broadly rather than looking up one known object.

**[QUERY]** KQL (Sentinel/Defender) — targets `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — string-match list illustrative.

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("Get-ADUser", "Get-ADGroup", "Get-ADComputer", "adsisearcher", "DirectorySearcher")
| where ProcessCommandLine has_any ("-Filter *", "-Properties *", "-Filter {*}")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

**Expected result:** individual rows, one per qualifying invocation. **Interpretation:** same as the Sigma form above.

**[QUERY]** SPL — targets Splunk with the Windows TA's 4688 extraction, a forwarded Sysmon sourcetype, or PowerShell Operational log Event ID 4104.

CONCEPTUAL SAMPLE — field names illustrative across the three possible sourcetypes.

```spl
index=windows (EventCode=4688 OR (sourcetype=XmlWinEventLog:Sysmon EventCode=1)
    OR (sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104))
    (CommandLine="*Get-ADUser*" OR CommandLine="*Get-ADGroup*" OR CommandLine="*Get-ADComputer*"
     OR CommandLine="*adsisearcher*" OR CommandLine="*DirectorySearcher*"
     OR ScriptBlockText="*Get-AD*" OR ScriptBlockText="*DirectorySearcher*")
    (CommandLine="*-Filter *" OR CommandLine="*-Properties *"
     OR ScriptBlockText="*-Filter *" OR ScriptBlockText="*-Properties *")
| table _time ComputerName user CommandLine ScriptBlockText
```

**Expected result:** a table combining command-line and script-block hits. **Interpretation:** same as above; a hit sourced only from `ScriptBlockText` with an empty `CommandLine` is consistent with an obfuscated or dot-sourced invocation the raw command line didn't capture.

**[QUERY]** AQL (QRadar) — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — custom property names illustrative.

```sql
SELECT starttime, "Computer Name" AS host, username, "Command Line" AS commandline
FROM events
WHERE ("Command Line" ILIKE '%Get-ADUser%' OR "Command Line" ILIKE '%Get-ADGroup%'
       OR "Command Line" ILIKE '%Get-ADComputer%' OR "Command Line" ILIKE '%adsisearcher%'
       OR "Command Line" ILIKE '%DirectorySearcher%')
  AND ("Command Line" ILIKE '%-Filter *%' OR "Command Line" ILIKE '%-Properties *%')
LAST 24 HOURS
```

**Expected result:** a row per matching invocation across the last day. **Interpretation:** same as above.

**[QUERY]** YARA-L (Google SecOps) — targets UDM `PROCESS_LAUNCH` events.

CONCEPTUAL SAMPLE — illustrative YARA-L syntax, not validated against a live tenant.

```yaral
rule qc_15_04_ad_recon_cmdlets {
  meta:
    author = "soc-query-cookbook"
    description = "Directory-services cmdlet or raw .NET searcher run with a wildcard filter or full-property pull"
    mitre_technique_id = "T1069.002"
    severity = "MEDIUM"

  events:
    $launch.metadata.event_type = "PROCESS_LAUNCH"
    $launch.target.process.command_line = /(Get-AD(User|Group|Computer)|adsisearcher|DirectorySearcher)/ nocase
    $launch.target.process.command_line = /(-Filter\s+\*|-Filter\s+\{\*\}|-Properties\s+\*)/ nocase

  condition:
    $launch

  outcome:
    $risk_score = 45
}
```

**Expected result:** a detection instance per qualifying launch. **Interpretation:** same as above.

**[QUERY]** Elastic KQL — a single-event boolean match, the cheapest correct surface for this pattern's shape. Not Sentinel/Defender KQL — this is the Elastic search-bar/detection-rule dialect.

CONCEPTUAL SAMPLE — illustrative Elastic KQL, not validated against a live cluster.

```kql
process.command_line: (*Get-ADUser* or *Get-ADGroup* or *Get-ADComputer* or *adsisearcher* or *DirectorySearcher*) and
  process.command_line: (*-Filter\ \** or *-Properties\ \**)
```

**Expected result:** matching documents in Discover or a custom-query detection rule. **Interpretation:** same as above.

**[FALSE POSITIVE]** IT-automation and identity-governance scripts genuinely need a wide `Get-ADUser -Filter *` pull for a weekly access review or an HR-sync job, and any AD-integrated ITSM/IGA product's service account triggers this daily. Scope the exclusion to that specific service account and its documented scheduled runtime window, not to the cmdlet-and-filter pattern itself — the pattern is exactly what a real attacker's PowerShell-based reconnaissance looks like too, and loosening it to dodge one service account's noise loosens it for everyone else as well.

**[PIVOT]** Check the same session for a subsequent Kerberoasting-shaped SPN request (Part 7) or a DCSync-adjacent replication request against one of the objects this query just enumerated. A broad directory pull followed by a targeted follow-up against a specific result is the two-step shape a real attack-path walk actually takes, distinct from a one-off lookup that never gets a follow-up at all.

> **What Would Change My Mind**
> This pattern treats the wildcard-filter/full-property signature as the load-bearing part of the match, on the assumption that a targeted, well-known query for one object (`Get-ADUser -Identity jsmith`) is common enough on its own to be poor signal. If real telemetry showed attackers routinely scoping their PowerShell-based reconnaissance to narrow, per-object filters specifically to dodge a wildcard-based rule like this one, that would argue for shifting this pattern's signal toward call volume and session breadth — closer to `QC-15-03`'s shape — instead of the filter syntax itself.

---

### QC-15-05 — Linux/Unix host and identity discovery command sequence

| Field | Value |
|---|---|
| **Pattern ID** | `QC-15-05` |
| **MITRE** | T1087.001 (Account Discovery: Local Account) — overlaps T1082 (System Information Discovery) for `uname`, and T1016 (System Network Configuration Discovery) for `ip a`/`ifconfig`; tag an individual hit against its own closest technique and treat this header's mapping as the sequence-level umbrella, the same convention `QC-15-01` uses for its Windows counterpart. |
| **Behavior** | `id`, `whoami`, `groups`, `cat /etc/passwd`, `sudo -l`, `uname -a`, and `ip a`/`ifconfig` run in close succession from one shell session shortly after a new SSH logon or web-shell foothold. |
| **DEH cross-ref** | DEH Part 11 §2 (Process trees and lineage classification), stated there as explicitly cross-OS. DEH Part 13 has no Linux-specific equivalent to its own §7 LDAP framing, since that part's directory-reconnaissance treatment concentrates on Windows AD — consistent with this part's own scope note above. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (EQL) — all six covered. |

**[HUNTER]** A shell landed on a Linux host, whether via a stolen SSH key or a web-shell dropped through an application exploit, runs through the same orientation checklist a Windows attacker runs on landing — who am I, what can I do, what is this box, what network am I on — using a small, predictable set of built-in commands that need no special tooling at all. Hunting this directly rather than waiting on a threshold rule pays off the same way `QC-15-01` does: an analyst investigating one specific suspected foothold can treat two or three of these commands appearing together, close together, right after a new session starts, as worth a look immediately.

**[QUERY]** Sigma — targets an auditd-backed process-creation telemetry pipeline (`execve` logging) mapped through whatever pySigma pipeline your Linux collection uses.

CONCEPTUAL SAMPLE — command and argument lists illustrative.

```yaml
title: Linux host and identity discovery command sequence
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - '/id'
      - '/whoami'
      - '/groups'
      - '/uname'
      - '/ip'
      - '/ifconfig'
  selection_files:
    CommandLine|contains:
      - 'passwd'
      - 'sudo -l'
      - 'sudoers'
  condition: selection or selection_files
fields:
  - ParentProcessGuid
  - User
```

**Expected result:** individual rows for each qualifying command, grouped afterward by session/parent lineage to see three or more distinct commands within a short span. **Interpretation:** consistent with a landed foothold's orientation pass; a single hit alone, from a known automation lineage, is far weaker signal.

**[QUERY]** KQL (Sentinel/Defender) — targets `DeviceProcessEvents` populated by Microsoft Defender for Endpoint on Linux.

CONCEPTUAL SAMPLE — field names illustrative; verify `DeviceOs` filtering against your own MDE-for-Linux deployment.

```kql
DeviceProcessEvents
| where DeviceOs == "Linux"
| where FileName in~ ("id", "whoami", "groups", "uname", "ip", "ifconfig")
    or ProcessCommandLine has_any ("/etc/passwd", "sudo -l", "/etc/sudoers")
| summarize DistinctCommands = dcount(FileName), Commands = make_set(FileName),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, InitiatingProcessId
| where DistinctCommands >= 3 and LastSeen - FirstSeen <= 5m
```

**Expected result:** rows keyed by device and initiating-process ID where three or more distinct discovery commands ran inside a 5-minute span. **Interpretation:** same as the Sigma form above.

**[QUERY]** SPL — targets Splunk ingesting Linux auditd `EXECVE` records.

CONCEPTUAL SAMPLE — field names illustrative; verify against your own auditd-to-Splunk pipeline's extraction.

```spl
index=linux sourcetype=linux_audit type=EXECVE
    (comm="id" OR comm="whoami" OR comm="groups" OR comm="uname" OR comm="ip" OR comm="ifconfig"
     OR (a0="cat" a1="/etc/passwd") OR (a0="sudo" a1="-l"))
| stats dc(comm) as distinct_commands, values(comm) as commands,
    earliest(_time) as first_seen, latest(_time) as last_seen by host, ses
| eval window_seconds = last_seen - first_seen
| where distinct_commands >= 3 AND window_seconds <= 300
```

**Expected result:** one row per host/session pair with a `distinct_commands` count. **Interpretation:** same as above.

**[QUERY]** AQL (QRadar) — this is AQL, not standard SQL. As in `QC-15-01`, AQL natively supports a post-aggregation `HAVING` clause filtered on the aggregate's alias (IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5: https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html), so the threshold below is filtered inline with `HAVING distinct_commands >= 3` rather than read from unfiltered output.

CONCEPTUAL SAMPLE — custom property names illustrative.

```sql
SELECT "Host Name" AS host, "Session ID" AS session, UNIQUECOUNT("Process Name") AS distinct_commands
FROM events
WHERE "Process Name" IN ('id','whoami','groups','uname','ip','ifconfig')
   OR "Command Line" ILIKE '%passwd%' OR "Command Line" ILIKE '%sudo -l%'
GROUP BY host, session
HAVING distinct_commands >= 3
LAST 5 MINUTES
```

**Expected result:** a row per host/session pair that clears the `distinct_commands >= 3` floor. **Interpretation:** same as above.

**[QUERY]** YARA-L (Google SecOps) — targets UDM `PROCESS_LAUNCH` events, matched on host over a short window.

CONCEPTUAL SAMPLE — illustrative YARA-L syntax, not validated against a live tenant.

```yaral
rule qc_15_05_linux_discovery_sequence {
  meta:
    author = "soc-query-cookbook"
    description = "Three or more Linux host/identity discovery commands run from one session in a short window"
    mitre_technique_id = "T1087.001"
    severity = "LOW"

  events:
    $exec.metadata.event_type = "PROCESS_LAUNCH"
    $exec.target.process.file.full_path = /\/(id|whoami|groups|uname|ip|ifconfig)$/ nocase
    $exec.principal.hostname = $hostname

  match:
    $hostname over 5m

  condition:
    #exec >= 3

  outcome:
    $risk_score = 25
    $distinct_commands = count_distinct($exec.target.process.file.full_path)
}
```

**Expected result:** a detection instance once three qualifying launches share a host inside the 5-minute window. **Interpretation:** same as above.

**[QUERY]** Elastic (EQL) — an ordered, entity-joined sequence is the right surface here: an identity check followed by a system/network-recon command, joined on the same host and parent lineage within a bounded span.

CONCEPTUAL SAMPLE — illustrative EQL, not validated against a live Elastic Security tenant.

```eql
sequence by host.name, process.parent.entity_id with maxspan=2m
  [process where event.action == "exec" and process.name in ("id", "whoami", "groups")]
  [process where event.action == "exec" and (process.name in ("uname", "ip", "ifconfig") or
      (process.name == "cat" and process.args : "/etc/passwd"))]
```

**Expected result:** a two-stage match where an identity-check command is followed, within two minutes and the same parent lineage, by a system/network-recon command. **Interpretation:** consistent with the same orientation checklist the other five language forms flag; the ordering requirement here trades some recall (a reversed order won't match) for a cleaner false-positive profile than an unordered co-occurrence count.

**[FALSE POSITIVE]** Every interactive shell login on a well-run Linux fleet routinely runs `whoami` or `id` as part of a MOTD script, a shell-prompt customization, or a monitoring agent's health check, and `uname`/`ip a` show up constantly in cloud-init, container-entrypoint, and configuration-management runs. Exclude the specific parent processes those automation paths use (`cloud-init`, a documented CI/CD runner's session, a named monitoring agent) rather than dropping any individual command from the match set, since the individual commands are exactly what a real attacker also runs.

**[PIVOT]** Check the same session for a subsequent outbound connection or a `curl`/`wget` invocation immediately after the discovery burst. An attacker who has just confirmed their privilege level and the host's network configuration typically moves straight to downloading a second-stage tool or connecting outward, and that follow-on activity is far more diagnostic than the discovery commands alone.

> **Detection Test**
> **Setup:** Linux test host with auditd configured to log `execve` syscalls (`-a always,exit -F arch=b64 -S execve`), test account with ordinary non-root shell access.
> **Action:** From a fresh SSH session, run `id; whoami; groups; uname -a; ip a` in quick succession.
> **Expected result:** Five auditd `EXECVE` records sharing the same session ID within a few seconds of each other; the SPL/KQL/YARA-L queries above return one row or detection for that session with a distinct-command count of at least 3. Re-run with only `whoami` run alone and confirm none of the multi-command patterns fire, to catch a rule accidentally built to match on any single command in the list rather than genuine co-occurrence.

---

## Cross-references

DEH Part 11 §2 (Process trees and lineage classification) and DEH Part 13 §7 (LDAP enumeration and directory reconnaissance) for the telemetry and detection-engineering reasoning this part's patterns build on; DEH Parts 23–29 for this book's six query-language surfaces' own syntax, backend translation loss, and fundamentals this part deliberately does not re-teach; DEH Parts 41–43 for the Detection Coverage/Quality/Debt methodology this book's Part 28 applies to these patterns rather than reinventing. Within this book: Part 3 (Scanning & Enumeration) for the network-level scanning and share/service enumeration this part explicitly excludes; Part 7 (Kerberos & Directory Credential Attacks) for the credential-theft events that often follow the directory reconnaissance `QC-15-03`/`QC-15-04` surface; Part 11 (Account Creation & Privilege Escalation) for what an attacker does with a discovered account rather than the discovery itself; Part 16 (Lateral Movement via Admin Tools & Remote Services) for the next hop after a `[PIVOT]` above confirms follow-on activity.
