---
title: "Account Creation & Privilege Escalation"
part: 11
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 11 — Account Creation & Privilege Escalation

## Why this part exists

**[CONCEPT]** Creating a new account and manipulating who belongs to a privileged group are two of the cheapest, most durable ways an attacker can turn a single foothold into standing access — cheaper than re-exploiting the same initial-access vector every time, and durable because a quiet account or an extra group membership survives a password rotation on the credential that got the attacker in originally. This part covers that behavior class end to end on the two operating systems most SOCs actually run: Windows local/domain account creation and group-membership manipulation, and the Linux account/`sudo` equivalents.

This part's scope stops at the OS boundary stated in the Part Table: new local or domain account creation, unexpected privileged-group membership changes, and token/privilege-assignment escalation on Windows, plus `useradd`/`sudoers` drift on Linux. It does not cover scheduled-task or service-based persistence (cookbook Part 12), host/directory discovery that precedes an escalation attempt (Part 15), the credential-theft techniques an attacker might use to get the access needed to create an account in the first place (Part 7), or cloud IAM role/permission escalation (Parts 25–26) — cloud identity has a materially different query shape (control-plane API logs, not Windows Security/auditd events) and its own three parts. Six patterns follow, at this part's budget ceiling: four Windows-native and two Linux-native.

## 1. Windows-native account and privilege patterns

### QC-11-01 — New account created by a non-provisioning identity

| Field | Value |
|---|---|
| **Pattern ID** | `QC-11-01` |
| **MITRE** | T1136.001 (Create Account: Local Account) / T1136.002 (Create Account: Domain Account) |
| **Behavior** | Account created by an actor outside the known provisioning identity set. |
| **DEH cross-ref** | DEH Part 8 §7 (4720 field reference); DEH Part 13 §1 (identity analytic-layer scope) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) |

**[HUNTER]** Most account creation on a mature domain flows through a handful of known identities — an HRIS-driven joiner workflow, an AD Connect sync account, a helpdesk provisioning tool. This hunt inverts that assumption: pull every Event ID 4720 (A user account was created) whose `SubjectUserName` isn't on that short allowlist and look at who is actually creating accounts by hand. It beats waiting on a standing detection because building the allowlist itself — walking the real creation history to find out who legitimately creates accounts — is most of the work, and a hunt is how that list gets built the first time.

**[QUERY]** Sigma, targeting any Windows Security-log ingestion pipeline.

```yaml
# CONCEPTUAL SAMPLE — allowlist values illustrative; replace with your own provisioning identities.
title: New account created by a non-provisioning identity
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  filter_known_provisioning:
    SubjectUserName:
      - 'svc_hris_sync'
      - 'svc_adconnect'
      - 'svc_helpdesk_provisioning'
  condition: selection and not filter_known_provisioning
```

Plausible expected result: on a mid-size domain, single-digit daily volume once the allowlist is populated — most creation genuinely is scripted, so a filtered hit is the exception, not the rule. Interpretation: a match is consistent with a human administrator or an unrecognized automation identity creating the account; it is not by itself evidence of compromise, since some organizations still provision certain account types by hand.

**[QUERY]** KQL, targeting Microsoft Sentinel / Log Analytics `SecurityEvent`.

```kql
// CONCEPTUAL SAMPLE — KnownProvisioningAccounts_CL is an invented watchlist name.
SecurityEvent
| where EventID == 4720
| where SubjectUserName !in (KnownProvisioningAccounts_CL)
| project TimeGenerated, SubjectUserName, TargetUserName, Computer
```

Plausible expected result: a short table of rows, each `SubjectUserName` a named IT staff account rather than a service principal. Interpretation: same as above — a starting point for triage, not a conclusion.

**[QUERY]** SPL, targeting Splunk with the Windows TA's default 4720 extraction.

```spl
// CONCEPTUAL SAMPLE — lookup filename and field names illustrative; validate against your own Windows TA field extraction and allowlist lookup.
index=wineventlog EventCode=4720
| lookup provisioning_allowlist.csv SubjectUserName OUTPUT is_known
| where isnull(is_known)
| table _time SubjectUserName TargetUserName ComputerName
```

Plausible expected result: identical shape to the KQL version — a handful of rows per day once the lookup is current. Interpretation: unchanged; the query only changes backend, not meaning.

**[QUERY]** AQL, disambiguated here as QRadar's query language, not standard SQL — targeting Windows Security events ingested via WinCollect.

```sql
-- CONCEPTUAL SAMPLE — WinCollect custom property name ("Target Username") illustrative; validate against your own DSM field mapping.
SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS "Event Time",
       username AS "Creator",
       "Target Username" AS "New Account",
       sourceip AS "Source IP"
FROM events
WHERE QIDNAME(qid)='A user account was created'
AND username NOT IN ('svc_hris_sync','svc_adconnect','svc_helpdesk_provisioning')
LAST 24 HOURS
```

Plausible expected result: same shape again, subject to whatever custom property WinCollect maps `TargetUserName` onto as `"Target Username"` in your own deployment. Interpretation: unchanged.

**[QUERY]** YARA-L, targeting Google SecOps UDM.

```yaral
// CONCEPTUAL SAMPLE — illustrative rule shape; validate userid field mapping against your own parser.
rule new_account_outside_provisioning {
  meta:
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "USER_CREATION"
    $e.principal.user.userid != "svc_hris_sync"
    $e.principal.user.userid != "svc_adconnect"
    $e.principal.user.userid != "svc_helpdesk_provisioning"
  condition:
    $e
}
```

Plausible expected result: one detection per qualifying creation event. Interpretation: unchanged from the Sigma/KQL versions above.

**[QUERY]** Elastic KQL — a single-event boolean match is the cheapest fit for this pattern's shape, per DEH Appendix A5 §8's decision table, so this pattern does not use EQL or ES\|QL.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own Winlogbeat/ECS field mapping before use.

```kql
event.code:"4720" and not winlog.event_data.SubjectUserName:("svc_hris_sync" or "svc_adconnect" or "svc_helpdesk_provisioning")
```

Plausible expected result: same shape as the other five. Interpretation: unchanged.

**[FALSE POSITIVE]** Helpdesk technicians manually creating contractor accounts during onboarding spikes — a seasonal intake, a large project ramp-up — and break-glass emergency-account procedures are the dominant legitimate drivers, and both can produce a real burst rather than a steady trickle. The fix is treating the allowlist as a living artifact tied to actual provisioning-tool identities rather than trying to guess intent from the event alone; a manual creation should require a change ticket, and the absence of one is the actual signal, not the creation event itself.

**[PIVOT]** Check whether the new account's name follows the org's naming convention — a name like `svc_backup2` or one character off from an existing account is a common attacker tell — and pull the creator's own recent Event ID 4624 (An account was successfully logged on) history to see whether they authenticated somewhere unusual immediately before creating the account.

### QC-11-02 — Account created and immediately added to a privileged group

| Field | Value |
|---|---|
| **Pattern ID** | `QC-11-02` |
| **MITRE** | T1136.002 (Create Account: Domain Account) chained with T1098 (Account Manipulation) |
| **Behavior** | New account created and added to a privileged group within minutes of its own creation. |
| **DEH cross-ref** | DEH Part 8 §7 (4720/4728/4732/4756 fields); DEH Part 13 §8, extends DET-13-05's change-window logic with an antecedent-creation join |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL (QRadar, investigative pull only — see below), YARA-L, Elastic (EQL) — Sigma: `N/A`, see below |

**[HUNTER]** A legitimate joiner account picks up its working-group memberships over days or weeks as access requests clear an approval queue. An attacker standing up a persistence account does both steps back to back, because they want usable privileged access fast, not because they're following a joiner-mover-leaver process. Hunting for "created, then privileged, within minutes" catches the attacker's own operational impatience rather than any single event.

Sigma: `N/A` — structurally poor fit. Expressing "event A followed by event B for the same identity within N minutes" needs Sigma's `temporal_ordered` correlation type, which has narrow backend support (§4.4's "structurally poor fit" reason category); publishing it here would force most Sigma consumers into a rule they can't actually run.

**[QUERY]** KQL, joining two `SecurityEvent` projections on the new account's name.

```kql
// CONCEPTUAL SAMPLE — 15-minute window illustrative; validate against your own baseline before trusting it as a cutoff.
SecurityEvent
| where EventID == 4720
| project CreateTime = TimeGenerated, NewAccount = TargetUserName, Creator = SubjectUserName
| join kind=inner (
    SecurityEvent
    | where EventID in (4728, 4732, 4756)
    | project AddTime = TimeGenerated, NewAccount = MemberName, Group = TargetUserName, Adder = SubjectUserName
  ) on NewAccount
| where AddTime - CreateTime between (0min .. 15min)
| project NewAccount, Creator, Adder, Group, CreateTime, AddTime
```

Plausible expected result: a small number of matched pairs, most commonly minutes apart rather than hours. Interpretation: consistent with an account provisioned and privileged in one operational motion — worth checking against a change ticket regardless of which actor performed it.

**[QUERY]** SPL, joining on the same key.

```spl
// CONCEPTUAL SAMPLE — 900-second (15-minute) window illustrative; validate against your own baseline before trusting it as a cutoff.
index=wineventlog EventCode=4720
| rename TargetUserName as NewAccount, SubjectUserName as Creator, _time as create_time
| join type=inner NewAccount [
    search index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
    | rename MemberName as NewAccount, TargetUserName as Group, SubjectUserName as Adder, _time as add_time
  ]
| eval gap_seconds = add_time - create_time
| where gap_seconds >= 0 AND gap_seconds <= 900
| table create_time NewAccount Creator Adder Group gap_seconds
```

Plausible expected result and interpretation: identical to the KQL version above.

**[QUERY]** AQL, disambiguated here as QRadar's query language, not standard SQL. QRadar cannot express this keyed, time-bounded two-event join as one statement — a standing correlation needs a Rule chaining a Building Block for 4720 with a Reference Set keyed on the new account name, populated by that Building Block and consumed by a second rule watching 4728/4732/4756 (QRadar's Building Block/Reference Set/Rule model, per DEH Part 27 §2–§3). Before building those three objects, this investigative pull shows whether the pattern exists at all:

```sql
-- CONCEPTUAL SAMPLE — investigative pull only, not a standing correlation; QID name list illustrative, validate against your own DSM mapping.
SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS "Event Time",
       QIDNAME(qid) AS "Event Name",
       username AS "Actor",
       "Target Username" AS "Account or Group"
FROM events
WHERE QIDNAME(qid) IN (
  'A user account was created',
  'A member was added to a security-enabled global group',
  'A member was added to a security-enabled local group',
  'A member was added to a security-enabled universal group'
)
LAST 24 HOURS
ORDER BY devicetime ASC
```

Plausible expected result: an ordered list an analyst scans by eye for a creation row followed within minutes by a group-add row naming the same account. Interpretation: this pull surfaces candidates for manual review; it does not itself assert a match the way the KQL/SPL joins do.

**[QUERY]** YARA-L, using a multi-event rule matched on a shared identity within a time window.

```yaral
// CONCEPTUAL SAMPLE — validate that your UDM parser populates target.user.userid identically for both event types.
rule account_created_then_privileged {
  meta:
    severity = "HIGH"
  events:
    $create.metadata.event_type = "USER_CREATION"
    $add.metadata.event_type = "GROUP_MODIFICATION"
    $create.target.user.userid = $add.target.user.userid
  match:
    $create.target.user.userid over 15m
  condition:
    $create and $add
}
```

Plausible expected result: one detection per matched creation-then-add pair inside the 15-minute window. Interpretation: unchanged from the KQL/SPL versions.

**[QUERY]** Elastic EQL — an ordered two-event pattern is exactly what EQL `sequence` is for, per DEH Appendix A5 §8's decision table.

```eql
// CONCEPTUAL SAMPLE — 15-minute maxspan illustrative; validate SamAccountName/MemberName field availability against your own Winlogbeat mapping.
sequence with maxspan=15m
  [any where event.code == "4720"] by winlog.event_data.SamAccountName
  [any where event.code in ("4728", "4732", "4756")] by winlog.event_data.MemberName
```

Plausible expected result: a matched sequence per qualifying pair. Interpretation: unchanged.

**[FALSE POSITIVE]** Automated onboarding pipelines that create an account and add it to a baseline group (an "All Staff" distribution group, a default department group) in the same SCIM/Terraform run are the dominant false-positive source, and during a hiring wave this can produce dozens of legitimate create-then-add pairs a week. Narrow the window to exclude the fleet's own SCIM/AD Connect service identity as the adder, or require the target group to be on a maintained privileged-group list (Domain Admins, Enterprise Admins, local Administrators) rather than matching on any group — most pipelines already carry the group name in the event, so this is a one-line filter addition, not a redesign.

**[PIVOT]** Pull the creator's and adder's own accounts for any privilege-escalation activity in the prior 24 hours (QC-11-04), and check whether the new account has since authenticated interactively (`4624` Type 2 or Type 10) rather than through the service context that normally uses newly-provisioned accounts first.

> **Blind Spot**
> Privilege equivalent to group membership can be granted by writing a permissive ACE — `GenericAll` or `WriteDACL` — directly onto a sensitive object instead of ever touching Event ID 4728, 4732, or 4756. DEH Part 13 §8 names this exact blind spot for the group-membership analytic this pattern's second half depends on; a hunt that only watches create-then-add-to-group has no visibility into that path at all.

### QC-11-03 — Existing account added to a privileged group with no matching history

| Field | Value |
|---|---|
| **Pattern ID** | `QC-11-03` |
| **MITRE** | T1098 (Account Manipulation) |
| **Behavior** | Existing account added to a privileged group by an actor with no history of doing so. |
| **DEH cross-ref** | DEH Part 13 §8 (Privilege and admin-group changes); this pattern is the underlying exploratory hunt behind DET-13-05 |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) |

**[HUNTER]** DEH's DET-13-05 needs an approved-change-window lookup, keyed on both the group and the specific member, already populated before it can distinguish a legitimate addition from an unauthorized one. Most teams hunting this pattern for the first time don't have that lookup built yet. This hunt substitutes a cruder but immediately available signal — has this specific actor ever added a member to this specific privileged group before — and treats "never, until today" as worth a look while the real change-window integration gets built.

**[QUERY]** Sigma, scoped to a maintained privileged-group name list. Sigma has no cross-run state, so the historical-actor comparison below is downstream of this filter, not inside it.

```yaml
# CONCEPTUAL SAMPLE — group names illustrative; maintain your own tiered-admin-group list.
title: Privileged group membership change
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: [4728, 4732, 4756]
  privileged_groups:
    TargetUserName:
      - 'Domain Admins'
      - 'Enterprise Admins'
      - 'Schema Admins'
      - 'Administrators'
  condition: selection and privileged_groups
```

Plausible expected result: fires on every addition to the four named groups, unfiltered by actor history. Interpretation: a hit alone is not yet anomalous — it needs the historical-actor check the KQL/SPL/ES\|QL versions below apply to be useful for triage.

**[QUERY]** KQL, comparing today's additions against a 90-day-prior window for the same actor/group pair.

```kql
// CONCEPTUAL SAMPLE — 90-day baseline window illustrative; validate against your own change cadence.
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| summarize TodaysAdditions = count() by SubjectUserName, TargetUserName
| join kind=leftouter (
    SecurityEvent
    | where EventID in (4728, 4732, 4756)
    | where TimeGenerated < ago(1d) and TimeGenerated > ago(90d)
    | summarize PriorAdditions = count() by SubjectUserName, TargetUserName
  ) on SubjectUserName, TargetUserName
| where isnull(PriorAdditions)
```

Plausible expected result: rows where an actor added a member to a privileged group with zero recorded prior additions to that same group. Interpretation: consistent with a first-time privileged-group change by this actor — could be a newly delegated admin duty or an unauthorized change; the [PIVOT] below is how you tell them apart.

**[QUERY]** SPL, same comparison via a left join.

```spl
// CONCEPTUAL SAMPLE — 90-day baseline window and group list illustrative; validate against your own change cadence.
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
TargetUserName IN ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| stats count as todays_additions by SubjectUserName TargetUserName
| join type=left SubjectUserName TargetUserName [
    search index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756) earliest=-90d latest=-1d
    | stats count as prior_additions by SubjectUserName TargetUserName
  ]
| where isnull(prior_additions)
```

Plausible expected result and interpretation: identical shape to the KQL version.

**[QUERY]** AQL, disambiguated here as QRadar's query language, not standard SQL — targeting the current-window count directly.

```sql
-- CONCEPTUAL SAMPLE — current-window count only, no cross-window join; group list illustrative, validate against your own DSM mapping.
SELECT username AS "Actor",
       "Target Username" AS "Group",
       COUNT(*) AS "Additions Today"
FROM events
WHERE QIDNAME(qid) IN (
  'A member was added to a security-enabled global group',
  'A member was added to a security-enabled local group',
  'A member was added to a security-enabled universal group'
)
AND "Target Username" IN ('Domain Admins','Enterprise Admins','Schema Admins','Administrators')
GROUP BY username, "Target Username"
LAST 24 HOURS
```

Plausible expected result: a small table of (actor, group, count) rows for the current window only — QRadar's AQL has no cross-window self-join primitive, so the 90-day "has this actor ever done this before" comparison has to be run as a second, separately-scoped search and diffed by hand, or accumulated into a Reference Set that grows as each new (actor, group) pair is first observed. Interpretation: same as the KQL/SPL versions once the historical diff is applied manually.

**[QUERY]** YARA-L, scoped to the same privileged-group list; the historical-actor comparison needs a reference list populated by a separate scheduled rule, the same caveat as AQL above.

```yaral
// CONCEPTUAL SAMPLE — %privileged_groups reference list illustrative; unfiltered by actor history, see [HUNTER] above.
rule privileged_group_add_scoped {
  meta:
    severity = "HIGH"
  events:
    $e.metadata.event_type = "GROUP_MODIFICATION"
    $e.target.group.group_display_name in %privileged_groups
  condition:
    $e
}
```

Plausible expected result: one detection per qualifying addition, unfiltered by history, same caveat as the Sigma block above.

**[QUERY]** Elastic ES\|QL — a wide-lookback threshold comparison is exactly what ES\|QL fits best per DEH Appendix A5 §8's decision table.

```esql
// CONCEPTUAL SAMPLE — 90-day baseline window and group list illustrative; validate against your own change cadence.
FROM logs-windows.security-*
| WHERE event.code IN ("4728", "4732", "4756") AND @timestamp > NOW() - 91 days
| EVAL is_privileged_group = winlog.event_data.TargetUserName IN ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| WHERE is_privileged_group == true
| EVAL period = CASE(@timestamp > NOW() - 1 day, "today", "baseline_90d")
| STATS additions = COUNT(*) BY winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName, period
```

Plausible expected result: two rows per (actor, group) pair — a "today" count and a "baseline_90d" count. An actor/group pair present only in the "today" bucket is the anomaly an analyst finds by comparing the two counts side by side. Interpretation: same as the KQL/SPL versions.

**[FALSE POSITIVE]** A newly hired admin or a newly rotated on-call rotation performing their first-ever privileged-group addition produces exactly this signature — zero prior history is also the shape of "someone just got delegated this responsibility." Expect a visible spike whenever on-call admin duty rotates, commonly quarterly. The fix DEH already names for DET-13-05 applies directly here: layer an approved-change-window lookup on top rather than trying to characterize "normal first-time admin" precisely enough to exclude it.

**[PIVOT]** Pull the actor's own recent authentication history for anything unusual — a new source host, an off-hours logon — immediately before the group change, and check whether the newly added member has since exercised the privileged access (a matching Event ID 4672 or privileged logon on a sensitive host); a grant that's never subsequently used carries a different risk profile than one immediately exercised.

> **Detection Autopsy — "alert on every 4728/4732/4756"**
>
> **The rule:** Fire an alert on any Event ID 4728, 4732, or 4756, unscoped.
> **Why it shipped:** It's a one-line event-ID filter, and group-membership auditing is commonly enabled earlier than more advanced identity auditing, so the data is already there.
> **How it failed:** Application-tiered "administrators" groups for a specific SharePoint site or Teams channel, and routine HR-distribution-list-adjacent groups, get swept in whenever the privileged-group list isn't scoped precisely — producing dozens of daily hits on groups nobody would actually call privileged.
> **The fix:** The scoped, maintained privileged-group list used above, kept current as new admin-tiered groups get created — a recurring maintenance job, not a one-time filter.

**[SOC MANAGEMENT]** Run this as a daily hunt until an approved-change-window integration exists to graduate it into DET-13-05's standing rule. Against DEH Part 41's six-tier Detection Coverage scale, this pattern presently scores as exploratory hunt-only coverage, not a standing detection; if it stays hunt-only past the point where the change-window data actually becomes available to build DET-13-05 for real, that's Detection Debt (DEH Part 43) accumulating on a fix that's ready to ship, not a genuinely open coverage gap.

### QC-11-04 — Sensitive privilege or token right granted outside normal administrative activity

| Field | Value |
|---|---|
| **Pattern ID** | `QC-11-04` |
| **MITRE** | No clean single-technique mapping — see [HUNTER] framing |
| **Behavior** | Sensitive user right or special privilege granted outside a known administrative/deployment pattern. |
| **DEH cross-ref** | DEH Part 8 §4 (4672 field reference); cf. DET-08-02 (baseline-anomaly design); no DEH analytic for 4703 |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), Elastic (KQL) — YARA-L: `N/A`, see below |

**[HUNTER]** Granting a low-privileged account `SeDebugPrivilege` or `SeImpersonatePrivilege` directly, without ever adding it to a privileged group, is quieter than QC-11-02/QC-11-03's group-membership route precisely because it skips the comparatively well-monitored 4728/4732/4756 events entirely. A hunter watching only group membership has a genuine blind spot here — this pattern watches the rights-assignment and special-logon events instead. On the MITRE mapping: T1098's published sub-techniques don't cover on-premises User Rights Assignment grants — the same gap DEH Part 13 §8 names for group membership, extended here to the rights-assignment case — and T1134 (Access Token Manipulation) covers *using* an already-held privilege to impersonate a token at runtime, not the act of granting the underlying right, so neither fits cleanly.

**[QUERY]** Sigma, scoped to three specific sensitive rights out of the much longer list Event ID 4703 (A user right was adjusted) can carry.

```yaml
# CONCEPTUAL SAMPLE — rights list illustrative; extend to match your own high-value privilege set.
title: Sensitive user right adjusted
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4703
  sensitive_rights:
    PrivilegeList|contains:
      - 'SeDebugPrivilege'
      - 'SeImpersonatePrivilege'
      - 'SeTcbPrivilege'
  condition: selection and sensitive_rights
```

Plausible expected result: a handful of matching events per month on most estates once scoped to these three rights — 4703 fires far more often for benign rights (`SeBatchLogonRight` and similar) that this filter excludes. Interpretation: consistent with a sensitive privilege being newly granted to an account; worth checking against a deployment or change record before escalating.

**[QUERY]** KQL.

```kql
// CONCEPTUAL SAMPLE — sensitive-rights list illustrative; extend to match your own high-value privilege set.
SecurityEvent
| where EventID == 4703
| where PrivilegeList has_any ("SeDebugPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege")
| project TimeGenerated, SubjectUserName, TargetAccount = TargetUserName, PrivilegeList, Computer
```

Plausible expected result and interpretation: same as the Sigma version above.

**[QUERY]** SPL.

```spl
// CONCEPTUAL SAMPLE — sensitive-rights list illustrative; adjust to your own Windows TA field extraction.
index=wineventlog EventCode=4703
| search PrivilegeList="*SeDebugPrivilege*" OR PrivilegeList="*SeImpersonatePrivilege*" OR PrivilegeList="*SeTcbPrivilege*"
| table _time SubjectUserName TargetUserName PrivilegeList ComputerName
```

Plausible expected result and interpretation: unchanged.

**[QUERY]** AQL, disambiguated here as QRadar's query language, not standard SQL — targeting Windows Security events ingested via WinCollect.

```sql
-- CONCEPTUAL SAMPLE — sensitive-rights list illustrative; validate WinCollect custom property names against your own DSM mapping.
SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS "Event Time",
       username AS "Actor",
       "Target Username" AS "Account",
       "Privilege List" AS "Privileges Granted"
FROM events
WHERE QIDNAME(qid)='A user right was adjusted'
AND ("Privilege List" ILIKE '%SeDebugPrivilege%'
     OR "Privilege List" ILIKE '%SeImpersonatePrivilege%'
     OR "Privilege List" ILIKE '%SeTcbPrivilege%')
LAST 7 DAYS
```

Plausible expected result and interpretation: unchanged, subject to how your own WinCollect deployment names the privilege-list custom property.

**[QUERY]** Elastic KQL — a single-event boolean match is the right-sized surface for this pattern; it does not need EQL's sequencing or ES\|QL's aggregation.

CONCEPTUAL SAMPLE — sensitive-rights list illustrative; validate against your own Winlogbeat/ECS field mapping before use.

```kql
event.code:"4703" and winlog.event_data.PrivilegeList:(*SeDebugPrivilege* or *SeImpersonatePrivilege* or *SeTcbPrivilege*)
```

Plausible expected result and interpretation: unchanged.

YARA-L: `N/A` — missing schema field. Google SecOps' UDM has no confirmed field mapping the enumerated Windows privilege-constant string (`PrivilegeList`'s `SeDebugPrivilege`/`SeImpersonatePrivilege`/`SeTcbPrivilege` values) onto a structured UDM attribute; the closest candidate (`security_result.privilege`) is unconfirmed against this specific event's actual parser output, the same missing-schema-field gap DEH Part 28 §1.1 names for `GrantedAccess`.

**[FALSE POSITIVE]** Backup software and some EDR/AV agents legitimately request `SeBackupPrivilege` and `SeDebugPrivilege` for their own service accounts at install or upgrade time, producing a burst of 4703 events scoped to that one service account on rollout day. Expect this to cluster tightly around patch and deployment windows for backup and security tooling; anything outside that window on an account that isn't a known backup/EDR service identity is the signal worth chasing.

**[PIVOT]** Check whether the account that received the privilege subsequently produced a matching Event ID 4672 (Special privileges assigned to new logon) on a sensitive host, and pull the process that issued the rights-assignment change (`secedit`, `ntrights.exe`, or a GPO link event) to distinguish a scripted deployment from an interactive one.

> **Blind Spot**
> A 4672 baseline-anomaly check (DET-08-02) only sees privilege *use* at logon time — an attacker who compromises a process already running under a service account that permanently holds `SeDebugPrivilege` (a backup agent, an EDR agent) needs no fresh 4703 or anomalous 4672 at all; they inherit the sensitive right for free. Both halves of this pattern are blind to privilege that was never freshly granted or freshly logged into.

## 2. Linux account and privilege patterns

### QC-11-05 — Local account or group created outside configuration management

| Field | Value |
|---|---|
| **Pattern ID** | `QC-11-05` |
| **MITRE** | T1136.001 (Create Account: Local Account) |
| **Behavior** | Local Linux account or group created outside configuration-management tooling. |
| **DEH cross-ref** | DEH Part 3 §6.2 (auditd `auid`/`exe`/`comm` fields); DEH Part 11 §1 (cross-OS scope) — no dedicated DEH analytic |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (EQL) |

**[HUNTER]** A fleet managed by Ansible, Puppet, or Chef creates and modifies accounts through that tool's own service identity almost exclusively; a `useradd`, `adduser`, or `groupadd` process whose parent is an interactive shell, run under a human `auid`, is the shape worth chasing on that kind of fleet. This is the direct Linux analog of QC-11-01, pivoting on `auid` — the login identity that survives a `sudo`/`su` privilege change, per DEH Part 3 §6.2 — rather than a Windows `SubjectUserName`.

**[QUERY]** Sigma, targeting auditd `EXECVE` records.

```yaml
# CONCEPTUAL SAMPLE — config-management exe paths illustrative; match your own fleet's agents.
title: Local account created outside configuration management
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    comm:
      - 'useradd'
      - 'adduser'
      - 'groupadd'
  filter_cm:
    exe|contains:
      - '/usr/bin/ansible'
      - '/opt/puppetlabs'
      - '/usr/bin/salt-minion'
  condition: selection and not filter_cm
```

Plausible expected result: a small number of `EXECVE` records per week naming `useradd`, `adduser`, or `groupadd` with a non-config-management `exe` path. Interpretation: consistent with a human operator or a script outside the fleet's normal provisioning path creating a Linux account — still routine on hosts intentionally managed by hand.

**[QUERY]** KQL, targeting Microsoft Defender for Endpoint's Linux process telemetry.

```kql
// CONCEPTUAL SAMPLE — config-management process-name list illustrative; match your own fleet's agents.
DeviceProcessEvents
| where FileName in ("useradd", "adduser", "groupadd")
| where InitiatingProcessFileName !in ("ansible-playbook", "puppet", "salt-minion")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

Plausible expected result and interpretation: same shape as the Sigma version.

**[QUERY]** SPL, targeting auditd forwarded via syslog.

```spl
// CONCEPTUAL SAMPLE — config-management process-name list illustrative; match your own fleet's agents.
index=linux_auditd type=EXECVE comm IN ("useradd", "adduser", "groupadd")
| where NOT match(exe, "ansible|puppet|salt-minion")
| table _time host auid comm exe
```

Plausible expected result and interpretation: unchanged.

**[QUERY]** AQL, disambiguated here as QRadar's query language, not standard SQL — targeting raw syslog ingestion of auditd output.

```sql
-- CONCEPTUAL SAMPLE — raw-payload text match; config-management process-name exclusions illustrative, validate against your own auditd feed.
SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS "Event Time",
       sourceip AS "Host",
       UTF8(payload) AS "Raw Payload"
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'
AND (UTF8(payload) ILIKE '%comm="useradd"%'
     OR UTF8(payload) ILIKE '%comm="adduser"%'
     OR UTF8(payload) ILIKE '%comm="groupadd"%')
AND UTF8(payload) NOT ILIKE '%ansible%'
AND UTF8(payload) NOT ILIKE '%puppet%'
AND UTF8(payload) NOT ILIKE '%salt-minion%'
LAST 24 HOURS
```

Plausible expected result: matching raw payload lines rather than a parsed field table — see the language-specific note in [FALSE POSITIVE] below. Interpretation: unchanged.

**[QUERY]** YARA-L.

```yaral
// CONCEPTUAL SAMPLE — narrow match on user-creation event type only; config-management process-path exclusion not applied here, see note below.
rule linux_account_created_outside_cm {
  meta:
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "USER_CREATION"
    $e.target.platform = "LINUX"
  condition:
    $e
}
```

Plausible expected result: one detection per qualifying creation event; the config-management exclusion applied in the other languages needs a post-filter on the process path here, since the illustrative rule above keeps the match narrow rather than assume a specific UDM field for the initiating process path. Interpretation: unchanged.

**[QUERY]** Elastic EQL — the useradd-family process and its resulting write to `/etc/passwd`/`/etc/group` are an ordered pair, which is the shape EQL `sequence` fits.

```eql
// CONCEPTUAL SAMPLE — config-management process-name list illustrative; validate file-event process attribution against your own EDR schema.
sequence by process.entity_id
  [process where process.name in ("useradd", "adduser", "groupadd") and not process.parent.name in ("ansible-playbook", "puppet", "salt-minion")]
  [file where file.path in ("/etc/passwd", "/etc/group") and event.action == "change"]
```

Plausible expected result: a matched sequence — the process launch followed by its own file write. Interpretation: unchanged.

**[FALSE POSITIVE]** Break-glass runbooks that call for a human to manually create a local emergency-access account during an outage are the main legitimate driver, and they cluster tightly around active incidents — cross-check the timestamp against the incident ticket log before treating this as suspicious on its own. A secondary driver is a misconfigured configuration-management agent that shells out to `useradd` directly instead of using its native user resource, which repeats on a fixed schedule and is worth fixing at the automation layer rather than exception-listing forever. On the AQL query specifically: most QRadar deployments ingest auditd only as raw syslog without a DSM that parses fields into custom properties, so that query matches on raw payload text rather than a structured field — expect it to be noisier and slower than the parsed-field versions in the other languages until a custom DSM or a Universal DSM extension exists for your auditd feed.

**[PIVOT]** Check the new account's UID — a UID of `0`, or a UID reused from a previously deleted account, is a stronger signal than a normal sequential UID — and whether it was immediately granted a sudoers entry (QC-11-06) in the same session.

### QC-11-06 — Sudoers configuration modified outside visudo and configuration management

| Field | Value |
|---|---|
| **Pattern ID** | `QC-11-06` |
| **MITRE** | T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching) |
| **Behavior** | Sudoers configuration modified directly, bypassing visudo and configuration management. |
| **DEH cross-ref** | DEH Part 3 §6.2–6.3 (auditd architecture/tuning); cf. HUNT-46-03 (Sudoers exposure audit, DEH Part 46) — drift counterpart to that point-in-time audit |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) |

**[HUNTER]** `visudo` validates syntax before saving and is the only sanctioned path to hand-edit sudoers on most hardened images; a direct write to `/etc/sudoers` or a file under `/etc/sudoers.d/` by any other process is worth a look regardless of what it actually changed, because the safety rail itself was bypassed. DEH Part 46's HUNT-46-03 audits the resulting sudoers *state* at a point in time; this pattern watches the write event itself, so it catches drift between audits.

**[QUERY]** Sigma, targeting auditd `PATH` records under the watched sudoers paths.

```yaml
# CONCEPTUAL SAMPLE — config-management exe paths illustrative.
title: Direct sudoers modification outside visudo
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: PATH
    name|startswith:
      - '/etc/sudoers'
      - '/etc/sudoers.d/'
  filter_visudo:
    comm: 'visudo'
  filter_cm:
    exe|contains:
      - '/usr/bin/ansible'
      - '/opt/puppetlabs'
  condition: selection and not 1 of filter_*
```

Plausible expected result: rare — most fleets see zero to low single digits per month once `visudo` and configuration management are excluded. Interpretation: consistent with sudoers being modified through an unsanctioned path; a hit deserves a look at what changed even if the change itself turns out to be benign.

**[QUERY]** KQL, targeting Microsoft Defender for Endpoint's Linux file-event telemetry.

```kql
// CONCEPTUAL SAMPLE — config-management process-name list illustrative; match your own fleet's agents.
DeviceFileEvents
| where FolderPath startswith "/etc/sudoers"
| where InitiatingProcessFileName !in ("visudo", "ansible-playbook", "puppet")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName
```

Plausible expected result and interpretation: same shape as the Sigma version.

**[QUERY]** SPL.

```spl
// CONCEPTUAL SAMPLE — config-management process-name list illustrative; match your own fleet's agents.
index=linux_auditd type=PATH name="/etc/sudoers*"
| where NOT (comm="visudo" OR match(exe,"ansible|puppet"))
| table _time host auid comm name
```

Plausible expected result and interpretation: unchanged.

**[QUERY]** AQL, disambiguated here as QRadar's query language, not standard SQL — targeting raw syslog ingestion of auditd output; the same parsed-field caveat noted for QC-11-05 applies here.

```sql
-- CONCEPTUAL SAMPLE — raw-payload text match; config-management process-name exclusions illustrative, validate against your own auditd feed.
SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS "Event Time",
       sourceip AS "Host",
       UTF8(payload) AS "Raw Payload"
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'
AND UTF8(payload) ILIKE '%sudoers%'
AND UTF8(payload) NOT ILIKE '%comm="visudo"%'
AND UTF8(payload) NOT ILIKE '%ansible%'
AND UTF8(payload) NOT ILIKE '%puppet%'
LAST 7 DAYS
```

Plausible expected result and interpretation: unchanged from the other languages, at the coarser raw-text-match granularity noted in [FALSE POSITIVE] below.

**[QUERY]** YARA-L.

```yaral
// CONCEPTUAL SAMPLE — config-management process-path exclusion illustrative; validate principal.process.file.full_path population against your own UDM parser.
rule sudoers_modified_outside_visudo {
  meta:
    severity = "HIGH"
  events:
    $e.metadata.event_type = "FILE_MODIFICATION"
    $e.target.file.full_path = /^\/etc\/sudoers/
    $e.principal.process.file.full_path != "/usr/sbin/visudo"
    $e.principal.process.file.full_path != "/usr/bin/ansible-playbook"
    $e.principal.process.file.full_path != "/opt/puppetlabs/puppet/bin/puppet"
  condition:
    $e
}
```

Plausible expected result and interpretation: unchanged.

**[QUERY]** Elastic ES\|QL — a wide-lookback fleet-level aggregation is the better fit here than a per-event alert, per DEH Appendix A5 §8's decision table, since a weekly drift review across many hosts at once is how this pattern is most often actually run.

```esql
// CONCEPTUAL SAMPLE — process-name exclusion illustrative; validate against your own fleet's configuration-management agents.
FROM logs-linux.auditd-*
| WHERE file.path LIKE "/etc/sudoers%"
| WHERE process.name NOT IN ("visudo", "ansible-playbook", "puppet")
| STATS writes = COUNT(*) BY host.name, process.name, user.name
```

Plausible expected result: a small results table naming the host, the writing process, and the acting user for every non-`visudo` sudoers touch across the lookback window. Interpretation: consistent with drift worth reviewing at the next fleet-wide sudoers audit, not necessarily an in-progress attack.

**[FALSE POSITIVE]** The dominant legitimate driver is a configuration-management run that templates sudoers content directly rather than calling `visudo` internally — several common Ansible and Puppet modules do exactly this by design, so the fix is excluding the configuration-management tool's own `exe` path, as shown above, not excluding `visudo` more broadly. A secondary, lower-volume driver is a package install or upgrade whose `postinst` script drops a vendor-supplied file into `/etc/sudoers.d/`.

**[PIVOT]** Pull the resulting sudoers grant's actual scope — `ALL=(ALL) NOPASSWD: ALL` versus a narrowly scoped single command — since DEH's HUNT-46-03 breadth-of-grant framing applies directly here, and check whether the account that received the grant is human or a scripted service identity; a scripted identity with a broad, unscoped grant is the higher-priority finding of the two.

## Cross-references

DEH Part 8 (Windows Detection Engineering) and DEH Part 13 (Identity: Directory, Privilege & Kerberos Detection) own the Windows telemetry and analytic mechanics this part's four Windows patterns build on; DEH Part 3 §6 (Linux host telemetry) and DEH Part 11 (Endpoint Detection Engineering) own the equivalent Linux mechanics behind QC-11-05 and QC-11-06; DEH Part 46 (Identity Compromise Model) owns HUNT-46-03's sudoers-exposure audit that QC-11-06 complements; DEH Parts 23–29 own the query-language syntax fundamentals used across every `[QUERY]` block in this part; DEH Parts 41–43 own the Detection Coverage/Quality/Debt scoring this part's one `[SOC MANAGEMENT]` entry applies without redefining; cookbook Part 12 (Scheduled Tasks & Service Manipulation) and Part 15 (Host & Directory Discovery) own the neighboring persistence and recon behaviors this part deliberately excludes; cookbook Parts 25–26 own the cloud-native IAM equivalent of this part's Windows/Linux scope.
