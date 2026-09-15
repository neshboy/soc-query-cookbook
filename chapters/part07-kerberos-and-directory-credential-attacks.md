---
title: "Kerberos & Directory Credential Attacks"
part: 7
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 7 — Kerberos & Directory Credential Attacks

## Why this part exists

**[CONCEPT]** This part covers the credential-*theft* side of Kerberos and Active Directory abuse — the point in the kill chain where an attacker turns directory access into password hashes or forgeable ticket material, before spending any of it. That covers Kerberoasting (T1558.003), AS-REP Roasting (T1558.004), DCSync (T1003.006), and the ticket-forgery and hash-harvesting techniques that feed Pass-the-Hash (T1550.002) and Pass-the-Ticket (T1550.003) — Golden Ticket (T1558.001), Silver Ticket (T1558.002), and the LSASS memory access (T1003.001) that harvests the material in the first place. The explicit boundary: the *use* of a stolen hash or a forged/replayed ticket to authenticate to a new host is Part 17's scope (Lateral Movement via Stolen Tokens & Ticket Reuse), not this one's — the same theft/use split ATT&CK draws between Credential Access and Lateral Movement. A pattern below that surfaces a theft event points forward to Part 17 at [PIVOT]; it never re-derives the use-side query itself.

This part's six patterns extend DEH Part 13 (Identity: Directory, Privilege & Kerberos Detection), which already carries DET-13-01 through DET-13-05 for this exact surface. Most patterns below adapt one of those detections across the languages DEH's own chapter doesn't show rather than inventing new logic — DET-13-01 for QC-07-01, DET-13-02 for QC-07-02, DET-13-04 for QC-07-03, and DEH Part 13 §5's own named-but-unbuilt correlation for QC-07-04 and QC-07-05. Where a query's aggregation, join, or correlation mechanics need explaining beyond what a framing sentence covers, that explanation lives in DEH Part 23–29 (the six-language canonical-detection bridge), cited rather than re-taught here. Graduating any pattern below from a hunt into a standing rule, and scoring its coverage, quality, or debt once it's there, is DEH Part 41–43's job, applied to this book's own catalog in Part 28 — not repeated per pattern in this part.

Six named patterns sit at this part's budget ceiling (BOOK-INDEX.md, Section C). They split below into two loose groupings by telemetry shape rather than by MITRE tactic: ticket-request abuse that lives almost entirely in the 4768/4769 pair (§1), and directory-replication and post-theft credential-material handling, which needs enrichment against a maintained inventory or baseline rather than a single event field (§2).

## 1. Ticket-request abuse: Kerberoasting and AS-REP Roasting

### QC-07-01 — Kerberoasting via SPN request fan-out

| Field | Value |
|---|---|
| **Pattern ID** | `QC-07-01` |
| **MITRE** | T1558.003 (Kerberoasting) |
| **Behavior** | One requesting principal fans out service-ticket requests across many distinct SPNs in a short window, instead of the one-or-two-SPN-per-legitimate-logon pattern normal Kerberos traffic produces. |
| **DEH cross-ref** | DEH Part 13 §3 (Kerberoasting), DET-13-01 (Kerberoasting via requester fan-out, not ticket-encryption type) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) |

**[HUNTER]** Kerberoasting tools request a service ticket per targeted SPN, not repeated attempts against one SPN, so a per-account repeat-count threshold — the shape a spray or brute-force detection uses — never crosses its own bar; the volume signal lives in how many *distinct* SPNs one requester touches, not how many times they touch one. A rule keyed on RC4 ticket encryption alone also goes silent once AES enforcement is in place domain-wide, and Kerberoasting against AES-ticket SPNs is still fully possible — the hash is just slower to crack. Reach for this hunt while a domain is mid-migration to AES-only SPNs, or before a fan-out threshold has been tuned against a real baseline, since a mistuned standing rule fails silently rather than erroring.

**[QUERY]** Sigma expresses the fan-out as a `value_count` correlation over a base rule matching Event ID 4769 (A Kerberos service ticket was requested), grouped by the requesting account, counting distinct `ServiceName` values inside a 10-minute window.

CONCEPTUAL SAMPLE — field names, window, and threshold illustrative; validate the distinct-SPN cutoff against your own domain's baseline request rate before use.

```yaml
title: Kerberos service-ticket request fan-out across many SPNs
id: 3f2c9b3a-79b0-4b1b-9c33-e07a10000001
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType:
      - '0x17'   # RC4
      - '0x12'   # AES256 — fan-out works against AES SPNs too, just slower to crack offline
  condition: selection
---
title: Fan-out correlation for QC-07-01
id: 8a1d0e2f-4c11-4a2a-9d33-e07a10000002
status: experimental
correlation:
  type: value_count
  rules:
    - 3f2c9b3a-79b0-4b1b-9c33-e07a10000001
  group-by:
    - TargetUserName    # the requesting account, not the service account
  timespan: 10m
  condition:
    field: ServiceName
    gte: 8              # distinct SPNs, not raw event count
```

Expected result: a small number of `TargetUserName` values crossing eight or more distinct `ServiceName` values inside ten minutes — a real Kerberoasting run against a mid-size domain's SPN population plausibly clears this within one Rubeus or Impacket `GetUserSPNs` invocation. Interpretation: consistent with one principal enumerating and ticketing most or all discoverable SPNs at once, the shape DEH Part 13 §3 documents as Kerberoasting's actual tell — not proof any hash was cracked, only that the material to attempt cracking was harvested.

**[QUERY]** Sentinel/Defender KQL over `SecurityEvent`, the same fan-out logic as the Sigma correlation above expressed in one query.

CONCEPTUAL SAMPLE — untested against real Kerberoasting traffic; validate the threshold against your own environment.

```kql
SecurityEvent
| where EventID == 4769
| where ServiceName !endswith "$"          // exclude machine-account TGS activity
| summarize DistinctSPNs = dcount(ServiceName), Services = make_set(ServiceName, 20)
    by TargetUserName, bin(TimeGenerated, 10m)
| where DistinctSPNs >= 8
```

Expected result: rows keyed on `TargetUserName` and a 10-minute bin, `DistinctSPNs` in the low double digits for a real enumeration run, `Services` spanning unrelated applications the account has no operational reason to touch together. Interpretation: a legitimate account's requests cluster around the handful of services it actually uses; a wide, unrelated `Services` set inside one short bin is the enumeration signature, independent of which ticket-encryption type shows up.

**[QUERY]** Splunk SPL over a Windows Security index, `dc()` for the distinct-SPN count.

CONCEPTUAL SAMPLE — field names illustrative; validate `index`/`sourcetype` against your own onboarding.

```spl
index=wineventlog EventCode=4769
| where NOT match(ServiceName, "\$$")
| bucket _time span=10m
| stats dc(ServiceName) as distinct_spns values(ServiceName) as spns by TargetUserName, _time
| where distinct_spns >= 8
```

Expected result and interpretation: identical in shape to the KQL version above — SPL adds nothing structurally different here since both languages aggregate one event type natively.

**[QUERY]** This is AQL, QRadar's query language, not standard SQL, despite the fence tag. The same aggregation, expressed with QRadar's `UNIQUECOUNT`.

CONCEPTUAL SAMPLE — property names illustrative; validate against your own DSM mapping for Windows Security events.

```sql
SELECT "Target Username" AS requester,
       UNIQUECOUNT("Service Name") AS distinct_spns
FROM events
WHERE EVENTID = '4769'
GROUP BY "Target Username"
LAST 10 MINUTES
HAVING UNIQUECOUNT("Service Name") >= 8
```

Expected result: a short requester/count result set, refreshed each time the search runs, with a count profile comparable to the KQL/SPL versions. Interpretation: QRadar's aggregation model handles this threshold shape natively — no Building Block/Reference Set escalation needed for the investigative version.

**[QUERY]** Google SecOps YARA-L rule over the Windows Kerberos UDM event, matching a per-principal distinct-SPN outcome inside the rule's match window.

CONCEPTUAL SAMPLE — UDM field mapping illustrative; validate against your own Windows Kerberos event parser before trusting a zero result.

```yaral
rule qc_07_01_kerberoasting_fanout {
  meta:
    description = "Requesting principal ticketing many distinct SPNs in a short window"
  events:
    $tgs.metadata.event_type = "USER_LOGIN"
    $tgs.metadata.product_event_type = "4769"
    $tgs.target.user.userid = $requester
    $tgs.target.resource.name = $spn
  match:
    $requester over 10m
  outcome:
    $distinct_spns = count_distinct($spn)
  condition:
    $tgs and $distinct_spns >= 8
}
```

Expected result: detections keyed on `$requester`, one per 10-minute window that clears the distinct-SPN outcome, carrying the matched SPN list for triage. Interpretation: the same fan-out logic as the other five languages; the main risk is whether your parser actually populates `target.resource.name` with the SPN rather than a raw service-account SID.

**[QUERY]** This is a threshold/wide-lookback aggregation, not an ordered sequence, so ES|QL is the right Elastic surface here rather than EQL's `sequence` stage, which has no aggregation of its own (DEH Appendix A5 §4).

CONCEPTUAL SAMPLE — field names illustrative for a generic Windows-event ECS mapping; validate against your own winlogbeat integration schema.

```esql
FROM winlogbeat-*
| WHERE event.code == "4769"
| STATS distinct_spns = COUNT_DISTINCT(winlog.event_data.ServiceName)
    BY winlog.event_data.TargetUserName, bucket = BUCKET(@timestamp, 10minute)
| WHERE distinct_spns >= 8
```

Expected result and interpretation: same shape and same read as the other five implementations above.

**[FALSE POSITIVE]** Legitimate bulk-service accounts that authenticate against many SPNs in one batch run — backup software, vulnerability scanners crawling many service endpoints under one service account — reproduce a wide distinct-SPN set inside a short window with no attacker involved. DET-13-01 notes the threshold needs domain-specific tuning above what a real Kerberoasting run would reach; this book has not validated a universal number, so treat the illustrative default of eight as a baseline-dependent starting point, not a cutoff, and exclude known scanner/backup service-account SIDs explicitly rather than raising the threshold for everyone.

**[PIVOT]** On a hit, pull the requester's Event ID 4624 (An account was successfully logged on) history for the same window to confirm the account is a human interactive principal rather than a batch service account, and check whether the targeted SPNs' service accounts have `msDS-SupportedEncryptionTypes` restricted to AES only (DEH Part 13 §5's DET-13-03 lookup table) — an AES-forced SPN raises the cracking cost but doesn't remove the exposure. A subsequent successful crack surfaces later as an anomalous logon from that service account, which is Part 17's hunt, not this one's.

### QC-07-02 — AS-REP Roasting via no-preauth TGT requests

| Field | Value |
|---|---|
| **Pattern ID** | `QC-07-02` |
| **MITRE** | T1558.004 (AS-REP Roasting) |
| **Behavior** | A Kerberos authentication-ticket request succeeds with no pre-authentication proof for an account configured to allow it, handing the requester an AS-REP encrypted with that account's own key to crack offline. |
| **DEH cross-ref** | DEH Part 13 §4 (AS-REP Roasting), DET-13-02 (AS-REP Roasting: TGT requests with no pre-authentication) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Unlike Kerberoasting, this technique needs no SPN and no prior enumeration beyond knowing — or guessing — which accounts have pre-authentication disabled, so the volume signal is thinner: a careful attacker requests exactly once per targeted account. Reach for this hunt instead of waiting on a standing per-account threshold whenever `Do not require Kerberos preauthentication` hasn't been centrally inventoried, since the population of exposed accounts is itself usually unknown and worth surfacing even with zero attack activity.

**[QUERY]** Single-event Sigma rule on Event ID 4768 (A Kerberos authentication ticket (TGT) was requested), matching the pre-authentication-absent signature DEH Part 13 §4 documents.

CONCEPTUAL SAMPLE — `PreAuthType` field presence and values vary by Windows Server version's audit schema; validate before deploying.

```yaml
title: AS-REQ with no Kerberos pre-authentication
id: c1a2b3d4-5e6f-4a1b-9c33-e07a20000001
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    # no TicketEncryptionType filter — an account with preauth disabled is roastable
    # regardless of which encryption type the KDC issues, unlike QC-07-01's Kerberoasting
    # fan-out, which has to handle RC4 and AES separately
  condition: selection
```

Expected result: a small, generally stable-membership set of `TargetUserName` values matching the environment's known no-preauth population, plus any newly appearing name. Interpretation: presence alone is the primary signal — a name appearing here for the first time, or from a source IP that doesn't match that account's normal workstation, is worth investigating regardless of volume.

**[QUERY]** Sentinel/Defender KQL, the same single-event boolean filter with a source-IP history check added.

CONCEPTUAL SAMPLE — untested against real AS-REP Roasting traffic.

```kql
SecurityEvent
| where EventID == 4768
| where PreAuthType == "0"          // no encryption-type filter — preauth-disabled is roastable regardless of cipher
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Count = count(), Sources = make_set(IpAddress, 10)
    by TargetUserName
```

Expected result: one row per exposed account with a `Sources` set — a legitimate no-preauth service account shows a stable, small set; an attacker attempt shows a new IP outside that account's history. Interpretation: a new entry in `Sources`, or an entirely new `TargetUserName`, is consistent with an AS-REP Roasting attempt against that account.

**[QUERY]** SPL, the same aggregation.

CONCEPTUAL SAMPLE — field names illustrative.

```spl
index=wineventlog EventCode=4768 PreAuthType=0
| stats min(_time) as first_seen max(_time) as last_seen count values(IpAddress) as sources
    by TargetUserName
```

Expected result and interpretation: identical to the KQL version.

**[QUERY]** This is AQL, not standard SQL.

CONCEPTUAL SAMPLE — property names illustrative.

```sql
SELECT "Target Username" AS account,
       MIN(starttime) AS first_seen, MAX(starttime) AS last_seen,
       COUNT(*) AS request_count
FROM events
WHERE EVENTID = '4768'
  AND "Pre-Authentication Type" = '0'
GROUP BY "Target Username"
LAST 24 HOURS
```

Expected result and interpretation: same as the KQL/SPL versions above.

**[QUERY]** Google SecOps YARA-L, single-event match.

CONCEPTUAL SAMPLE — UDM field mapping illustrative.

```yaral
rule qc_07_02_asrep_roasting {
  meta:
    description = "AS-REQ succeeding with no pre-authentication"
  events:
    $asreq.metadata.event_type = "USER_LOGIN"
    $asreq.metadata.product_event_type = "4768"
    $asreq.additional.fields["PreAuthType"] = "0"
    $asreq.target.user.userid = $account
  condition:
    $asreq
}
```

Expected result and interpretation: matches every account presenting this signature, same read as above.

**[QUERY]** A single-event boolean match — Elastic KQL is the cheapest surface for this shape (DEH Appendix A5 §7.6's own precedent, applied here).

CONCEPTUAL SAMPLE — field names illustrative for a generic winlogbeat mapping.

```kql
event.code : "4768" and winlog.event_data.PreAuthType : "0"
```

Expected result and interpretation: same as the other five implementations.

**[FALSE POSITIVE]** Legitimate legacy interoperability — older Unix/Linux Kerberos clients, some IoT and network-appliance service accounts, and intentionally exempted break-glass accounts — are configured with pre-authentication disabled for compatibility reasons unrelated to any attack. DEH Part 13's own tuning note recommends an explicit `KnownPreAuthExemptAccounts` allowlist rather than a count threshold, since a careful attacker's request count is indistinguishable from one legitimate request.

**[PIVOT]** Check whether the account's exposure (`Do not require Kerberos preauthentication` set) is itself already inventoried — if not, this is also a standing-exposure finding independent of any attack traffic, worth surfacing through the same LDAP-attribute audit DEH Part 13 §7 covers for SPN exposure. On a suspicious new source IP, pull that IP's other Kerberos activity in the same window to see whether it's also touching QC-07-01's fan-out pattern from the same host.

> **Blind Spot**
> The offline hash-cracking step against a captured AS-REP happens entirely outside any telemetry this pattern or DEH Part 13 covers. A hit here means the ticket was obtainable, not that the account's password has been cracked — cracking success itself never generates a log entry anywhere until the attacker uses the recovered password, which is Part 17's territory.

## 2. Directory replication and stolen or forged credential material

### QC-07-03 — DCSync by a non-inventoried principal

| Field | Value |
|---|---|
| **Pattern ID** | `QC-07-03` |
| **MITRE** | T1003.006 (OS Credential Dumping: DCSync) |
| **Behavior** | A principal that isn't an inventoried domain controller or documented sync/backup tool exercises the DS-Replication-Get-Changes / DS-Replication-Get-Changes-All extended rights to pull directory data, including password hashes, from a domain controller. |
| **DEH cross-ref** | DEH Part 13 §6 (DCSync and directory replication abuse), DET-13-04 (DCSync by a non-inventoried principal); pivot destination cites DEH Part 13 §6.2, HUNT-13-02 |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) |

**[HUNTER]** DCSync needs no code execution on a domain controller at all — it only needs a principal already holding, or freshly granted, the replication extended rights — so this hunt is really "who is exercising this right and are they supposed to," not a malware-presence question. Reach for it ahead of a standing DET-13-04-style rule whenever the two inventory tables the rule depends on (real domain-controller identities, documented sync/backup accounts) haven't been built yet, since an unmaintained inventory makes the standing rule either silent or self-alerting on routine replication.

**[QUERY]** Sigma expresses the base filter and the known-principal exclusion through a field-list placeholder (Sigma's `%…%` list-substitution convention, filled in per deployment). It cannot express DET-13-04's IP-versus-expected-IP enrichment branch at all — no join mechanism exists in Sigma's detection block — so that branch is dropped here, not approximated; the exclusion-list half still genuinely works, which is why this language isn't marked `N/A`.

CONCEPTUAL SAMPLE — placeholder-list mechanics vary by backend/pySigma pipeline.

```yaml
title: Directory replication rights exercised by a non-inventoried principal
id: d5e6f7a8-1b2c-4d3e-9c33-e07a30000001
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All
  filter_known:
    SubjectUserSid:
      - '%KnownReplicationPrincipals%'
  condition: selection and not filter_known
```

Expected result: near-zero on a well-inventoried domain; any row names a `SubjectUserName` outside the documented DC/sync/backup population. Interpretation: consistent with DCSync exercised by a principal not on the maintained exclusion list — see [FALSE POSITIVE] before treating this as confirmed malicious.

**[QUERY]** Sentinel/Defender KQL, adapted directly from DET-13-04's own worked query, extended with the expected-IP enrichment branch.

CONCEPTUAL SAMPLE — adapted from DEH DET-13-04; untested against real DCSync traffic (no AD domain controller exists in this book's own test environment).

```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
     or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserSid !in (KnownReplicationPrincipals)
| join kind=leftouter (DomainControllerInventory) on SubjectUserSid
| where isnull(ExpectedIpAddress) or IpAddress != ExpectedIpAddress
| project TimeGenerated, SubjectUserName, SubjectUserSid, IpAddress, ExpectedIpAddress
```

Expected result: rows naming either a SID absent from the inventory entirely, or an inventoried DC identity authenticating from an IP that doesn't match its expected one. Interpretation: consistent with DCSync run by an uninventoried principal, or a real DC's machine-account credential replayed from an attacker-controlled host.

**[QUERY]** SPL, the same lookup-and-join logic.

CONCEPTUAL SAMPLE — lookup table names and fields illustrative; validate against your own lookup definitions and DC/sync-account inventory.

```spl
index=wineventlog EventCode=4662
    (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
| lookup known_replication_principals.csv SubjectUserSid OUTPUT is_known
| where is_known!="true"
| lookup dc_inventory.csv SubjectUserSid OUTPUT ExpectedIpAddress
| where isnull(ExpectedIpAddress) OR IpAddress!=ExpectedIpAddress
```

Expected result and interpretation: same as the KQL version above.

**[QUERY]** This is AQL, not standard SQL. QRadar's `REFERENCESETCONTAINS` covers the exclusion-list half directly; the expected-IP comparison needs a *keyed* lookup (principal → expected IP), which QRadar models as a Reference Data Map maintained by a separate rule — the multi-object dependency DEH Part 27 §2–3 describes. Shown below is the exclusion-list half as a self-contained investigative search; the IP-mismatch half is a second search against that companion map once it exists, not one self-contained query.

CONCEPTUAL SAMPLE — property names illustrative; validate against your own DSM mapping and reference set naming.

```sql
SELECT "Subject User Name" AS principal, sourceip, "Properties" AS props
FROM events
WHERE EVENTID = '4662'
  AND ("Properties" ILIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'
       OR "Properties" ILIKE '%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%')
  AND NOT REFERENCESETCONTAINS('KnownReplicationPrincipals', "Subject User Sid")
LAST 24 HOURS
```

Expected result: rows naming a principal exercising replication rights who isn't on the maintained exclusion list. Interpretation: same read as the exclusion-list half of the KQL/SPL versions — the IP-mismatch enrichment is a documented gap in this single query, not a silent omission.

**[QUERY]** Google SecOps YARA-L, single-event match against the same GUIDs.

CONCEPTUAL SAMPLE — UDM field mapping illustrative.

```yaral
rule qc_07_03_dcsync_noninventoried {
  meta:
    description = "Directory replication rights exercised by a non-inventoried principal"
  events:
    $repl.metadata.event_type = "USER_RESOURCE_ACCESS"
    $repl.metadata.product_event_type = "4662"
    $repl.security_result.detection_fields["Properties"] = /1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2/
    $repl.principal.user.userid = $subject
  condition:
    $repl and $subject != "%KnownReplicationPrincipals%"
}
```

Expected result and interpretation: same shape as the Sigma version — the exclusion-list check works, the keyed IP-mismatch enrichment is out of scope for one rule here too.

**[QUERY]** This is a static-table enrichment against a maintained inventory, not an ordered event sequence — ES|QL's `LOOKUP JOIN` expresses the inventory check more directly than EQL's `sequence` stage, which has no join of this shape (DEH Appendix A5 §4).

CONCEPTUAL SAMPLE — field names illustrative for a generic winlogbeat mapping.

```esql
FROM winlogbeat-*
| WHERE event.code == "4662" AND winlog.event_data.Properties RLIKE ".*1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2.*"
| LOOKUP JOIN known_replication_principals ON winlog.event_data.SubjectUserSid
| WHERE known_replication_principals.is_known != true
```

Expected result and interpretation: same as the KQL/SPL/AQL versions' exclusion-list half.

**[FALSE POSITIVE]** DEH Part 13 §6's own Blind Spot is the load-bearing caveat here: the exclusion list itself is the trust boundary. A compromised Entra Connect/AAD Connect sync account, or a real domain controller's own machine-account credential replayed from that DC's own IP, both pass every check this pattern runs — a clean result means "no *uninventoried* principal did this," not "no DCSync happened." Keep both inventory tables current; a newly promoted DC not yet added will self-alert on its first replication cycle, which is a maintenance gap, not a detection failure.

**[PIVOT]** On a hit, check whether the flagged SID legitimately needs replication rights at all via DEH Part 13 §6.2's HUNT-13-02 — auditing who already holds DS-Replication-Get-Changes/-All directly on the domain object's ACL, independent of activity. A flagged principal that shouldn't hold the right is a privilege-escalation finding on its own, even before deciding whether this specific event was malicious.

> **Engineering Reality**
> Every query above depends on DEH Part 13 §6's two audit prerequisites — SACL auditing on the domain object itself, and "Audit Directory Service Access" enabled on every domain controller, not just one — actually being configured. Miss either and this pattern produces zero results domain-wide, which reads identically to "no DCSync attempts happening." Confirm both before trusting a clean result.

### QC-07-04 — Golden Ticket: use with no matching TGT issuance

| Field | Value |
|---|---|
| **Pattern ID** | `QC-07-04` |
| **MITRE** | T1558.001 (Golden Ticket) |
| **Behavior** | A Kerberos-authenticated logon or service-ticket use presents a session with no corresponding Event ID 4768 issuance anywhere in that logon session's lifetime — a legitimately issued ticket always has an issuance event upstream of its use; a forged `krbtgt`-signed ticket doesn't. |
| **DEH cross-ref** | DEH Part 13 §5 (Pass-the-Hash, Pass-the-Ticket, and forged tickets) names the absence-of-upstream-4768 correlation as "the most reliable tell in practice" for a forged ticket, then explicitly defers building it to "a stateful correlation engine (DEH Part 30)"; this pattern is that build. |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL, Elastic (ES\|QL) — Sigma and YARA-L: N/A, see below |

**[HUNTER]** A well-forged Golden Ticket reproduces every field a normal TGT-derived session would carry, so no single-event rule distinguishes it — the tell is structural, not a field value: the ticket's use has no matching issuance record anywhere upstream. Reach for this hunt when a suspected compromise involves privileged access with no clean explanation for how the session got its TGT, since a standing rule for this shape needs the stateful correlation engine DEH Part 13 §5 explicitly says it hasn't built.

**[QUERY]** Sentinel/Defender KQL, an anti-join between Event ID 4769/4624 use events and 4768 issuance events on the same logon session, inside the ticket's maximum lifetime window.

CONCEPTUAL SAMPLE — `TargetLogonId` stands in for whatever field actually correlates a 4768 issuance to later ticket use in your environment, and the lifetime window is illustrative; validate both against your logging pipeline and your domain's actual maximum ticket-lifetime policy (see [FALSE POSITIVE]).

```kql
let ticket_lifetime = 10h;
let issued = SecurityEvent
    | where EventID == 4768
    | project TargetLogonId, IssuedAt = TimeGenerated;
SecurityEvent
| where EventID in (4769, 4624)
| where AuthenticationPackageName == "Kerberos"
| where TimeGenerated > ago(ticket_lifetime)
| join kind=leftanti issued on TargetLogonId
| project TimeGenerated, TargetUserName, TargetLogonId, IpAddress
```

Expected result: near-zero under healthy conditions; any row is a Kerberos-authenticated session or ticket use with no matching TGT issuance record for its `TargetLogonId` anywhere in the lookback window. Interpretation: consistent with a forged ticket presented without ever going through a real AS-REQ — the strongest single signal DEH Part 13 §5 names for Golden Ticket, though not proof on its own (see [FALSE POSITIVE]).

**[QUERY]** SPL, the same anti-join built with a subsearch.

CONCEPTUAL SAMPLE — field names illustrative; `TargetLogonId` stands in for whatever field actually correlates ticket issuance to ticket use in your environment (see [FALSE POSITIVE]).

```spl
index=wineventlog EventCode=4768
| fields TargetLogonId
| eval issued=1
| append
    [ search index=wineventlog (EventCode=4769 OR EventCode=4624) AuthenticationPackageName=Kerberos
      | fields TargetLogonId TimeGenerated TargetUserName IpAddress ]
| stats count(eval(issued=1)) as had_issuance values(TargetUserName) as user values(IpAddress) as source
    by TargetLogonId
| where had_issuance=0
```

Expected result: a `had_issuance` of zero for a logon session that otherwise used Kerberos. Interpretation: same read as the KQL version.

**[QUERY]** This is AQL, not standard SQL. QRadar's reference-set membership function stands in for the anti-join: a companion rule populates a reference set of `TargetLogonId` values seen in a 4768 event, and this search checks for Kerberos-authenticated sessions whose `TargetLogonId` never appears in it. The standing version needs that companion population rule (DEH Part 27 §2–3's multi-object model); shown below is the investigative search that validates the logic once the reference set exists.

CONCEPTUAL SAMPLE — property names illustrative; `TargetLogonId` stands in for your environment's actual issuance-to-use correlator field (see [FALSE POSITIVE]).

```sql
SELECT "Target Logon ID" AS logon_id, "Target User Name" AS account, sourceip
FROM events
WHERE (EVENTID = '4769' OR EVENTID = '4624')
  AND "Authentication Package Name" = 'Kerberos'
  AND NOT REFERENCESETCONTAINS('IssuedTgtLogonIds', "Target Logon ID")
LAST 10 HOURS
```

Expected result: rows naming a logon session using Kerberos with no matching entry in the issuance reference set. Interpretation: same read as the KQL/SPL versions.

**[QUERY]** This is an anti-join, not an ordered sequence — EQL's `sequence` stage has no negative/absence join (DEH Appendix A5 §4), so this uses ES|QL's `LOOKUP JOIN` against the issuance table with an `IS NULL` filter instead.

CONCEPTUAL SAMPLE — field names illustrative.

```esql
FROM winlogbeat-*
| WHERE (event.code == "4769" OR event.code == "4624") AND winlog.event_data.AuthenticationPackageName == "Kerberos"
| LOOKUP JOIN issued_tgts ON winlog.event_data.TargetLogonId
| WHERE issued_tgts.IssuedAt IS NULL
```

Expected result and interpretation: same shape as the other three implementations.

**Sigma — N/A (aggregation ceiling).** Sigma's correlation spec covers `event_count`, `value_count`, and ordered (`temporal`/`temporal_ordered`) correlation of events that occur; it has no correlation type for the *absence* of a related event, which is exactly what this pattern's tell depends on. A single Sigma rule can flag Kerberos-authenticated sessions, but it cannot express "and no 4768 exists for this logon ID anywhere upstream" without an external anti-join Sigma's detection block doesn't have.

**YARA-L — N/A (missing schema field).** This pattern needs to correlate a 4768 issuance against later 4769/4624 use by a shared session identifier; this book has no confirmed UDM field that carries Windows' `TargetLogonId` consistently across both event types in Chronicle's default Windows parser, and a wrong assumption here would silently produce a rule that never matches — the same caution DEH Part 28 §1.1 gives for YARA-L's unconfirmed `GrantedAccess` equivalent, applied here to session-ID continuity instead.

**[FALSE POSITIVE]** The most common failure mode DEH Part 13 §5 flags is DC-log distribution: the 4768 was issued on one domain controller and the 4769/4624 use event landed on another, and if not every DC's Security log reaches the same query scope, "no issuance found" is a log-collection gap, not a forged ticket. Confirm all domain controllers' Security logs feed the same index/table before trusting a hit, and expect a nonzero false-positive rate from clock skew pushing the issuance event just outside the lookback window on a session that started near the query's edge. Every implementation above also assumes its join key (`TargetLogonId` above) genuinely correlates a 4768 issuance to the later 4769/4624 use — some environments track that continuity through a ticket-scoped identifier distinct from the interactive-session Logon ID conflated here; confirm which field actually links the two event types in your own pipeline before trusting either a hit or a clean result.

**[PIVOT]** On a hit, check the flagged logon session's ticket lifetime and encryption type against domain Kerberos policy defaults — a lifetime exceeding the domain's configured maximum, or an encryption type inconsistent with `krbtgt`'s current key version, both independently support forgery. If confirmed, the account used to present the ticket is now Part 17's problem, not this one's.

> **What Would Change My Mind**
> This pattern assumes DC-log distribution gaps and clock skew are rare enough that an anti-join hit is worth escalating on its own. If a production audit of this environment showed 4768 events routinely landing on a domain controller excluded from this query's scope, or clock skew regularly exceeding a few minutes across domain controllers, the false-positive rate would make this pattern unusable as written — it would need to fall back to the narrower encryption-downgrade/lifetime-anomaly heuristic (closer to DEH Part 13 §5's DET-13-03) instead of the anti-join.

### QC-07-05 — Silver Ticket: first-seen service-ticket source for a high-value SPN

| Field | Value |
|---|---|
| **Pattern ID** | `QC-07-05` |
| **MITRE** | T1558.002 (Silver Ticket) |
| **Behavior** | A source requests a service ticket for a specific high-value SPN for the first time relative to that SPN's own multi-week request baseline — the KDC-visible hash-harvesting step that typically precedes a Silver Ticket forge; the forged ticket's own later use bypasses the KDC entirely and leaves no comparable record to catch here at all. |
| **DEH cross-ref** | DEH Part 13 §5 (Pass-the-Hash, Pass-the-Ticket, and forged tickets) — the same absence-of-issuance reasoning as QC-07-04, applied at the SPN/source level against a rolling baseline instead of a per-session anti-join. |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL, Elastic (ES\|QL) — Sigma and YARA-L: N/A, see below |

**[HUNTER]** A Silver Ticket is forged offline against a stolen service-account hash and, once forged, is presented directly to the target service — it never touches the KDC, so its actual use leaves no 4769 record to catch here at all. What this hunt watches for instead is the step that usually has to happen first: a source requesting a ticket for that high-value SPN for the first time relative to the SPN's own request history, the same KDC-visible signature a Kerberoasting-style attempt to harvest that SPN's hash would produce. Reach for this hunt on high-value SPNs specifically — domain-admin-equivalent service accounts, backup/agent services with broad access — since a full-domain first-seen baseline over every SPN is expensive to maintain and mostly noise on low-value services.

**[QUERY]** Sentinel/Defender KQL, requiring a maintained baseline of source/SPN pairs, shown as a materialized summary joined against the day's traffic.

CONCEPTUAL SAMPLE — the 30-day baseline window is illustrative; validate against how long your environment needs to establish a stable per-SPN source population.

```kql
let baseline = SecurityEvent
    | where EventID == 4769
    | where TimeGenerated between (ago(37d) .. ago(7d))
    | summarize by ServiceName, IpAddress;
SecurityEvent
| where EventID == 4769
| where TimeGenerated > ago(7d)
| where ServiceName in (HighValueSPNs)
| join kind=leftanti baseline on ServiceName, IpAddress
| project TimeGenerated, TargetUserName, ServiceName, IpAddress
```

Expected result: rare rows naming a high-value SPN and a source IP with no matching pair anywhere in the prior 30-day window. Interpretation: consistent with a ticket for that SPN never having organically originated from this source before — worth investigating as a possible hash-harvesting precursor to a Silver Ticket forge, not as the forged ticket's own use, which this event type cannot capture.

**[QUERY]** SPL, the same baseline comparison via a lookup table.

CONCEPTUAL SAMPLE — field names and lookup table illustrative; validate against your own baseline lookup definition.

```spl
index=wineventlog EventCode=4769 ServiceName IN (highvalue_spns)
    earliest=-7d
| lookup spn_source_baseline.csv ServiceName IpAddress OUTPUT seen_before
| where isnull(seen_before)
| table _time TargetUserName ServiceName IpAddress
```

Expected result and interpretation: same as the KQL version above.

**[QUERY]** This is AQL, not standard SQL. QRadar's Reference Set is the natural fit for a rolling seen-before population — a companion rule, or the reference set's own configured lifespan, maintains 30 days of SPN/source pairs, and this search checks membership.

CONCEPTUAL SAMPLE — property names illustrative; validate against your own reference set naming and configured lifespan.

```sql
SELECT "Target User Name" AS account, "Service Name" AS spn, sourceip
FROM events
WHERE EVENTID = '4769'
  AND "Service Name" IN ('HighValueSPN1','HighValueSPN2')
  AND NOT REFERENCESETCONTAINS('SpnSourceBaseline30d', "Service Name" || ':' || sourceip)
LAST 7 DAYS
```

Expected result and interpretation: same shape as the KQL/SPL versions.

**[QUERY]** A wide-lookback baseline comparison — ES|QL's native shape per the decision table in §4.2.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own baseline lookup index.

```esql
FROM winlogbeat-*
| WHERE event.code == "4769"
    AND winlog.event_data.ServiceName IN ("HighValueSPN1", "HighValueSPN2")
    AND @timestamp > NOW() - 7 days
| LOOKUP JOIN spn_source_baseline ON winlog.event_data.ServiceName, source.ip
| WHERE spn_source_baseline.seen_before IS NULL
```

Expected result and interpretation: same as the other three implementations.

**Sigma — N/A (structurally poor fit, not impossible).** A first-seen check against a rolling multi-week baseline needs persisted state outside any single rule evaluation. Sigma's static detection block has no mechanism to reference a maintained historical population — its placeholder-list convention (used for QC-07-03's flat exclusion list) only substitutes a fixed value list at pipeline-build time, not a continuously updated seen-before table.

**YARA-L — N/A (structurally poor fit, not impossible).** Chronicle's YARA-L rule engine evaluates over a bounded match window that in practice stays well under the 30-day baseline this pattern compares against. Expressing the equivalent check means exporting a baseline to an external table and enriching against it outside the rule language itself — a different pattern shape than a self-contained rule.

**[FALSE POSITIVE]** The most common driver is baseline immaturity, not attacker activity — a newly provisioned client, a failed-over application server, or a service migration introduces a genuinely new but entirely legitimate source/SPN pairing, and every one of those reads identically to a hash-harvesting probe on a first-seen check. Run this hunt with a known-change calendar in hand (deployments, DR failovers) before escalating a hit, and expect a burst of hits for a week or two after any infrastructure change to the high-value services in scope.

**[PIVOT]** Check the source host's own recent activity against QC-07-01's fan-out pattern and Part 15's discovery patterns — a first-seen SPN touch from a host that also shows enumeration activity in the same session is a much stronger combined signal than either alone. If the source host is a legitimate new server, document it and let it age into the baseline rather than tuning the baseline window down for one exception.

> **Hunter's Note**
> Don't run this baseline against every SPN in the domain — pick the handful of service accounts that are actually domain-admin-equivalent or hold broad access first, the accounts a real Silver Ticket would be worth forging, and expand scope later. A domain-wide first-seen baseline on every printer and low-value service SPN is mostly deployment noise and buries the hits that matter.

### QC-07-06 — LSASS memory access enabling hash and ticket harvesting

| Field | Value |
|---|---|
| **Pattern ID** | `QC-07-06` |
| **MITRE** | T1003.001 (OS Credential Dumping: LSASS Memory) |
| **Behavior** | A process outside a small, known set of legitimate callers opens a handle to `lsass.exe` with an access mask consistent with reading credential material — the step that harvests the NTLM hash or Kerberos ticket material later spent in Pass-the-Hash, Pass-the-Ticket, or ticket-forgery attacks. |
| **DEH cross-ref** | DEH Part 11 (Endpoint Detection Engineering) owns LSASS-access telemetry mechanics; DEH Part 13 §5 frames why this matters for Kerberos/Pass-the-Hash specifically. DET-13-03's narrower NTLM-fallback proxy (Event ID 4776 — the domain controller attempted to validate the credentials for an account) is the *use*-side complement Part 17 covers, not repeated here. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, Elastic (KQL) — YARA-L: N/A, see below |

**[HUNTER]** This is the harvesting step behind every credential-material theft pattern above it in this part — a successful Kerberoasting or DCSync run still needs the operator to get the hash or ticket off the box, or, more directly, pull it straight out of LSASS without touching Kerberos at all. Reach for it specifically on hosts a discovery hunt or an admin-tool lateral-movement hit has already flagged, since LSASS access alone, without that context, is common enough from legitimate security tooling to be a weak standalone signal.

**[QUERY]** Sysmon Event ID 10 (ProcessAccess), matching a `GrantedAccess` mask consistent with credential-reading tools against `lsass.exe`, excluding a known-good caller list.

CONCEPTUAL SAMPLE — access-mask values illustrative; validate against your own Sysmon config's `GrantedAccess` reporting and your environment's actual EDR/AV caller baseline.

```yaml
title: Suspicious process access to lsass.exe
id: e9f0a1b2-3c4d-4e5f-9c33-e07a60000001
status: experimental
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x143a'
  filter_known:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\wrsa.exe'
  condition: selection and not filter_known
```

Expected result: rare rows outside a known EDR/AV baseline, `SourceImage` naming an unexpected process — a renamed binary, a scripting-host process, a LOLBin — requesting one of the flagged access masks against `lsass.exe`. Interpretation: consistent with an attempt to read credential material directly from memory, the classic precursor to both Pass-the-Hash and ticket-forgery attacks — not proof material was successfully extracted.

**[QUERY]** Sentinel/Defender KQL over process-access telemetry.

CONCEPTUAL SAMPLE — untested; validate the `ActionType` value and the `GrantedAccess` representation inside `AdditionalFields` against your own environment.

```kql
DeviceEvents
| where ActionType == "OpenProcessApiCall"          // handle-access event, not DeviceProcessEvents' process-creation shape
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in ("MsMpEng.exe", "wrsa.exe")
| where AdditionalFields has_any ("0x1010", "0x1410", "0x143a")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, AdditionalFields
```

Expected result and interpretation: same as the Sigma version above.

**[QUERY]** SPL over Sysmon telemetry.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own Sysmon field extraction.

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
    NOT SourceImage IN ("*MsMpEng.exe", "*wrsa.exe")
    GrantedAccess IN ("0x1010","0x1410","0x143a")
| table _time ComputerName SourceImage GrantedAccess User
```

Expected result and interpretation: same as above.

**[QUERY]** This is AQL, not standard SQL. Assumes Sysmon Event ID 10 fields are mapped as custom event properties in your DSM.

CONCEPTUAL SAMPLE — property names illustrative; validate against your own DSM mapping for Sysmon Event ID 10.

```sql
SELECT "Source Image" AS caller, "Granted Access" AS access_mask, sourceip
FROM events
WHERE "Target Image" ILIKE '%lsass.exe'
  AND "Granted Access" IN ('0x1010','0x1410','0x143a')
  AND "Source Image" NOT ILIKE '%MsMpEng.exe' AND "Source Image" NOT ILIKE '%wrsa.exe'
LAST 24 HOURS
```

Expected result and interpretation: same as the other four implementations.

**[QUERY]** A single-event boolean match — Elastic KQL is the cheapest surface for this shape.

CONCEPTUAL SAMPLE — field names illustrative for a generic winlogbeat/Sysmon mapping.

```kql
process.target.name : "lsass.exe" and winlog.event_data.GrantedAccess : ("0x1010" or "0x1410" or "0x143a")
    and not process.name : ("MsMpEng.exe" or "wrsa.exe")
```

Expected result and interpretation: same as the other five implementations.

**YARA-L — N/A (missing schema field).** This book has no confirmed UDM field equivalent to Sysmon's `GrantedAccess` access-mask value in Chronicle's default process-access UDM mapping. Per DEH Part 28 §1.1, forcing a translation here risks a rule that looks correct but silently never matches against a real Chronicle instance's actual parser output.

**[FALSE POSITIVE]** Every major EDR and AV product legitimately reads LSASS memory as part of its own credential-protection or scanning function, and that population dominates this event type by volume. Maintain an explicit allowlist of your deployed security tooling's binary *paths* (not just process name, which is spoofable), and treat the access-mask filter as a second-order refinement, not the primary noise control — the allowlist is the noise control.

**[PIVOT]** Check the source host for Part 15's discovery patterns and Part 16's admin-tool lateral-movement patterns in the surrounding window — LSASS access with no discovery or lateral-movement context on the same host is far more likely to be an unlisted legitimate tool than a real theft attempt. If corroborated, the next event to expect is a new-source authentication using that host's credentials elsewhere, which is Part 17's scope, not this one's.

> **Blind Spot**
> This pattern only sees direct handle-based access to the running `lsass.exe` process. `RunAsPPL` (LSASS as a Protected Process Light) blocks exactly that access path without blocking every credential-theft technique — memory dumped via a vulnerable signed driver, secrets pulled from the SAM/SECURITY registry hives offline, or DPAPI-based credential theft all bypass this pattern entirely and produce none of the events above. A clean result here is not evidence the host wasn't harvested, only that this specific access path wasn't used.

## Cross-references

DEH Part 13 (Identity: Directory, Privilege & Kerberos Detection) for the underlying Kerberos protocol mechanics, DET-13-01 through DET-13-05, and the audit-policy prerequisites every pattern above depends on; DEH Part 11 (Endpoint Detection Engineering) for LSASS-access telemetry mechanics behind QC-07-06; DEH Part 23–29 for the six query languages' own syntax and semantics; DEH Part 30 (Correlation Engineering) for the stateful-correlation mechanics QC-07-04 and QC-07-05 build out; DEH Part 41–43 for coverage/quality/debt scoring once any pattern here graduates to a standing rule, applied to this book's catalog in Part 28. Within this book: Part 15 (Host & Directory Discovery) and Part 16 (Lateral Movement via Admin Tools & Remote Services) for the pivot context named at QC-07-05 and QC-07-06; Part 17 (Lateral Movement via Stolen Tokens & Ticket Reuse) for the *use* of any credential material a pattern in this part surfaces as stolen.
