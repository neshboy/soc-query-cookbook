---
title: "Lateral Movement via Stolen Tokens & Ticket Reuse"
part: 17
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["deh:part13"]
---

# Part 17 — Lateral Movement via Stolen Tokens & Ticket Reuse

## Why this part exists

**[CONCEPT]** This part covers the *use* of authentication material an attacker already holds — a stolen NTLM hash, or a captured, replayed, or forged Kerberos ticket — to authenticate to a host or resource as someone else. It adapts, rather than re-derives, the detection logic DEH Part 13 §5 (Pass-the-Hash, Pass-the-Ticket, and forged tickets) already develops for this exact material. DEH Part 13 §5's own framing is the load-bearing fact behind every pattern below: "the single hardest thing about all three" techniques — Pass-the-Hash, Pass-the-Ticket, and Golden/Silver Ticket forgery — is that a forged or replayed ticket carrying normal-looking field values produces a logon that is indistinguishable from a real one. DEH Part 13 §5 names two places the anomaly can still surface: the *absence* of a corresponding TGT-issuance event (Event ID 4768) upstream of a ticket's later use, which it calls "the most reliable tell in practice"; and a downstream fact the ticket forger has to guess or that doesn't refresh the way real Kerberos state does, such as a ticket-encryption type or authentication package inconsistent with the account's own configured or observed baseline — the same logic DEH DET-13-03 builds for NTLM fallback specifically. This part's three patterns are direct adaptations of that reasoning into this book's own six-language, per-pattern format; DEH Part 13 §5 is cited throughout rather than re-explained.

This part is the deliberate mirror image of this book's own Part 7 (Kerberos & Directory Credential Attacks), which covers how the underlying hash or ticket material gets harvested in the first place — Kerberoasting, AS-REP Roasting, DCSync, LSASS memory access — and explicitly defers the *use* of that material to this part rather than covering it itself. That is the same theft-versus-use split ATT&CK draws between Credential Access and Lateral Movement, and BOOK-INDEX.md states it explicitly for this exact pair of parts. The boundary is not merely nominal: Part 7's own QC-07-04 already builds the anti-join half of DEH Part 13 §5's absence-of-issuance correlation, for the case of a ticket with no matching issuance anywhere in the domain — Golden Ticket forgery. `QC-17-02` below adapts the same underlying DEH Part 13 §5 reasoning to a related but distinct case that pattern does not cover: a ticket that genuinely *was* issued somewhere, but is presented from a different host than the one it was issued to — Pass-the-Ticket, not wholesale forgery. Read the two together rather than expecting either to duplicate the other.

This part also draws a second boundary, against Part 16 (Lateral Movement via Admin Tools & Remote Services). Part 16 is organized around the *mechanism* an attacker uses to run something on a second host — a service install, a WMI call, a WinRM session, an RDP logon — regardless of whether the credentials behind it were phished, guessed, or stolen. This part is organized around the *credential material itself* being reused in a way that doesn't match how it was supposed to have been issued or presented, regardless of what the attacker does once authenticated. The same intrusion can trip a pattern in both parts — a Pass-the-Hash logon (this part) that then runs a PsExec-style service (Part 16's `QC-16-01`) is one attacker action generating two independent, complementary telemetry hits — and that overlap is intentional, not a duplication to fix.

Three named patterns are covered below. This part's fuller pattern budget (BOOK-INDEX.md, Section G) leaves room for stolen-material lateral-movement patterns outside DEH Part 13 §5's own scope entirely — token impersonation, RDP session hijacking — which draw on a different DEH telemetry surface (DEH Part 8's logon-type mechanics and DEH Part 11's process-tree correlation, rather than the Kerberos/NTLM material DEH Part 13 §5 covers) and are left for a later pass rather than forced into this one just to fill the budget. Every pattern below extends telemetry fundamentals DEH Part 8 (Windows Detection Engineering) already teaches field-by-field — logon types, 4672's privilege list, the 4768/4769 Kerberos ticket lifecycle — cited rather than re-taught. Query-language syntax and semantics for every block below are DEH Parts 23–29's and DEH Appendix A5's material, cited rather than re-derived per this book's own stated job. Once any pattern below graduates from an exploratory hunt into a standing rule, scoring its coverage, quality, and debt is DEH Parts 41–43's job, applied to this book's own catalog in Part 28 — not repeated per pattern here.

## 1. Credential-material reuse: Pass-the-Hash, Pass-the-Ticket, and overpass-the-hash

### QC-17-01 — Pass-the-Hash-shaped NTLM logon for a privileged account

| Field | Value |
|---|---|
| **Pattern ID** | `QC-17-01` |
| **MITRE** | T1550.002 (Use Alternate Authentication Material: Pass the Hash) |
| **Behavior** | A network logon (Logon Type 3) for a privileged or otherwise sensitive account authenticates via the NTLM package rather than Kerberos, from a source outside that account's known NTLM-permitted exception list, with the resulting token immediately carrying a sensitive privilege. |
| **DEH cross-ref** | DEH Part 13 §5 (Pass-the-Hash, Pass-the-Ticket, and forged tickets), DET-13-03 (NTLM fallback from an AES-Kerberos-only account) — this pattern is the logon-side mirror of DET-13-03's validation-side signal; DEH Part 8 §3–§4 (4624 logon-type/package fields, 4672 special-privilege assignment); this book's `QC-07-06` (LSASS memory access, the usual harvesting precursor). |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Pass-the-Hash never touches Kerberos at all — the attacker already holds the NTLM hash, so there's no AS-REQ step to check for absence the way `QC-17-02` below does. The tell instead is the authentication package itself: on a domain where Kerberos is healthy and the default negotiated protocol, a privileged account authenticating over the network via `NtLmSsp` from a source that account has never used before is worth a look before a per-account NTLM baseline exists to build a standing rule against. Reach for this hunt right after a `QC-07-06` LSASS-access hit names a specific account, to check whether that harvested hash already moved.

**[QUERY]** Sigma, targeting the Windows Security log's logon event, filtered to a placeholder-substituted privileged-account list and a known-source exception list (Sigma's `%…%` placeholder convention, filled in per deployment).

CONCEPTUAL SAMPLE — the privileged-account and known-source lists are placeholders; validate both against your own directory before use.

```yaml
title: NTLM network logon for a privileged account outside its NTLM exception list
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    TargetUserName:
      - '%PrivilegedAccounts%'
  filter_known:
    WorkstationName:
      - '%KnownNtlmSources%'
  condition: selection and not filter_known
falsepositives:
  - Legacy applications, network appliances, and cross-forest trusts that authenticate over NTLM by design
level: medium
```

Expected result: rare rows naming a privileged `TargetUserName` authenticating via NTLM from a `WorkstationName`/`IpAddress` outside the known exception list — a moderately sized domain with the exception list already tuned plausibly surfaces single digits over a week. Interpretation: consistent with an NTLM hash being replayed rather than a Kerberos ticket obtained the normal way; not proof the hash wasn't entered interactively by the account's own owner from a legitimate but unlisted machine.

**[QUERY]** Sentinel/Defender KQL, joining the logon event to its own 4672 privilege-assignment record on the shared logon ID.

CONCEPTUAL SAMPLE — the privileged-account and known-source lists are illustrative; untested against real Pass-the-Hash traffic.

```kql
let PrivilegedAccounts = dynamic(["CORP\\da-jsmith", "CORP\\svc-backup-admin"]);
let KnownNtlmSources = dynamic(["10.20.30.5", "10.20.30.6"]);
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName in (PrivilegedAccounts)
| where IpAddress !in (KnownNtlmSources)
| join kind=inner (
    SecurityEvent | where EventID == 4672 | project SubjectLogonId, PrivilegeList
  ) on $left.TargetLogonId == $right.SubjectLogonId
| project TimeGenerated, TargetUserName, IpAddress, WorkstationName, PrivilegeList
```

Expected result: rows naming the privileged account, the unlisted source IP, and a non-empty `PrivilegeList` (for example `SeDebugPrivilege`). Interpretation: consistent with Pass-the-Hash-based lateral movement into a privileged context, strengthened by the confirmed privilege assignment rather than the NTLM logon alone.

**[QUERY]** SPL, the same join via a subsearch against Sysmon-independent Windows Security telemetry.

CONCEPTUAL SAMPLE — field names and lookup illustrative; validate against your own field extraction.

```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
| lookup privileged_accounts.csv TargetUserName OUTPUT is_privileged
| where is_privileged="true"
| lookup known_ntlm_sources.csv IpAddress OUTPUT is_known_source
| where isnull(is_known_source)
| join TargetLogonId
    [ search index=wineventlog EventCode=4672
      | rename SubjectLogonId as TargetLogonId ]
| table _time, TargetUserName, IpAddress, WorkstationName, PrivilegeList
```

Expected result and interpretation: identical shape to the KQL entry above.

**[QUERY]** This is AQL, QRadar's query language, not standard SQL, despite the fence tag.

CONCEPTUAL SAMPLE — property names illustrative; validate against your own DSM mapping.

```sql
SELECT "Target User Name" AS account, sourceip, "Workstation Name"
FROM events
WHERE EVENTID = '4624'
  AND "Logon Type" = '3'
  AND "Authentication Package Name" = 'NTLM'
  AND "Target User Name" IN ('da-jsmith', 'svc-backup-admin')
  AND NOT REFERENCESETCONTAINS('KnownNtlmSources', sourceip)
LAST 24 HOURS
```

Expected result: a short result set naming the privileged account and the unlisted source. Interpretation: same read as the other implementations; pull the corresponding 4672 for that session in a second search to confirm privilege assignment, since this single AQL statement doesn't join the two event types.

**[QUERY]** Google SecOps YARA-L, over the Windows logon UDM event.

CONCEPTUAL SAMPLE — UDM field mapping illustrative; confirm against your own parser before trusting a zero result.

```yaral
rule qc_17_01_pth_ntlm_privileged_logon {
  meta:
    description = "NTLM network logon for a privileged account outside its known-source list"
  events:
    $logon.metadata.event_type = "USER_LOGIN"
    $logon.metadata.product_event_type = "4624"
    $logon.additional.fields["LogonType"] = "3"
    $logon.network.application_protocol = "NTLM"
    $logon.target.user.userid = $account
  condition:
    $logon and $account = "%PrivilegedAccounts%"
}
```

Expected result and interpretation: matches every privileged account authenticating via NTLM matching the placeholder list; unchanged from the other five implementations.

**[QUERY]** Elastic KQL — a single-event boolean match, the cheapest Elastic surface for this shape (DEH Appendix A5 §7.6's own precedent).

CONCEPTUAL SAMPLE — field names illustrative for a generic winlogbeat mapping.

```kql
winlog.event_id:4624 and winlog.event_data.LogonType:"3" and winlog.event_data.AuthenticationPackageName:"NTLM"
    and user.name:("da-jsmith" or "svc-backup-admin")
    and not source.ip:("10.20.30.5" or "10.20.30.6")
```

Expected result and interpretation: same as the other five implementations.

**[FALSE POSITIVE]** Legacy applications, network appliances, and IP-based service access are the dominant driver, echoing DET-13-03's own False Positive Trap on the validation side: an account reached by IP address rather than hostname, a partner-domain trust that doesn't support Kerberos, or a non-Windows SMB client (Samba, older NAS firmware) will authenticate over NTLM for that specific connection regardless of how hardened the rest of the domain is. Fix by maintaining an explicit source/target exception list per privileged account, not by loosening the privileged-account filter — a wider filter just relocates the same false positive onto more accounts.

**[PIVOT]** Check `QC-07-06` (LSASS access) and DET-13-03's own 4776 NTLM-validation signal on the source host for this account in the preceding hours, to see whether the hash was recently harvested there. If corroborated, check whether the account then continues moving through Part 16's admin-tool patterns from the same session.

### QC-17-02 — Pass-the-Ticket: Kerberos ticket used from an IP that doesn't match its own issuance

| Field | Value |
|---|---|
| **Pattern ID** | `QC-17-02` |
| **MITRE** | T1550.003 (Use Alternate Authentication Material: Pass the Ticket) |
| **Behavior** | A Kerberos service-ticket use (Event ID 4769) or the resulting network logon (Event ID 4624) presents a session whose source IP address doesn't match the source IP address recorded on that same session's own TGT issuance (Event ID 4768) — consistent with the ticket having been exported from the issuing host and replayed from a different one. |
| **DEH cross-ref** | DEH Part 13 §5, which names the absence of a matching upstream 4768 "the most reliable tell in practice" for forged-ticket use; this book's `QC-07-04` (Golden Ticket: use with no matching TGT issuance) builds the anti-join half of that reasoning, and this pattern builds the issuance-versus-use IP-mismatch half DEH Part 13 §5 also names, for a ticket that was genuinely issued but replayed elsewhere. |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL (investigative single-search only, see note), Elastic (ES\|QL) — Sigma and YARA-L: `N/A`, see below |

**[HUNTER]** `QC-07-04` catches a wholly forged ticket that was never issued anywhere. A stolen-but-genuinely-issued ticket is subtler: Mimikatz's `sekurlsa::tickets /export` or Rubeus's `dump`/`ptt` pulls a real ticket out of one host's memory and replays it on a second host, so somewhere in the domain a matching 4768 really does exist — it just wasn't issued to the host presenting the ticket. Reach for this hunt whenever a `QC-07-06` LSASS-access hit names a specific host, to check whether ticket material harvested there actually surfaced somewhere else.

**[QUERY]** Sentinel/Defender KQL, joining a session's TGT issuance to its later ticket-use or logon events on the shared logon ID, flagging an IP mismatch.

CONCEPTUAL SAMPLE — `TargetLogonId` stands in for whatever field actually correlates a 4768 issuance to later use in your environment, and the 10-hour window is illustrative; validate both against your logging pipeline and domain ticket-lifetime policy.

```kql
let ticket_lifetime = 10h;
let issuance = SecurityEvent
    | where EventID == 4768
    | where TimeGenerated > ago(ticket_lifetime)
    | project TargetLogonId, IssuingIp = IpAddress, IssuedAt = TimeGenerated;
SecurityEvent
| where EventID in (4769, 4624)
| where TimeGenerated > ago(ticket_lifetime)
| join kind=inner issuance on TargetLogonId
| where isnotempty(IssuingIp) and isnotempty(IpAddress) and IpAddress != IssuingIp
| project TimeGenerated, TargetUserName, TargetLogonId, IssuingIp, IpAddress, IssuedAt
```

Expected result: rare rows naming a session whose use-side IP differs from its own ticket's issuance IP. Interpretation: consistent with the ticket having been exported and replayed from a different host — not proof, since a roaming client's changing egress address can produce the same mismatch (see [FALSE POSITIVE]).

**[QUERY]** SPL, the same correlation via `append` and a per-session comparison.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own field extraction.

```spl
index=wineventlog EventCode=4768
| fields TargetLogonId, IpAddress
| rename IpAddress as issuing_ip
| eval role="issuance"
| append
    [ search index=wineventlog (EventCode=4769 OR EventCode=4624)
      | fields TargetLogonId, IpAddress, TargetUserName
      | eval role="use" ]
| stats values(issuing_ip) as issuing_ip values(IpAddress) as use_ip values(TargetUserName) as user
    by TargetLogonId
| where mvcount(use_ip) > 0 AND issuing_ip!=use_ip
```

Expected result and interpretation: same shape as the KQL entry above.

**[QUERY]** This is AQL, not standard SQL. QRadar's AQL has no native join between two independently filtered event sets in one statement — a standing detection needs a Reference Data Map keyed on `TargetLogonId` and populated by a companion rule at issuance time, checked by a second rule against later use events (QRadar's Building Block/Reference Set/Rule model, per DEH Part 27 §2–§3; cf. DEH DET-27-01). Shown below is the investigative version: a time-ordered pull an analyst walks by eye to compare issuance and use IPs for one account.

CONCEPTUAL SAMPLE — investigative form only; property names illustrative.

```sql
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS EventTime,
       QIDNAME(qid) AS event_type, sourceip, username
FROM events
WHERE (QIDNAME(qid) = 'A Kerberos authentication ticket (TGT) was requested'
       OR QIDNAME(qid) = 'A Kerberos service ticket was requested'
       OR QIDNAME(qid) = 'An account was successfully logged on')
  AND username = 'jsmith'
ORDER BY starttime ASC
LAST 10 HOURS
```

Expected result: a time-ordered list an analyst walks to compare the `sourceip` on the TGT-request row against every later ticket-use or logon row for the same account. Interpretation: a manually confirmed IP mismatch is consistent with the same behavior the other three covered languages express as a single correlated query.

**[QUERY]** This is a same-key, cross-event-type comparison, not an ordered sequence — ES\|QL's `LOOKUP JOIN` against a maintained issuance table expresses it directly; plain EQL's `sequence` stage has no field-inequality join of this shape (DEH Appendix A5 §4).

CONCEPTUAL SAMPLE — assumes a `kerberos_ticket_issuance` lookup index refreshed on a short schedule from 4768 events; field names illustrative for a generic winlogbeat mapping.

```esql
FROM winlogbeat-*
| WHERE (event.code == "4769" OR event.code == "4624")
| LOOKUP JOIN kerberos_ticket_issuance ON winlog.event_data.TargetLogonId
| WHERE kerberos_ticket_issuance.issuing_ip IS NOT NULL AND source.ip != kerberos_ticket_issuance.issuing_ip
```

Expected result and interpretation: same shape as the KQL/SPL implementations above.

**Sigma — N/A (aggregation ceiling).** Sigma's correlation grammar (`event_count`, `value_count`, `temporal`/`temporal_ordered`) tests for the presence or count of matching events by a shared field value; it has no construct for comparing one correlated event's field value against a *different* correlated event's own field value, which is exactly what an issuance-IP-versus-use-IP inequality needs.

**YARA-L — N/A (missing schema field).** YARA-L can express multi-event, multi-role correlation with an inequality condition between roles, but doing so here still depends on a confirmed UDM field linking a 4768 issuance to its corresponding 4769/4624 use — the same missing-schema-field gap `QC-07-04` names for the identical reason. Forcing either language through this pattern risks a rule that looks plausible but silently never matches.

**[FALSE POSITIVE]** Two drivers dominate, and they need different fixes. First, the same DC-log-distribution and clock-skew gap `QC-07-04` names: if the 4768 landed on one domain controller and the 4769/4624 use event landed on another that doesn't feed the same query scope, or the 4768 falls just outside the lookback window, "IP mismatch" is a log-collection artifact, not a stolen ticket — confirm every domain controller's Security log reaches the same index/table before trusting a hit. Second, and more specific to this pattern than to `QC-07-04`'s forged-ticket case: a roaming client changing its own egress address mid-session — switching from office Wi-Fi to a VPN concentrator, or sitting behind a load-balanced NAT pool — flips the apparent source IP between issuance and use without the ticket ever leaving the original physical host. Cross-check a flagged mismatch against DHCP/VPN concentrator logs for that account before escalating; a genuine ticket transplant and a laptop that changed networks mid-session are otherwise indistinguishable from this query alone.

**[PIVOT]** Cross-reference `QC-07-06` to check whether the ticket was harvested from LSASS on the issuing host in the same window, and pull DHCP/VPN logs to confirm whether the "two IPs" resolve to the same physical device before treating this as a confirmed transplant.

> **Engineering Reality**
> Every implementation above assumes `TargetLogonId` genuinely correlates a 4768 issuance to its later 4769/4624 use in your environment — the same assumption `QC-07-04` flags, and it's just as load-bearing here. Some environments track that continuity through a ticket-scoped identifier distinct from the interactive-session logon ID conflated above. Confirm which field actually links the two event types in your own pipeline before trusting either a hit or a clean result; a wrong assumption here doesn't error, it just quietly never matches.

**[SOC MANAGEMENT]** This pattern is exploratory by design: run it as a periodic hunt, not a standing high-severity alert, until a baseline period confirms the roaming-client false-positive rate is genuinely tunable against your own VPN/NAT topology. Per DEH Part 41's coverage tiers, expect this pattern to sit at "exploratory" for a while — the join key's fragility across NAT boundaries is a real constraint, not a tuning oversight to fix quickly.

### QC-17-03 — Overpass-the-hash: an AES-baselined account requesting a TGT in RC4

| Field | Value |
|---|---|
| **Pattern ID** | `QC-17-03` |
| **MITRE** | T1550.002 (Use Alternate Authentication Material: Pass the Hash) |
| **Behavior** | A TGT request (Event ID 4768) for an account whose configuration or historical baseline shows AES-only Kerberos negotiates instead with a legacy RC4 ticket-encryption type — consistent with converting a stolen NTLM hash directly into Kerberos ticket material rather than presenting it over NTLM. |
| **DEH cross-ref** | DEH Part 13 §5, DET-13-03 (NTLM fallback from an AES-Kerberos-only account) — this pattern applies the same encryption-baseline logic to the 4768 TGT-request event instead of DET-13-03's 4776 NTLM-validation event; DEH Part 8 §5 (4768 fields, `TicketEncryptionType`). |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) |

**[HUNTER]** An attacker holding only an NTLM hash can still reach Kerberos-protected resources by using that hash to request a TGT directly — no plaintext password, no interactive logon — a technique commonly called overpass-the-hash. That sidesteps `QC-17-01`'s NTLM-package filter entirely, since the resulting session negotiates Kerberos downstream and looks like ordinary ticket traffic. The one place this can't hide is the TGT request's own encryption type: a tool converting a raw NTLM hash into ticket material can only produce it in RC4, regardless of what the account is actually configured or observed to use day to day. Reach for this hunt on any account already known to be AES-capable, since a downgrade there has no ordinary explanation the way it might on an unhardened legacy client.

**[QUERY]** Sigma, matching the TGT-request event against a placeholder-substituted list of accounts baselined or configured for AES-only Kerberos.

CONCEPTUAL SAMPLE — the AES-only account list is a placeholder; validate against your own `msDS-SupportedEncryptionTypes` inventory before use.

```yaml
title: RC4 TGT request from an account expected to negotiate AES-only Kerberos
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    TicketEncryptionType: '0x17'   # RC4
    TargetUserName:
      - '%AesOnlyAccounts%'
  condition: selection
```

Expected result: near-zero on a domain where AES enforcement actually holds; any row names an AES-baselined account requesting a TGT in RC4. Interpretation: consistent with a hash-to-ticket conversion tool (Rubeus `asktgt`, Impacket `getTGT.py`) rather than a normal client negotiation — see [FALSE POSITIVE] before treating a hit as confirmed.

**[QUERY]** Sentinel/Defender KQL, the same filter against a maintained AES-only account list.

CONCEPTUAL SAMPLE — untested against real overpass-the-hash traffic.

```kql
let AesOnlyAccounts = dynamic(["CORP\\svc-payroll", "CORP\\svc-hr-sync"]);
SecurityEvent
| where EventID == 4768
| where TicketEncryptionType == "0x17"
| where TargetUserName in (AesOnlyAccounts)
| project TimeGenerated, TargetUserName, IpAddress, TicketEncryptionType
```

Expected result and interpretation: unchanged from the Sigma entry above.

**[QUERY]** SPL, the same lookup-based filter.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own lookup definition.

```spl
index=wineventlog EventCode=4768 TicketEncryptionType=0x17
| lookup aes_only_accounts.csv TargetUserName OUTPUT is_aes_only
| where is_aes_only="true"
| table _time, TargetUserName, IpAddress
```

Expected result and interpretation: unchanged.

**[QUERY]** This is AQL, not standard SQL.

CONCEPTUAL SAMPLE — property names illustrative; validate against your own DSM mapping and reference set naming.

```sql
SELECT "Target User Name" AS account, sourceip
FROM events
WHERE EVENTID = '4768'
  AND "Ticket Encryption Type" = '0x17'
  AND REFERENCESETCONTAINS('AesOnlyAccounts', "Target User Name")
LAST 24 HOURS
```

Expected result and interpretation: unchanged.

**[QUERY]** Google SecOps YARA-L, over the Kerberos TGT-request UDM event.

CONCEPTUAL SAMPLE — UDM field mapping illustrative.

```yaral
rule qc_17_03_overpass_the_hash {
  meta:
    description = "AES-baselined account requesting a TGT with RC4 ticket encryption"
  events:
    $tgt.metadata.event_type = "USER_LOGIN"
    $tgt.metadata.product_event_type = "4768"
    $tgt.additional.fields["TicketEncryptionType"] = "0x17"
    $tgt.target.user.userid = $account
  condition:
    $tgt and $account = "%AesOnlyAccounts%"
}
```

Expected result and interpretation: unchanged from the other five implementations.

**[QUERY]** This is a lookup-enrichment against a maintained baseline, not a pure boolean filter — ES\|QL's `LOOKUP JOIN` expresses the account-baseline check more directly than Elastic KQL's simple query syntax, which has no join mechanism.

CONCEPTUAL SAMPLE — assumes an `aes_only_accounts` lookup index; field names illustrative.

```esql
FROM winlogbeat-*
| WHERE event.code == "4768" AND winlog.event_data.TicketEncryptionType == "0x17"
| LOOKUP JOIN aes_only_accounts ON winlog.event_data.TargetUserName
| WHERE aes_only_accounts.is_aes_only == true
```

Expected result and interpretation: unchanged.

**[FALSE POSITIVE]** `msDS-SupportedEncryptionTypes` misconfiguration or propagation lag is the dominant driver, echoing DET-13-03's own caveat on the request side rather than the validation side: an account flagged AES-only in inventory but not yet actually enforced (a recent attribute change still replicating, a child domain or trust that doesn't honor the restriction) will still negotiate RC4 for entirely legitimate reasons. Older non-Windows Kerberos clients — legacy Java/JDBC Kerberos stacks, some network appliances — also only support RC4 or DES regardless of how the target account itself is configured, and will reproduce this exact signature against an AES-only service account with zero attacker involvement. Maintain the AES-only list against confirmed *enforced* configuration, not just the attribute setting, and expect a small, identifiable population of legacy-client false positives rather than zero.

**[PIVOT]** Check `QC-07-06` for LSASS access on the requesting source in the preceding window, and check whether the resulting ticket is used to reach a new host shortly after via `QC-17-01` or `QC-17-02`.

> **Detection Autopsy**
> An early version of this pattern alerted on any RC4-encrypted TGT request domain-wide. It drowned in noise within a day — most domains still carry a long tail of legacy clients, printers, and older service accounts that negotiate RC4 as a matter of course, entirely unrelated to any attack. Scoping the rule to accounts specifically baselined or configured for AES-only Kerberos, rather than flagging RC4 itself, is what turned an unusable firehose into a rare, actionable signal — the same lesson DET-13-03 already draws for the NTLM-validation side of this exact account population.

## Cross-references

DEH Part 13 §5 (Pass-the-Hash, Pass-the-Ticket, and forged tickets) for the underlying credential-reuse and forged-ticket correlation logic every pattern in this part adapts — the absence-of-upstream-issuance tell and the encryption/authentication-package baseline mismatch DET-13-03 develops, both cited rather than re-derived; DEH Part 8 for the logon-type and Kerberos-event field mechanics behind each `[QUERY]` block; DEH Parts 23–29 and DEH Appendix A5 for the six query languages' own syntax and semantics; DEH Parts 41–43 for coverage/quality/debt scoring once any pattern here graduates to a standing rule, applied to this book's catalog in Part 28. Within this book: Part 7 (Kerberos & Directory Credential Attacks), which covers the theft side of this exact material and explicitly defers the *use* of a stolen hash or forged/replayed ticket — this part's entire scope — to Part 17 rather than covering it itself; Part 16 (Lateral Movement via Admin Tools & Remote Services) for the mechanism-side pivot named at each pattern's `[PIVOT]`.
