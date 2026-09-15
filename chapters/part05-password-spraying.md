---
title: "Password Spraying"
part: 5
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 5 — Password Spraying

## Why this part exists

**[CONCEPT]** Password spraying is the low-and-slow inverse of brute force: instead of hammering one account with many passwords, the attacker tries one password (or a short list) against many accounts, one attempt each, staying under any per-account failure threshold. Attackers reach for it precisely because most identity providers lock or alert on repeated failures against a single account, not on a single failure spread across a thousand accounts — the same low-value-per-target logic behind any low-and-slow technique. See DEH Part 12 §2 for the full mechanics of how sign-in logs represent a failed authentication in the first place; this part assumes that grounding and goes straight to the query shapes.

This part's scope is the many-accounts, single-attempt shape specifically — the trait that distinguishes it from Part 4 (Brute Force), which covers high per-account volume against one target, and from Part 6 (MFA Abuse & Authentication Anomalies), which covers push-bombing, impossible travel, and a login following a failure *burst against one account*. A pattern in this part always keys its core aggregation on distinct-account count per source, not per-account failure count. Where a spray campaign's success needs to be traced forward into a specific compromised account, this part's own QC-05-05 stops at the moment a success surfaces inside a flagged cluster; what that account does next (mailbox rule changes, OAuth consent grants) is this book's Part 24 and Part 21 territory, not repeated here.

> **Detection Autopsy — "five failed logins = brute force"**
>
> **The rule:** Alert when any single account accumulates five or more failed logons (Event ID 4625) inside a rolling window.
>
> **Why it shipped:** It is the textbook brute-force signal, matches vendor-default correlation rules out of the box, and needs no baseline to tune.
>
> **How it failed:** DEH Part 40 dissects this exact rule as a seeded naive analytic. A spray tool that sends one attempt per account never accumulates five failures against any single account, so the rule never evaluates true for the entire campaign — hundreds of accounts can be touched with zero alerts fired, and the rule's own dashboard reports a clean day.
>
> **The fix:** Add a companion aggregation grouped by *source*, counting *distinct target accounts* rather than failures per account — the shape every pattern in this part builds around.

**[SOC MANAGEMENT]** QC-05-01 and QC-05-02 tune cleanly into standing near-real-time correlation rules once their thresholds are validated against a baseline — treat them as detection-engineering graduation candidates, not permanent hunts. QC-05-03 and QC-05-04 carry wider lookback windows and heavier aggregation cost; running them as a scheduled weekly or biweekly hunt is usually the better cadence than a standing rule on most SIEM licensing models, per DEH Part 43's telemetry/compute-cost framing of detection debt. QC-05-05 should never run standing on its own — it depends on the account list an upstream pattern already flagged, so its hunt cadence is tied to those upstream hits, not a fixed schedule.

### QC-05-01 — Single-source spray against many accounts

| Field | Value |
|---|---|
| **Pattern ID** | `QC-05-01` |
| **MITRE** | T1110.003 (Password Spraying) |
| **Behavior** | One source IP produces exactly one bad-password failure against each of many distinct on-prem AD accounts inside a short window. |
| **DEH cross-ref** | DEH Part 12 §2 (Identity: Access & Authentication Detection); DEH Part 40 (naive "five failed logins" teardown) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (ES\|QL) |

**[HUNTER]** A per-account lockout or failure-count rule never fires against this shape by construction — each account gets exactly one failure. The hunt reaches for a distinct-account-count aggregation grouped by source instead, which is the one framing a per-account rule structurally cannot express. Start here on any domain controller with 4625 volume, since it's the cheapest, highest-signal version of the pattern before chasing the distributed or long-horizon variants below.

**[QUERY]** Windows Security Event ID 4625 on-prem AD, expressed as a Sigma correlation over a base detection rule.

CONCEPTUAL SAMPLE — correlation type, threshold, and field names illustrative; validate `value_count` support against your Sigma backend before deploying.

```yaml
title: Password Spray - Single Source Against Many Accounts
id: 6b1f2e9a-0a3d-4b7a-9c1e-3a2f7d9c4e11
status: experimental
correlation:
  type: value_count
  rules:
    - failed_logon_bad_password
  group-by:
    - IpAddress
  timespan: 1h
  condition:
    field: TargetUserName
    gte: 15
---
title: Failed Logon - Bad Password
id: failed_logon_bad_password
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    SubStatus: '0xC000006A'
  condition: selection
```

Plausible expected result: a `TargetUserName` count in the 15–40 range for one `IpAddress` inside a single hour, almost entirely `SubStatus 0xC000006A` (bad password), with no corresponding successes. Interpretation: consistent with an automated spray tool testing one password across an enumerated account list from a single point of origin; on its own it is not evidence any account was compromised.

**[QUERY]** Sentinel/Defender KQL against `SecurityEvent`.

CONCEPTUAL SAMPLE — threshold illustrative; validate against your own baseline volume.

```kql
SecurityEvent
| where EventID == 4625 and SubStatus == "0xC000006A"
| summarize DistinctAccounts = dcount(TargetUserName),
            Accounts = make_set(TargetUserName, 25)
      by IpAddress, bin(TimeGenerated, 1h)
| where DistinctAccounts >= 15
| order by DistinctAccounts desc
```

Plausible expected result: a handful of rows per day at most in a well-segmented environment, each carrying a populated `Accounts` set worth pivoting into directly. Interpretation: the `Accounts` set is the working target list for the rest of the investigation — a hit here is a starting point, not a conclusion.

**[QUERY]** Splunk SPL against a Windows security event index.

CONCEPTUAL SAMPLE — field names (`Account_Name`, `Sub_Status`) assume a common Windows TA mapping; verify against your own field extraction.

```spl
index=wineventlog EventCode=4625 Sub_Status="0xC000006A"
| bin _time span=1h
| stats dc(Account_Name) as distinct_accounts values(Account_Name) as accounts by src_ip, _time
| where distinct_accounts >= 15
| sort - distinct_accounts
```

Plausible expected result: `accounts` returns as a multivalue field capped by SPL's default value limit — raise `maxvalues` on `stats` if the campaign is wide enough to truncate it. Interpretation: a truncated `accounts` field understates the true blast radius; don't read the displayed count as the ceiling.

**[QUERY]** QRadar AQL (not standard SQL) against the `events` view.

CONCEPTUAL SAMPLE — `UNIQUECOUNT()` is AQL's distinct-count function, not SQL's `COUNT(DISTINCT)`; confirm the field mapping for `substatus` against your Windows log source extension. `HAVING` filters on the `distinct_accounts` alias rather than the raw aggregate expression, per IBM's only documented AQL `HAVING` pattern (IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5: https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html).

```sql
SELECT sourceip, UNIQUECOUNT(username) AS distinct_accounts
FROM events
WHERE eventid = '4625' AND substatus = '0xC000006A'
GROUP BY sourceip
HAVING distinct_accounts >= 15
LAST 1 HOURS
```

Plausible expected result: one row per offending source IP within the rolling one-hour AQL search window. Interpretation: treat a QRadar hit the same as the KQL/SPL form — it is the aggregation surfacing the cluster, not a scored offense on its own unless you've built a corresponding rule.

**[QUERY]** Google SecOps YARA-L over `USER_LOGIN` UDM events.

CONCEPTUAL SAMPLE — UDM field paths illustrative; confirm `target.user.userid` is populated for your Windows log ingestion path rather than `target.user.email_addresses`.

```yaral
rule password_spray_single_source {
  meta:
    description = "Single source, one failed attempt against many distinct accounts"
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $ip
    $e.target.user.userid = $user
  match:
    $ip over 1h
  outcome:
    $distinct_accounts = count_distinct($user)
  condition:
    $e and $distinct_accounts >= 15
}
```

Plausible expected result: a detection instance with `$ip` bound to the source and `distinct_accounts` in the same 15–40 range as the other surfaces. Interpretation: identical analytic to the KQL/SPL forms; the count is the only value worth trusting from this rule until you pull the actual matched events.

**[QUERY]** Elastic ES\|QL, chosen over EQL because this is a threshold/aggregation shape rather than an ordered sequence (per DEH Appendix A5 §8's decision table).

CONCEPTUAL SAMPLE — field path for `SubStatus` depends on your Winlogbeat/ECS mapping version.

```esql
FROM logs-windows.security*
| WHERE event.code == "4625" AND winlog.event_data.SubStatus == "0xC000006A"
| STATS distinct_accounts = COUNT_DISTINCT(user.target.name) BY source.ip, BUCKET(@timestamp, 1h)
| WHERE distinct_accounts >= 15
| SORT distinct_accounts DESC
```

Plausible expected result: same shape as the KQL output, one row per source/hour bucket. Interpretation: unchanged from the other five — this is one analytic, six surfaces, per this book's own framing.

**[FALSE POSITIVE]** Vulnerability scanners and default-credential checks against many service accounts from one internal scanner host produce the identical shape — many distinct accounts, one attempt each, from a single source. So does a stale cached credential on a shared jump host or monitoring agent replaying an old password against many service accounts right after a helpdesk-driven bulk password reset. Exclude known scanner and jump-host source IPs explicitly, and cross-check the hit's timing against any recent mass-reset change ticket before treating volume alone as malicious — raising the distinct-account threshold to "fix" this just raises the bar for a real attacker too.

**[PIVOT]** Check whether any targeted account later authenticated successfully (QC-05-05). Pull IP/ASN reputation for the source. Check whether the targeted account list overlaps with a recent enumeration hit from Part 3 (Scanning & Enumeration) or Part 15 (Host & Directory Discovery) — a pre-validated account list is a stronger signal than a raw distinct-account count alone.

---

### QC-05-02 — Cloud IdP spray via legacy authentication protocols

| Field | Value |
|---|---|
| **Pattern ID** | `QC-05-02` |
| **MITRE** | T1110.003 (Password Spraying) |
| **Behavior** | Many distinct UPNs authenticate via a legacy, non-interactive protocol (IMAP4, POP3, Exchange ActiveSync) that bypasses modern MFA, one failed attempt each, from one client/IP. |
| **DEH cross-ref** | DEH Part 12 §2 (Identity: Access & Authentication Detection) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (ES\|QL) |

**[HUNTER]** Legacy authentication protocols predate MFA and mostly can't be challenged for it, so a spray that targets them succeeds on password alone even in a tenant that enforces MFA everywhere else. Hunt this specifically because Conditional Access legacy-auth blocks are frequently incomplete in practice — per-mailbox exceptions for old scanners, fax-to-email gateways, and CRM integrations are common and rarely re-audited.

> **Engineering Reality**
> A tenant-wide "block legacy authentication" Conditional Access policy is not the same claim as "legacy authentication is disabled." Per-application and per-user exclusions accumulate for years, usually for a device or integration nobody remembers approving, and none of them show up in a policy summary that only reports the policy as "enabled." Confirm actual legacy-auth volume in the sign-in logs before trusting a policy name as the ground truth.

**[QUERY]** Entra ID `SigninLogs`, Sigma correlation over a base rule.

CONCEPTUAL SAMPLE — threshold and `ClientAppUsed` value list illustrative; confirm which legacy-protocol labels your tenant actually emits.

```yaml
title: Password Spray via Legacy Authentication Protocol
correlation:
  type: value_count
  rules:
    - entra_legacy_auth_bad_password
  group-by:
    - IPAddress
  timespan: 1h
  condition:
    field: UserPrincipalName
    gte: 12
---
title: Entra ID Legacy Auth Bad Password
id: entra_legacy_auth_bad_password
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    ResultType: '50126'
    ClientAppUsed:
      - 'IMAP4'
      - 'POP3'
      - 'Exchange ActiveSync'
      - 'Other clients'
  condition: selection
```

Plausible expected result: a burst of `ResultType 50126` events tagged with a legacy `ClientAppUsed` value against 12 or more distinct UPNs in an hour. Interpretation: consistent with a spray tool specifically probing the legacy-auth surface rather than the modern interactive sign-in flow.

**[QUERY]** Sentinel KQL.

CONCEPTUAL SAMPLE — validate `ClientAppUsed` value spelling against your tenant's schema version.

```kql
SigninLogs
| where ResultType == "50126"
| where ClientAppUsed in ("IMAP4","POP3","Exchange ActiveSync","Other clients")
| summarize DistinctUsers = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
| where DistinctUsers >= 12
```

Plausible expected result: rows clustering on a small number of source IPs, each associated with a `ClientAppUsed` value your organization's actual mobile/mail clients rarely produce in bulk. Interpretation: legacy-protocol clustering on one IP against a double-digit UPN count is a stronger spray signal than the same UPN count against a modern interactive client, precisely because legacy auth can't be MFA-challenged.

**[QUERY]** Splunk SPL.

CONCEPTUAL SAMPLE — field names assume a standard Azure AD Sign-in add-on mapping.

```spl
index=azure_signinlogs ResultType=50126 ClientAppUsed IN ("IMAP4","POP3","Exchange ActiveSync","Other clients")
| bin _time span=1h
| stats dc(UserPrincipalName) as distinct_users by IPAddress, _time
| where distinct_users >= 12
```

Plausible expected result: same shape as the KQL form. Interpretation: unchanged — cross-check the volume against Entra ID's own risk-detection feed (`riskState`) if licensed, since Microsoft's own spray heuristic often independently corroborates this exact query.

**[QUERY]** QRadar AQL (not standard SQL).

CONCEPTUAL SAMPLE — assumes a custom Azure AD DSM extension already maps `clientappused` and `resulttype` as queryable fields; without that extension these are unparsed payload text, not columns.

```sql
SELECT sourceip, UNIQUECOUNT(username) AS distinct_users
FROM events
WHERE UTF8(clientappused) IN ('IMAP4','POP3','Exchange ActiveSync','Other clients')
  AND resulttype = '50126'
GROUP BY sourceip
HAVING distinct_users >= 12
LAST 1 HOURS
```

Plausible expected result: identical shape to the other surfaces, gated entirely on whether your DSM mapping is actually current. Interpretation: a zero-result run here is as likely to mean "the field mapping is stale" as "no spray occurred" — verify the mapping before trusting an empty result.

**[QUERY]** Google SecOps YARA-L.

CONCEPTUAL SAMPLE — `%legacy_auth_protocols` assumes a reference list defined elsewhere in your rule set; UDM field paths illustrative.

```yaral
rule password_spray_legacy_auth {
  meta:
    description = "Legacy auth protocol spray against many distinct UPNs from one source"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.network.application_protocol = $proto
    $e.principal.ip = $ip
    $e.target.user.email_addresses = $user
  match:
    $ip over 1h
  outcome:
    $distinct_users = count_distinct($user)
  condition:
    $e and $distinct_users >= 12 and $proto in %legacy_auth_protocols
}
```

Plausible expected result: a match bound to one `$ip` and a `distinct_users` count in the low teens or higher. Interpretation: same analytic as the other five surfaces.

**[QUERY]** Elastic ES\|QL (threshold/aggregation shape).

CONCEPTUAL SAMPLE — field names depend on your Azure AD ECS integration mapping.

```esql
FROM logs-azure.signinlogs*
| WHERE result_type == "50126" AND client_app_used IN ("IMAP4","POP3","Exchange ActiveSync","Other clients")
| STATS distinct_users = COUNT_DISTINCT(user.principal_name) BY source.ip, BUCKET(@timestamp, 1h)
| WHERE distinct_users >= 12
```

Plausible expected result and interpretation: unchanged from the other surfaces above.

**[FALSE POSITIVE]** A company-wide password-rotation policy taking effect produces a real spike in legacy-auth bad-password failures as old phones and cached mail-client profiles retry stale credentials — but that spike comes from as many *different* source IPs as accounts (each user's own device), a roughly 1:1 IP-to-account ratio. Genuine spray produces a many-accounts-to-few-sources ratio instead. Pair this pattern's distinct-account threshold with a check on distinct-source diversity before escalating; a hit with high account count and high source diversity is very likely the rotation-noise case, not a spray.

**[PIVOT]** Confirm whether legacy authentication is actually blocked for the affected UPNs despite a tenant-level Conditional Access policy claiming it is — a policy gap here is itself a finding independent of whether this specific spray succeeded. Check for any subsequent modern-auth success from the same account shortly after the legacy-auth failures.

---

### QC-05-03 — Distributed spray via rotating source infrastructure

| Field | Value |
|---|---|
| **Pattern ID** | `QC-05-03` |
| **MITRE** | T1110.003 (Password Spraying) |
| **Behavior** | Many distinct accounts, one attempt each, spread across dozens of distinct source IPs sharing one ASN or client fingerprint — evading a single-source-IP threshold entirely. |
| **DEH cross-ref** | DEH Part 12 §2; cf. DEH Part 14 §2 (Network Detection Engineering) for ASN/IP-reputation enrichment mechanics |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L — `N/A`, see below; Elastic (ES\|QL) |

**[HUNTER]** QC-05-01's group-by key is the source IP, which fails outright the moment an attacker rents a residential-proxy or cloud-relay pool and rotates IPs faster than any single one accumulates enough distinct accounts to trip the threshold. The hunt has to move the group-by key off `IPAddress` entirely and onto something the rotation doesn't defeat — ASN, a shared client fingerprint, or a distinctive user-agent string.

**[QUERY]** Sigma correlation grouped by an ASN-enrichment field.

CONCEPTUAL SAMPLE — `SourceASN` assumes an enrichment step (e.g., a MaxMind lookup) has already added this field to the event before Sigma evaluates it; Entra ID does not emit ASN natively.

```yaml
title: Distributed Password Spray Grouped by ASN
correlation:
  type: value_count
  rules:
    - cloud_bad_password_base
  group-by:
    - SourceASN
  timespan: 6h
  condition:
    field: UserPrincipalName
    gte: 25
---
title: Cloud Sign-in Bad Password (ASN-Enriched)
id: cloud_bad_password_base
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    ResultType: '50126'
  condition: selection
```

Plausible expected result: a `SourceASN` with 25 or more distinct UPNs and, when cross-checked, a source-IP count well above 25 — many different IPs, one ASN. Interpretation: consistent with spray infrastructure that rotates IPs specifically to defeat per-IP thresholds; the ASN grouping is what makes the campaign visible at all.

**[QUERY]** Sentinel KQL.

CONCEPTUAL SAMPLE — the `NetworkLocationDetails` path is illustrative; validate against whatever ASN enrichment your pipeline actually applies.

```kql
SigninLogs
| where ResultType == "50126"
| extend ASN = tostring(parse_json(NetworkLocationDetails)[0].asn) // adjust to your enrichment field
| summarize DistinctUsers = dcount(UserPrincipalName), DistinctIPs = dcount(IPAddress)
      by ASN, bin(TimeGenerated, 6h)
| where DistinctUsers >= 25 and DistinctIPs >= 10
```

Plausible expected result: `DistinctIPs` meaningfully exceeding what QC-05-01's single-source query would ever surface for the same campaign. Interpretation: the `DistinctIPs >= 10` guard is there specifically to distinguish this from ordinary corporate NAT egress, where one ASN legitimately carries many users but each IP maps to roughly one account, not many.

**[QUERY]** Splunk SPL.

CONCEPTUAL SAMPLE — assumes a maintained `asn_lookup.csv` lookup table; a stale table silently under-counts.

```spl
index=azure_signinlogs ResultType=50126
| lookup asn_lookup.csv ip AS IPAddress OUTPUT asn AS source_asn
| bin _time span=6h
| stats dc(UserPrincipalName) as distinct_users, dc(IPAddress) as distinct_ips by source_asn, _time
| where distinct_users >= 25 AND distinct_ips >= 10
```

Plausible expected result and interpretation: same as the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL), assuming a Custom Event Property already maps an ASN value onto each event.

CONCEPTUAL SAMPLE — `sourceasn` assumes a Custom Event Property already maps an ASN value onto `sourceip` via a reference-table lookup or DSM extension you build ahead of time; AQL has no native ASN field and no inline enrichment command like SPL's `lookup` or ES\|QL's `ENRICH`.

```sql
SELECT sourceasn,
       UNIQUECOUNT(username) AS distinct_users,
       UNIQUECOUNT(sourceip) AS distinct_ips
FROM events
WHERE resulttype = '50126'
GROUP BY sourceasn
HAVING distinct_users >= 25 AND distinct_ips >= 10
LAST 6 HOURS
```

Plausible expected result and interpretation: same shape as the other surfaces, contingent entirely on whether that Custom Event Property has actually been built in your deployment.

**YARA-L (Google SecOps): N/A — missing schema field.** As of this writing there is no confirmed UDM field carrying an enriched autonomous system number for a principal IP in Google SecOps, the same class of gap DEH Part 28 §1.1 documents for `GrantedAccess`. If your tenant ingests ASN via a custom label or a pre-processing pipeline, substitute the equivalent field and validate a non-empty result before trusting a zero-hit run as clean rather than as a missing mapping.

**[QUERY]** Elastic ES\|QL (threshold/aggregation shape) with an inline enrichment stage.

CONCEPTUAL SAMPLE — assumes an `asn_lookup` enrich policy is already configured; ES\|QL's `ENRICH` command needs that policy built ahead of time, not inline.

```esql
FROM logs-azure.signinlogs*
| WHERE result_type == "50126"
| ENRICH asn_lookup ON source.ip
| STATS distinct_users = COUNT_DISTINCT(user.principal_name),
        distinct_ips = COUNT_DISTINCT(source.ip)
      BY source.as.number, BUCKET(@timestamp, 6h)
| WHERE distinct_users >= 25 AND distinct_ips >= 10
```

Plausible expected result and interpretation: same as the KQL/SPL forms.

> **Hunter's Note**
> Check whether your ASN/GeoIP enrichment feed resolves IPv6 as reliably as IPv4 before trusting a "clean" result. Spray infrastructure increasingly rotates through IPv6 /64 blocks that several commercial ASN feeds still map inconsistently, which quietly reintroduces the exact single-source-per-IP blind spot this pattern exists to close.

**[FALSE POSITIVE]** A shared corporate VPN or SASE egress point, or a CDN/anycast edge fronting a legitimate SSO flow, presents as "many distinct source IPs, one ASN" too — if the whole organization routes outbound traffic through one cloud VPN provider, that provider's ASN legitimately carries high account diversity. Baseline and exclude your organization's own known egress ASNs, and keep the `distinct_ips >= 10` style guard: ordinary egress diversity maps IPs to accounts roughly 1:1, while spray infrastructure maps many IPs to accounts that don't correspond to the device actually sitting behind each one.

**[PIVOT]** Pull the TLS/JA3 fingerprint or user-agent string across the flagged IPs — a shared, unusual client fingerprint spanning otherwise-unrelated source IPs corroborates shared attacker tooling far better than IP/ASN grouping alone.

---

### QC-05-04 — Long-horizon low-and-slow spray beneath standard lookback windows

| Field | Value |
|---|---|
| **Pattern ID** | `QC-05-04` |
| **MITRE** | T1110.003 (Password Spraying) |
| **Behavior** | A source touches many distinct accounts but throttles to at most one failed attempt per account per rolling 24 hours, sustained over weeks — invisible to any 1-hour or 24-hour lookback threshold. |
| **DEH cross-ref** | DEH Appendix A5 §4 (aggregation-ceiling precedent); DEH Part 12 §2 |
| **Languages covered** | Sigma — `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar) — `N/A`, see below; YARA-L — `N/A`, see below; Elastic (ES\|QL) |

**[HUNTER]** Almost every standing correlation rule windows at an hour or a day for cost reasons. An attacker who already knows that — or who is simply throttling to stay under any rate limit — never produces enough volume inside any single window to trip QC-05-01 or QC-05-02 even once. The only way to see the accumulated pattern is a wide-lookback hunt that runs a two-stage aggregation: collapse to one qualifying account-day first, then roll that up across a multi-week window.

**Sigma: N/A — aggregation ceiling.** A single Sigma correlation rule supports one aggregation stage. This pattern needs two — a per-account-per-day dedup, then a distinct-account rollup across many days of those dedup results — which Sigma's `value_count`/`event_count` correlation types cannot express in one rule (per DEH Appendix A5 §4's aggregation-ceiling precedent). A SIEM-side scheduled search would have to pre-materialize the daily rollup as its own indexed result before a second Sigma correlation rule could consume it as input.

**[QUERY]** Sentinel KQL, two chained `summarize` stages against `SigninLogs`.

CONCEPTUAL SAMPLE — thresholds (30 accounts, 10 distinct days) illustrative; validate against your own multi-week baseline before treating them as a cutoff.

```kql
SigninLogs
| where ResultType == "50126"
| summarize DailyFailures = count() by UserPrincipalName, IPAddress, Day = bin(TimeGenerated, 1d)
| where DailyFailures == 1
| summarize DistinctAccounts = dcount(UserPrincipalName), DistinctDays = dcount(Day) by IPAddress
| where DistinctAccounts >= 30 and DistinctDays >= 10
```

Plausible expected result: a small number of source IPs, each associated with 30 or more distinct accounts and at least 10 distinct qualifying days across a 30-day lookback — a shape no 1-hour or 24-hour rule could ever have surfaced. Interpretation: a hit is consistent with a deliberately throttled campaign designed to stay under standard alerting windows; a well-tuned environment run monthly might settle to zero or single-digit qualifying sources.

**[QUERY]** Splunk SPL, same two-stage shape.

CONCEPTUAL SAMPLE — same threshold caveats as the KQL form; SPL's `stats`-into-`stats` chaining supports this two-stage shape natively.

```spl
index=azure_signinlogs ResultType=50126
| bin _time span=1d as day
| stats count as daily_failures by UserPrincipalName, IPAddress, day
| where daily_failures=1
| stats dc(UserPrincipalName) as distinct_accounts, dc(day) as distinct_days by IPAddress
| where distinct_accounts >= 30 AND distinct_days >= 10
```

Plausible expected result and interpretation: unchanged from the KQL form above.

**AQL (QRadar): N/A — aggregation ceiling.** AQL's `SELECT` has no subquery or common-table-expression stage to feed one aggregation's output into a second `GROUP BY`, so the per-account-per-day rollup followed by a 30-day distinct-account count cannot be expressed as one AQL query. Approximate it today with a saved AQL search bookmarked at the per-day layer, exported and re-aggregated outside AQL, or a Reference Set incremented once daily by a Building Block (per DEH Part 27 §2's multi-object model) rather than forcing a single-query translation that would silently under-count.

**YARA-L (Google SecOps): N/A — aggregation ceiling.** YARA-L's `outcome` section aggregates over one matched event window; it has no equivalent to a second pass that re-aggregates the first pass's own output, so the same nested rollup this pattern needs is out of reach in a single rule for the same structural reason as AQL above.

**[QUERY]** Elastic ES\|QL, two chained `STATS` stages.

CONCEPTUAL SAMPLE — thresholds illustrative; ES\|QL's pipe-chained `STATS` stages are what make this two-stage rollup possible in one query, unlike the three surfaces marked `N/A` above.

```esql
FROM logs-azure.signinlogs*
| WHERE result_type == "50126"
| STATS daily_failures = COUNT(*) BY user.principal_name, source.ip, day = BUCKET(@timestamp, 1d)
| WHERE daily_failures == 1
| STATS distinct_accounts = COUNT_DISTINCT(user.principal_name), distinct_days = COUNT_DISTINCT(day) BY source.ip
| WHERE distinct_accounts >= 30 AND distinct_days >= 10
```

Plausible expected result and interpretation: unchanged from the KQL/SPL forms.

> **What Would Change My Mind**
> This pattern assumes a legitimate, sustained one-failure-per-account-per-day cadence sourced from a single IP over multiple weeks is rare enough to threshold on. If a production audit showed a meaningful share of service-principal or integration accounts naturally retry a stale secret on exactly that cadence for weeks after a credential rotation, the fix would have to move from a count threshold to an explicit service-account allowlist, and this pattern's confidence would drop from Medium to Low until that allowlist existed.

**[FALSE POSITIVE]** A service or integration account whose scheduled job retries a stale credential exactly once every 24 hours — a scheduled task, cron job, or third-party integration nobody re-pointed after a credential rotation — produces the identical one-failure-per-account-per-day shape sustained over weeks, sourced from the one fixed IP that job runs from. At the query level this is indistinguishable from a throttled spray: both show low, evenly-spaced failures per account across many days. The discriminator is account type and source stability, not volume — a real spray's flagged cluster spans many different human accounts from a source with no legitimate reason to touch any of them, while the stale-credential case resolves to one or a handful of known service accounts retrying against their own expected target from an already-known, allowlistable source. Cross-check flagged accounts against a service-account inventory before escalating.

**[PIVOT]** Check whether the flagged cadence lines up with a known maintenance or retry schedule — an exact 24-hour interval at the same minute every time is a script's cron, not a spray tool jittering its timing or a human. Confirm every flagged account is a real interactive user, not a service or integration principal that legitimately retries on a fixed schedule.

---

### QC-05-05 — Successful authentication surfacing inside a flagged spray cluster

| Field | Value |
|---|---|
| **Pattern ID** | `QC-05-05` |
| **MITRE** | T1110.003 (Password Spraying) — successful completion; once confirmed valid, the credential's follow-on use falls under T1078 (Valid Accounts) |
| **Behavior** | A source or account already flagged by QC-05-01 through QC-05-04's cluster later produces exactly one successful authentication for a previously-targeted account. |
| **DEH cross-ref** | DEH Part 12 §2; cf. DEH Part 27 §2 (Building Block/Reference Set model) for AQL's standing-detection form |
| **Languages covered** | Sigma — `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (EQL) |

**[HUNTER]** A spray campaign's own success rate is deliberately tiny — attackers accept a single-digit-percent hit rate spread across a huge account list, so the one success that matters is buried inside dozens or hundreds of failures. This pattern joins the account/source list an earlier cluster pattern already flagged against a later success event, rather than waiting on an isolated "successful login" alert that carries no context connecting it to a spray. It differs from Part 6's login-after-a-failure-burst pattern in the join key: that pattern ties a success to a *volume burst against one account*; this one ties a success to *membership in a many-account cluster* already surfaced upstream.

**Sigma: N/A — structurally poor fit.** Expressing "join a success event against a dynamically-produced account list from an upstream `value_count` correlation's own output" requires chaining two correlation instances end to end, which is outside the backend support most Sigma processing pipelines carry for their narrower `temporal_ordered` correlation type. The logic is not impossible in Sigma's spec, just a fight against the language's narrow correlation-chaining support for this specific shape.

**[QUERY]** Sentinel KQL, joining a materialized spray-cluster list against later successes.

CONCEPTUAL SAMPLE — the 6-hour post-cluster success window and the 15-account cluster threshold (inherited from QC-05-01) are both illustrative; validate against your own baseline.

```kql
let SprayClusters = SigninLogs
| where ResultType == "50126"
| summarize DistinctUsers = dcount(UserPrincipalName),
            TargetedAccounts = make_set(UserPrincipalName),
            ClusterStart = min(TimeGenerated), ClusterEnd = max(TimeGenerated)
      by IPAddress, bin(TimeGenerated, 1h)
| where DistinctUsers >= 15
| mv-expand TargetedAccounts to typeof(string);
SigninLogs
| where ResultType == "0"
| join kind=inner SprayClusters on IPAddress, $left.UserPrincipalName == $right.TargetedAccounts
| where TimeGenerated between (ClusterStart .. (ClusterEnd + 6h))
| project TimeGenerated, UserPrincipalName, IPAddress, ClusterStart, ClusterEnd, DistinctUsers
```

Plausible expected result: a small number of rows, each pairing one successful sign-in with the cluster metadata (`ClusterStart`, `DistinctUsers`) that flagged its source. Interpretation: a match here is consistent with a spray campaign that reached a valid credential — treat it as a probable-compromise finding pending the pivot below, not as confirmed account takeover on its own.

**[QUERY]** Splunk SPL, joining a saved spray-cluster search against later successes.

CONCEPTUAL SAMPLE — assumes a saved search named `spray_clusters_qc0501` already materializes QC-05-01/02's cluster output; build that search first.

```spl
| savedsearch spray_clusters_qc0501
| rename IPAddress as spray_ip, TargetedAccounts as spray_user, cluster_end as spray_cluster_end
| join type=inner spray_ip
    [ search index=azure_signinlogs ResultType=0
      | rename IPAddress as spray_ip UserPrincipalName as spray_user ]
| where _time <= spray_cluster_end + 21600
| table _time spray_user spray_ip spray_cluster_end
```

Plausible expected result and interpretation: same as the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL) — the investigative single-query check an analyst runs by hand before building the standing multi-object version. A deployed QRadar detection for this pattern would populate a Reference Set from QC-05-01's spray-cluster rule, then run a second rule testing successful-logon membership against that set (DEH Part 27 §2's Building Block model); AQL alone cannot express both stages as one query.

CONCEPTUAL SAMPLE — username list and source IP are illustrative placeholders you paste in from the upstream cluster query's actual output.

```sql
SELECT logontime, username, sourceip
FROM events
WHERE resulttype = '0'
  AND username IN ('jdoe','asmith','mchen') -- paste the account list QC-05-01 surfaced
  AND sourceip = '203.0.113.44' -- the flagged spray source
LAST 1 DAYS
```

Plausible expected result: zero or one row, since a real campaign's success rate is low by design. Interpretation: unchanged from the KQL/SPL forms — treat any row as a probable-compromise lead.

**[QUERY]** Google SecOps YARA-L, matching a fail-then-success pair per account within a window.

CONCEPTUAL SAMPLE — the `$cluster_size >= 15` condition assumes YARA-L can see enough of the surrounding cluster's failures within the same 6-hour match window to count it; a cluster that formed slightly outside this window won't be caught.

```yaral
rule spray_cluster_success_followup {
  meta:
    description = "Successful auth for an account previously targeted by a flagged spray cluster"
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.principal.ip = $ip
    $fail.target.user.userid = $user
    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.target.user.userid = $user
    $success.metadata.event_timestamp.seconds > $fail.metadata.event_timestamp.seconds
  match:
    $ip, $user over 6h
  outcome:
    $cluster_size = count_distinct($user)
  condition:
    $fail and $success and $cluster_size >= 15
}
```

Plausible expected result and interpretation: same as the other surfaces.

**[QUERY]** Elastic EQL, chosen because this is an ordered, joined multi-event shape rather than a threshold aggregation (per DEH Appendix A5 §8's decision table).

CONCEPTUAL SAMPLE — this sequence alone only proves a fail-then-succeed chain for one account/IP pair; it does not, by itself, verify the source IP is part of a qualifying many-account cluster.

```eql
sequence by source.ip, user.target.name with maxspan=6h
  [authentication where event.outcome == "failure" and event.reason == "invalid_password"]
  [authentication where event.outcome == "success"]
```

Plausible expected result: a sequence match per compromised account/source pair inside the 6-hour window. Interpretation: pair this EQL output with QC-05-01 or QC-05-03's flagged-source list before treating a hit as spray-derived — read alone, this sequence is indistinguishable from a legitimate user mistyping a password once and immediately re-entering it correctly.

> **Blind Spot**
> This pattern can only surface a success once an upstream cluster query has already flagged the source or account list. If the account that gets sprayed successfully is hit on the campaign's very first attempt — before enough failures have accumulated anywhere to trip QC-05-01 through QC-05-04 — there is no cluster yet for this pattern to join against, and the success passes through unflagged until a later, unrelated signal (Part 6, Part 24) catches the account's post-compromise activity instead.

**[FALSE POSITIVE]** A legitimate user who mistypes their own password once, gets a bad-password failure, then correctly re-enters it seconds later produces the exact same fail-then-succeed shape for one account from one IP. The only real discriminator is upstream cluster membership: this pattern should never run against raw sign-in logs directly, only against an account/source list a cluster pattern already qualified. Treat a fail-then-succeed pair with no matching cluster membership as noise, not a hit.

**[PIVOT]** Once a real hit surfaces, immediately check post-authentication activity for that account — a new mail-forwarding rule, an OAuth app-consent grant, or an MFA method registration change are the fastest tells that the successful logon was attacker-driven rather than a coincidental password-typo recovery.

## Cross-references

This part's queries build on DEH Part 12 §2 for sign-in-log authentication mechanics, DEH Part 40 for the naive "five failed logins" teardown this part's design directly answers, and DEH Appendix A5 §4/§8 for the aggregation-ceiling and Elastic-surface-selection reasoning cited throughout. See this book's Part 4 (Brute Force) for the high-per-account-volume counterpart, Part 6 (MFA Abuse & Authentication Anomalies) for push-bombing and login-after-a-failure-burst patterns, Part 15 (Host & Directory Discovery) and Part 3 (Scanning & Enumeration) for the account-list-validation signals that often precede a spray campaign, and Part 24 (Cloud Identity & SaaS Abuse) for what a compromised account surfaced by QC-05-05 typically does next.
