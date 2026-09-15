---
title: "Brute Force"
part: 4
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 4 — Brute Force

## Why this part exists

**[CONCEPT]** Brute force, as this part uses the term, is repeated authentication attempts against **one account**, using different guessed or leaked credentials, from one source or a small rotating set of sources, until a guess lands or the attacker gives up. It maps to T1110 (Brute Force) as the parent technique and T1110.001 (Password Guessing) for the general case covered here. This is the single-account, high-volume shape — the inverse of Part 5's password spraying (few attempts per account, many accounts), a different signal from Part 6's MFA fatigue and impossible-travel patterns (which can fire on a single successful sign-in with no failure burst at all), and distinct from Part 7's Kerberos ticket-theft patterns (credential theft via protocol abuse, not password guessing).

This part scopes to four authentication surfaces DEH Part 12 (Identity: Access & Authentication Detection) does not natively own: RDP, SSH, VPN, and web-application login endpoints. DEH Part 12 §2 already builds the canonical single-account brute-force analytic (DET-12-02) against cloud identity-provider sign-in logs; this part carries that shape onto the endpoint- and perimeter-facing surfaces a hunter covers once the question moves off the IdP. A fifth pattern closes the part: the moment a guess actually lands, chased across whichever surface produced the burst.

Query-language syntax fundamentals for every language below — join semantics, aggregation windows, what a Sigma correlation rule can express — are DEH Parts 23–29's job, cited where relevant, not re-taught here. Coverage tracking against DEH's six-tier scale is DEH Parts 41–43's methodology, applied to this book's catalog in Part 28.

## 1. Endpoint and remote-access authentication surfaces

### QC-04-01 — High-volume failed RDP authentication against a single account

| Field | Value |
|---|---|
| **Pattern ID** | `QC-04-01` |
| **MITRE** | T1110.001 (Password Guessing) |
| **Behavior** | Repeated Event ID 4625 failures against one target account on an RDP-facing host, from one or a small set of sources, inside a short window. |
| **DEH cross-ref** | DEH Part 8 §3 (Logon events and logon types: 4624, 4625, 4648); DEH Part 12 §2 (DET-12-02, the single-account brute-force analytic shape, moved here from cloud sign-in logs to on-prem Windows RDP telemetry); DEH Part 40 §3 (the "five failed logins equals brute force" autopsy — read there, not repeated here) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) |

**[HUNTER]** A standing correlation rule for RDP brute force lags behind whatever result-code list and bin size it shipped with; this hunt runs against the raw Event ID 4625 (An account failed to log on) stream directly and catches the gap while that rule's threshold is stale. Reach for it right after a host becomes newly reachable — a firewall change, a lift-and-shift, a jump-box misconfiguration — since that is when RDP brute force shows up first, before any standing rule watches the new exposure. Group by target account, not source IP: DEH Part 40 §3 dissects why a fixed-threshold, source-grouped rule misses a patient single-account guesser, and this hunt narrows to result codes that actually mean "wrong credential" rather than any non-zero code.

**[QUERY]** **Sigma.** Pairs a base detection for one failed RDP logon with a Sigma correlation rule (`type: event_count`) that aggregates matches per target account over a rolling window — Sigma cannot express the aggregation in one rule alone.

CONCEPTUAL SAMPLE — field names, result code, and threshold illustrative; validate `SubStatus` codes and the correlation backend's support for `event_count` before use

```yaml
title: Failed RDP logon attempt (base event)
id: 4b6e2f2a-04a1-4a52-9c1e-9a1b2c3d4e5f
status: experimental
logsource:
  category: authentication
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType:
      - 10
      - 3
    SubStatus: '0xC000006A'          # wrong password — see DEH Part 8 §3 for the full Status/SubStatus table
  condition: selection
---
title: Single-account RDP brute force (correlation)
id: 7c1d3e4f-15b2-4c63-8d2f-0b2c3d4e5f6a
status: experimental
correlation:
  type: event_count
  rules:
    - 4b6e2f2a-04a1-4a52-9c1e-9a1b2c3d4e5f
  group-by:
    - TargetUserName
  timespan: 30m
  condition:
    gte: 10
```

**Expected result:** A hit names one `TargetUserName` value tied to 10 or more `0xC000006A` failures inside a 30-minute window, usually with one or two distinct `IpAddress` values repeated across the underlying base-rule matches. **Interpretation:** Consistent with an automated guesser working one account; a match here says nothing about whether any guess succeeded — see QC-04-05 for that check.

**[QUERY]** **KQL (Sentinel/Defender).** Targets Microsoft Sentinel's `SecurityEvent` table, populated from a domain-joined host or RD Gateway via the Log Analytics agent or Azure Monitor Agent.

CONCEPTUAL SAMPLE — field names, threshold, and window illustrative; validate against your own `SecurityEvent` schema and connector version

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4625
| where LogonType in (10, 3)
| where SubStatus == "0xC000006A"          // wrong password
| summarize
    FailedAttempts = count(),
    DistinctSourceIPs = dcount(IpAddress),
    SourceIPs = make_set(IpAddress, 10)
    by TargetUserName, bin(TimeGenerated, 30m)
| where FailedAttempts >= 10
```

**Expected result:** Rows name a `TargetUserName`, a `FailedAttempts` count in the tens, and typically one or two entries in `SourceIPs`; a wide `DistinctSourceIPs` value against an otherwise tight `FailedAttempts` count is itself worth a second look. **Interpretation:** A tight source set plausibly indicates one attacker's tooling; a wide one plausibly indicates a botnet or proxy pool working the same account.

**[QUERY]** **SPL.** Targets Splunk ingesting Windows Security events via the Splunk Add-on for Microsoft Windows.

CONCEPTUAL SAMPLE — field names and threshold illustrative; validate field extractions against your own add-on version

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
    (Logon_Type=10 OR Logon_Type=3) Sub_Status="0xC000006A"
| bin _time span=30m
| stats count as failed_attempts,
        dc(Source_Network_Address) as distinct_source_ips,
        values(Source_Network_Address) as source_ips
    by Target_User_Name, _time
| where failed_attempts >= 10
```

**Expected result:** Rows resemble the KQL result above, keyed on `Target_User_Name` with `failed_attempts` in the tens. **Interpretation:** Same reading as the KQL block — see the Blind Spot box below on the clock-aligned window.

**[QUERY]** **AQL (QRadar).** The following is QRadar AQL (Ariel Query Language, not standard SQL), against the Events source over the last 30 minutes.

CONCEPTUAL SAMPLE — field names and log source type illustrative; validate against your own DSM field mapping

```sql
SELECT
  "Target Username" AS targetUser,
  "Source IP" AS sourceIP,
  COUNT(*) AS failedAttempts
FROM events
WHERE LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Security Event Log'
  AND EVENTID = '4625'
  AND "Sub Status" = '0xC000006A'
GROUP BY targetUser, sourceIP
ORDER BY failedAttempts DESC
LAST 30 MINUTES
```

Most deployed AQL versions have no reliable post-aggregation `HAVING`-style filter, so this sorts descending instead — an analyst eyeballs the top of the list, and a confirmed threshold graduates into a Building Block once validated (DEH Part 27 §2–3). **Expected result:** The top rows name a `targetUser` with `failedAttempts` well above the rest of the list. **Interpretation:** Same reading as above; eyeballing is the tradeoff for AQL's missing aggregate filter.

**[QUERY]** **YARA-L.** Targets Google SecOps (Chronicle) UDM-normalized Windows Security events.

CONCEPTUAL SAMPLE — UDM field mapping illustrative; confirm your Windows parser populates these fields before relying on this rule

```yaral
rule single_account_rdp_brute_force {
  meta:
    description = "Repeated failed RDP logons against one account"
    mitre_technique_id = "T1110.001"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.metadata.product_event_type = "4625"
    $e.target.user.userid = $user
    $e.security_result.action = "BLOCK"

  match:
    $user over 30m

  outcome:
    $failed_attempts = count($e.metadata.id)
    $distinct_sources = count_distinct($e.principal.ip)

  condition:
    $failed_attempts >= 10
}
```

**Expected result:** A match names `$user` with `$failed_attempts` at or above 10 within the 30-minute match window. **Interpretation:** Same reading as the KQL/SPL blocks above.

**[QUERY]** **Elastic (ES\|QL).** A threshold/wide-lookback aggregation, not an ordered sequence, so ES\|QL rather than EQL or Elastic KQL, per DEH Appendix A5 §8's decision table. Targets a Windows-integration data stream in Elastic Security.

CONCEPTUAL SAMPLE — data stream name and field mapping illustrative; validate against your own Elastic integration version

```esql
FROM logs-windows.security-*
| WHERE @timestamp > NOW() - 30 minutes
  AND event.code == "4625" AND winlog.event_data.LogonType IN ("10", "3")
  AND winlog.event_data.SubStatus == "0xC000006A"
| STATS failed_attempts = COUNT(*), distinct_src = COUNT_DISTINCT(source.ip) BY user.target.name
| WHERE failed_attempts >= 10
| SORT failed_attempts DESC
```

**Expected result:** Same shape as the KQL/SPL/AQL results above, sorted descending. **Interpretation:** Same reading; ES|QL's ability to `WHERE` after `STATS` is what lets this stay one query instead of two.

> **Blind Spot**
> If these RDP connections traverse an RD Gateway, load balancer, or NAT/jump box, `IpAddress` reflects that intermediary, not the true client. Grouping by source IP undercounts distinct attacker infrastructure behind the same gateway — this pattern's account-first grouping sidesteps that, but cross-check gateway-side connection logs if source attribution matters.

**[FALSE POSITIVE]** RDP clients that cache a credential and retry automatically after a password change — Windows' own Credential Manager does this — produce a tight burst indistinguishable from a scripted guesser. RD Gateway or load-balancer health probes performing dummy logons, and shared jump-host or backup-agent accounts hitting a stale password after rotation, are the other two recurring drivers. Do not raise the count threshold to fix this — that raises the bar for a real attacker too; instead correlate against the directory's own password-change timestamp and suppress only where retries stop the moment a real success appears.

**[PIVOT]** Check for an immediate success on the same account (QC-04-05). Check whether the RDP listener is reachable from where the failures originated at all — an internet-facing 3389 that shouldn't be is the bigger finding regardless of this pattern's own result. Check Event ID 4688 process creation from any session this account opens in the following minutes, and see this book's Part 16 (Lateral Movement via Admin Tools & Remote Services) for what a successful RDP logon typically leads to next.

### QC-04-02 — High-volume failed SSH authentication against a single account

| Field | Value |
|---|---|
| **Pattern ID** | `QC-04-02` |
| **MITRE** | T1110.001 (Password Guessing) |
| **Behavior** | Repeated failed SSH authentication attempts against one target account on a Linux/Unix host, grouped by account rather than by source, inside a short window. |
| **DEH cross-ref** | DEH Part 3 §7.4 (DET-03-01, the source-IP-grouped SSH burst detection this pattern complements by grouping on the target account instead); DEH Part 14 §6 (SSH abuse: protocol scanning, downgrade probes, and brute force — the network-layer counterpart); DEH Part 12 §2 (DET-12-02, general single-account brute-force shape) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) |

**[HUNTER]** DEH Part 3 §7.4's DET-03-01 groups by source IP to catch a distributed or username-cycling scan, which leaves a complementary gap: one attacker repeatedly guessing a single high-value account — `root`, a shared service account — from a stable source, a shape a source-grouped rule tolerates until the source itself crosses its own threshold. Run this hunt the moment a specific account is suspected of being targeted, for example after it surfaces in a leaked-credential feed, rather than waiting for a source-IP anomaly to trip first.

**[QUERY]** **Sigma.** A base rule for one failed `sshd` password event, paired with an `event_count` correlation grouped on the target user.

CONCEPTUAL SAMPLE — logsource product/service illustrative; confirm your pipeline's Sigma taxonomy mapping for `sshd`

```yaml
title: Failed SSH password attempt (base event)
id: 9a2b3c4d-5e6f-4708-8192-a3b4c5d6e7f8
logsource:
  category: authentication
  product: linux
  service: sshd
detection:
  selection:
    event.outcome: failure
  condition: selection
---
title: Single-account SSH brute force (correlation)
id: 1f2e3d4c-6b7a-4980-9c1d-e2f3a4b5c6d7
correlation:
  type: event_count
  rules:
    - 9a2b3c4d-5e6f-4708-8192-a3b4c5d6e7f8
  group-by:
    - user.name
  timespan: 20m
  condition:
    gte: 15
```

**Expected result:** A hit names one target account with 15 or more failures inside a 20-minute window. **Interpretation:** Consistent with sustained guessing against that specific account; says nothing about the guesser's source diversity, unlike DET-03-01.

**[QUERY]** **KQL (Sentinel/Defender).** Targets Sentinel's `Syslog` table, populated from an on-prem Linux host via the Azure Monitor Agent syslog connector.

CONCEPTUAL SAMPLE — `parse` pattern illustrative; validate against your own syslog message format, which varies by distribution

```kql
Syslog
| where TimeGenerated > ago(20m)
| where ProcessName == "sshd" and SyslogMessage has "Failed password"
| parse SyslogMessage with * "Failed password for " TargetUser " from " SourceIP " port" *
| summarize FailedAttempts = count(), DistinctSourceIPs = dcount(SourceIP) by TargetUser, bin(TimeGenerated, 20m)
| where FailedAttempts >= 15
```

**Expected result:** Rows name a `TargetUser` with `FailedAttempts` at or above 15. **Interpretation:** Same reading as the Sigma result.

**[QUERY]** **SPL.** Adapted directly from DEH Part 3 §7.4's DET-03-01 by regrouping on `target_user` instead of `src_ip`, to catch one account targeted from a stable source rather than one source cycling through many accounts.

CONCEPTUAL SAMPLE — illustrative SPL; field names assume a normalized `sshd` source, per DEH Part 3 §7.4's own caveat

```spl
index=linux_auth sourcetype=sshd "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<target_user>\S+) from (?<src_ip>\S+) port (?<src_port>\d+)"
| eval conn_key = src_ip . ":" . src_port
| stats dc(conn_key) as distinct_connections, count as raw_failed_lines, dc(src_ip) as distinct_source_ips by target_user
| where distinct_connections >= 15
| sort - distinct_connections
```

**Expected result:** Rows name a `target_user` with `distinct_connections` at or above 15. **Interpretation:** Counting distinct connections rather than raw log lines avoids the `MaxAuthTries`-inflation failure mode DEH Part 3 §7.3's autopsy dissects for the source-grouped version of this same mistake.

**[QUERY]** **AQL (QRadar).** QRadar AQL, not standard SQL, against the Events source over the last 20 minutes.

CONCEPTUAL SAMPLE — log source type match illustrative; validate against your own SSH DSM's normalized field names

```sql
SELECT
  "Username" AS targetUser,
  "Source IP" AS sourceIP,
  COUNT(*) AS failedAttempts
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%SSH%'
  AND QIDNAME(qid) = 'Failed SSH Login'
GROUP BY targetUser, sourceIP
ORDER BY failedAttempts DESC
LAST 20 MINUTES
```

**Expected result:** Same shape as the other languages' results, sorted descending on `failedAttempts`. **Interpretation:** Same reading.

**[QUERY]** **YARA-L.** Targets Google SecOps UDM-normalized SSH authentication events.

CONCEPTUAL SAMPLE — `network.application_protocol` value illustrative; confirm your SSH parser's actual UDM mapping

```yaral
rule single_account_ssh_brute_force {
  meta:
    description = "Repeated failed SSH logons against one account"
    mitre_technique_id = "T1110.001"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.network.application_protocol = "SSH"
    $e.security_result.action = "BLOCK"
    $e.target.user.userid = $user

  match:
    $user over 20m

  outcome:
    $failed_attempts = count($e.metadata.id)
    $distinct_sources = count_distinct($e.principal.ip)

  condition:
    $failed_attempts >= 15
}
```

**Expected result:** A match names `$user` with `$failed_attempts` at or above 15. **Interpretation:** Same reading as above.

**[QUERY]** **Elastic (ES\|QL).** A threshold aggregation, so ES|QL per the same decision rule as QC-04-01. Targets a system-auth data stream in Elastic Security.

CONCEPTUAL SAMPLE — data stream name illustrative; validate against your own Filebeat/Elastic Agent integration

```esql
FROM logs-system.auth-*
| WHERE @timestamp > NOW() - 20 minutes
  AND process.name == "sshd" AND event.outcome == "failure"
| STATS failed_attempts = COUNT(*), distinct_src = COUNT_DISTINCT(source.ip) BY user.name
| WHERE failed_attempts >= 15
| SORT failed_attempts DESC
```

**Expected result:** Same shape as above. **Interpretation:** Same reading.

> **Hunter's Note**
> Pull the target-account field from the parsed `Failed password` line itself, not a generic "username" field some SIEM layers populate from `btmp`/`wtmp` instead — `invalid user <name>` attempts against a nonexistent account often land in a different field or get dropped depending on the parser, silently undercounting the dictionary-guessing behavior this pattern exists to catch.

**[FALSE POSITIVE]** Automated deployment or configuration-management tooling — Ansible, cron-driven scripts — retrying a stale key or password across a whole fleet from one controller host is the most common driver, and can produce a higher per-account count than a real attacker on a large fleet. `sshd`'s `MaxAuthTries` (default six in most distributions) also permits several prompts inside one TCP connection, which is why this pattern counts distinct connections rather than raw log lines, per DEH Part 3 §7.3's autopsy of that exact mistake. An internal vulnerability scanner performing authenticated credential checks is the third recurring source; allowlist its range rather than raising the threshold.

**[PIVOT]** Check auditd's `USER_LOGIN`/`CRED_ACQ` records (DEH Part 3 §6) for the same account and window — they carry the `auid` linkage `sshd`'s own log and `btmp` don't. Check for an immediate success (QC-04-05). Check `authorized_keys` or `/etc/shadow` modification timestamps right after any success, and see this book's Part 15 (Host & Directory Discovery) for what a landed guess typically does next on a Linux host.

### QC-04-03 — High-volume failed VPN authentication against a single account

| Field | Value |
|---|---|
| **Pattern ID** | `QC-04-03` |
| **MITRE** | T1110.001 (Password Guessing) |
| **Behavior** | Repeated failed authentication attempts against one account at a VPN concentrator or SSL-VPN gateway, from one or a small set of client sources, inside a short window. |
| **DEH cross-ref** | DEH Part 14 (Network Detection Engineering — general network-perimeter telemetry mechanics; no single DEH section owns VPN-gateway authentication logs specifically, stated here rather than forcing a citation); DEH Part 12 §2 (DET-12-02 analytic shape) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) |

**[HUNTER]** VPN-gateway authentication logs rarely get the same standing-detection attention as Windows or cloud sign-in logs, partly because every vendor's log format differs and partly because the gateway sits at the edge of what most SOC tooling normalizes first. Run this hunt whenever remote-access exposure just changed — a new gateway, a new SSO integration, a widened connect-from-outside policy — since that is when a brute-force attempt against a specific account is most likely to succeed and least likely to already have a tuned rule watching for it.

**[QUERY]** **Sigma.** VPN vendor logsource taxonomy varies (`cisco`/`asa`, `paloaltonetworks`/`globalprotect`, `fortinet`/`fortigate`); the following uses a vendor-neutral placeholder — swap in your backend's actual pySigma pipeline mapping.

CONCEPTUAL SAMPLE — vendor-neutral placeholder fields; map to your actual VPN vendor's Sigma pipeline before use

```yaml
title: Failed VPN authentication attempt (base event, vendor-neutral)
id: 2b3c4d5e-7f80-4a91-b2c3-d4e5f6a7b8c9
logsource:
  category: authentication
  product: vpn
detection:
  selection:
    event.outcome: failure
  condition: selection
---
title: Single-account VPN brute force (correlation)
id: 3c4d5e6f-8091-4ba2-c3d4-e5f6a7b8c9d0
correlation:
  type: event_count
  rules:
    - 2b3c4d5e-7f80-4a91-b2c3-d4e5f6a7b8c9
  group-by:
    - user.name
  timespan: 20m
  condition:
    gte: 8
```

**Expected result:** A hit names one account with eight or more failures inside a 20-minute window. **Interpretation:** Consistent with an attacker or a misbehaving client repeatedly failing authentication against that account; distinguishing the two is the [FALSE POSITIVE] entry below.

**[QUERY]** **KQL (Sentinel/Defender).** Targets Sentinel's `CommonSecurityLog` table, the standard landing table for CEF-normalized Cisco ASA, Palo Alto GlobalProtect, and Fortinet syslog.

CONCEPTUAL SAMPLE — `Activity` string match illustrative; validate against your specific vendor's CEF field mapping

```kql
CommonSecurityLog
| where TimeGenerated > ago(20m)
| where DeviceVendor in ("Cisco", "Palo Alto Networks", "Fortinet")
    and Activity has_any ("authentication failed", "Auth Fail")
| summarize FailedAttempts = count(), DistinctSourceIPs = dcount(SourceIP) by DestinationUserName, bin(TimeGenerated, 20m)
| where FailedAttempts >= 8
```

**Expected result:** Rows name a `DestinationUserName` with `FailedAttempts` at or above eight. **Interpretation:** Same reading as the Sigma result.

**[QUERY]** **SPL.** Spans three common VPN sourcetypes generically; narrow to whichever your environment actually ingests.

CONCEPTUAL SAMPLE — sourcetype list and message match illustrative; validate against your own vendor's field extraction

```spl
index=vpn (sourcetype=cisco:asa OR sourcetype=pan:globalprotect OR sourcetype=fortigate)
    (Message="authentication failed" OR Message="Auth Fail")
| stats count as failed_attempts, dc(src_ip) as distinct_source_ips by user
| where failed_attempts >= 8
```

**Expected result:** Rows name a `user` with `failed_attempts` at or above eight. **Interpretation:** Same reading as above.

**[QUERY]** **AQL (QRadar).** QRadar AQL, not standard SQL, against the Events source over the last 20 minutes.

CONCEPTUAL SAMPLE — log source type match illustrative; validate against your own VPN DSM's normalized field and event names

```sql
SELECT
  "Username" AS targetUser,
  "Source IP" AS sourceIP,
  COUNT(*) AS failedAttempts
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%VPN%'
  AND "Event Name" ILIKE '%auth%fail%'
GROUP BY targetUser, sourceIP
ORDER BY failedAttempts DESC
LAST 20 MINUTES
```

**Expected result:** Same shape as above, sorted descending. **Interpretation:** Same reading.

**[QUERY]** **YARA-L.** Targets Google SecOps UDM-normalized VPN authentication events.

CONCEPTUAL SAMPLE — `network.application_protocol` value illustrative; confirm the actual UDM protocol value your VPN parser emits

```yaral
rule single_account_vpn_brute_force {
  meta:
    description = "Repeated failed VPN logons against one account"
    mitre_technique_id = "T1110.001"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.network.application_protocol = "SSL"
    $e.security_result.action = "BLOCK"
    $e.target.user.userid = $user

  match:
    $user over 20m

  outcome:
    $failed_attempts = count($e.metadata.id)

  condition:
    $failed_attempts >= 8
}
```

**Expected result:** A match names `$user` with `$failed_attempts` at or above eight. **Interpretation:** Same reading as above.

**[QUERY]** **Elastic (ES\|QL).** A threshold aggregation, so ES|QL per the same decision rule used above. Targets a network-traffic VPN data stream.

CONCEPTUAL SAMPLE — data stream name illustrative; validate against your own VPN integration's field mapping

```esql
FROM logs-network_traffic.vpn-*
| WHERE @timestamp > NOW() - 20 minutes AND event.outcome == "failure"
| STATS failed_attempts = COUNT(*), distinct_src = COUNT_DISTINCT(source.ip) BY user.name
| WHERE failed_attempts >= 8
```

**Expected result:** Same shape as above. **Interpretation:** Same reading.

> **Engineering Reality**
> There is no shared field schema across VPN vendors. Cisco ASA, Palo Alto GlobalProtect, and Fortinet each log authentication failure with a different message string and a different field for the target account. Every query above is a starting shape, not a portable one — expect to rewrite the match condition and field names for your specific gateway before this pattern returns anything.

**[FALSE POSITIVE]** A traveling employee's VPN client on a phone and a laptop both retrying a just-changed password produces a tight, single-account burst indistinguishable from a guesser. A flapping SSO or RADIUS backend can trigger the same auto-retry shape with no attacker involved, and a branch-office appliance retrying an expired certificate-bound account is the third recurring driver. Correlate against the account's own recent password-change or certificate-renewal event before escalating.

**[PIVOT]** Check conditional-access or MFA prompt logs for the same account in the same window — see this book's Part 6 (MFA Abuse & Authentication Anomalies). Check whether the account's VPN policy permits connection from the observed geography or device posture at all. Check for an immediate success (QC-04-05).

## 2. Application-layer and cross-surface patterns

### QC-04-04 — High-volume failed web-application login against a single account

| Field | Value |
|---|---|
| **Pattern ID** | `QC-04-04` |
| **MITRE** | T1110.001 (Password Guessing) |
| **Behavior** | Repeated failed login attempts against one account at a web-application login endpoint, from one or a small set of sources, inside a short window — the single-account shape DEH Part 16 §9 explicitly hands off. |
| **DEH cross-ref** | DEH Part 16 §9 (Credential stuffing at the web layer — the explicit request-layer hand-off point to this shape); DEH Part 12 §2 (DET-12-02 analytic shape) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) |

**[HUNTER]** DEH Part 16 §9 draws its own scope boundary explicitly: it owns "many distinct username values, each tried a small number of times," and hands off "the bursty, single-account pattern of a targeted password guess" once the question becomes whether one specific account got hit. This pattern is that hand-off, written against a web login endpoint rather than a cloud IdP sign-in log, since DEH Part 12 already covers the latter.

**[QUERY]** **Sigma.** A base rule for one failed login POST against a generic `/login` endpoint, paired with an `event_count` correlation on the account field.

CONCEPTUAL SAMPLE — endpoint path and response code illustrative; every application's login endpoint and failure signal differ

```yaml
title: Failed web application login attempt (base event)
id: 4d5e6f70-91a2-4bc3-d4e5-f6a7b8c9d0e1
logsource:
  category: application
  product: web
detection:
  selection:
    url.path: '/login'
    http.response.status_code: 401
  condition: selection
---
title: Single-account web login brute force (correlation)
id: 5e6f7081-a2b3-4cd4-e5f6-a7b8c9d0e1f2
correlation:
  type: event_count
  rules:
    - 4d5e6f70-91a2-4bc3-d4e5-f6a7b8c9d0e1
  group-by:
    - user.name
  timespan: 15m
  condition:
    gte: 12
```

**Expected result:** A hit names one account with 12 or more failed `/login` responses inside a 15-minute window. **Interpretation:** Consistent with a targeted guess against that specific account, distinct from DEH Part 16 §9's distributed-stuffing shape.

**[QUERY]** **KQL (Sentinel/Defender).** Web-application login telemetry has no standard Sentinel table the way Windows or Entra sign-ins do; the following assumes a custom log table fed by the application's own login-failure events.

CONCEPTUAL SAMPLE — custom table and column names illustrative; substitute your own ingestion pipeline's schema

```kql
MyWebApp_CL
| where TimeGenerated > ago(15m)
| where RequestPath_s == "/login" and ResponseStatusCode_d == 401
| summarize FailedAttempts = count(), DistinctSourceIPs = dcount(ClientIP_s) by Username_s, bin(TimeGenerated, 15m)
| where FailedAttempts >= 12
```

**Expected result:** Rows name a `Username_s` with `FailedAttempts` at or above 12. **Interpretation:** Same reading as the Sigma result.

**[QUERY]** **SPL.** Targets a generic web-access index for the application in question.

CONCEPTUAL SAMPLE — index/sourcetype and path match illustrative; substitute your own application's access-log format

```spl
index=web sourcetype=myapp:access "/login" status=401
| stats count as failed_attempts, dc(client_ip) as distinct_source_ips by username
| where failed_attempts >= 12
```

**Expected result:** Rows name a `username` with `failed_attempts` at or above 12. **Interpretation:** Same reading as above.

**[QUERY]** **AQL (QRadar).** QRadar AQL, not standard SQL, against the Events source over the last 15 minutes.

CONCEPTUAL SAMPLE — URL and status-code fields illustrative; validate against however your web-log source populates custom properties

```sql
SELECT
  "Username" AS targetUser,
  "Source IP" AS sourceIP,
  COUNT(*) AS failedAttempts
FROM events
WHERE "URL" ILIKE '%/login%'
  AND "HTTP Status Code" = '401'
GROUP BY targetUser, sourceIP
ORDER BY failedAttempts DESC
LAST 15 MINUTES
```

**Expected result:** Same shape as above, sorted descending. **Interpretation:** Same reading.

**[QUERY]** **YARA-L.** Targets Google SecOps UDM-normalized web-application login events.

CONCEPTUAL SAMPLE — target field illustrative; confirm your web-app parser populates `target.url` rather than a resource-name field instead

```yaral
rule single_account_web_login_brute_force {
  meta:
    description = "Repeated failed web application login attempts against one account"
    mitre_technique_id = "T1110.001"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.target.url = "/login"
    $e.security_result.action = "BLOCK"
    $e.target.user.userid = $user

  match:
    $user over 15m

  outcome:
    $failed_attempts = count($e.metadata.id)

  condition:
    $failed_attempts >= 12
}
```

**Expected result:** A match names `$user` with `$failed_attempts` at or above 12. **Interpretation:** Same reading as above.

**[QUERY]** **Elastic (ES\|QL).** A threshold aggregation, so ES|QL per the same decision rule used throughout this part.

CONCEPTUAL SAMPLE — data stream and field names illustrative; substitute your own application's ingested schema

```esql
FROM logs-myapp.access-*
| WHERE @timestamp > NOW() - 15 minutes
  AND url.path == "/login" AND http.response.status_code == 401
| STATS failed_attempts = COUNT(*), distinct_src = COUNT_DISTINCT(source.ip) BY user.name
| WHERE failed_attempts >= 12
```

**Expected result:** Same shape as above. **Interpretation:** Same reading.

> **Blind Spot**
> A CDN or bot-mitigation layer in front of the login endpoint can absorb or block attempts before they reach the application's own logs, and may rewrite or drop the true client IP. A query against application logs alone undercounts real volume whenever that layer is doing its job — cross-check the CDN/WAF's own logs before concluding a low count means low attacker effort.

**[FALSE POSITIVE]** A password-manager extension retrying a stale credential, a mobile app's token-refresh loop, and a confused legitimate user retrying a forgotten password before using "forgot password" are the three recurring drivers — unlike DEH Part 16 §9's NAT-driven false positive, all three involve one real account, so a large-NAT allowlist doesn't help here. Pair the count threshold with a check of how the account's next successful authentication happens: a login via password reset is expected and benign; a login via the ordinary form is what QC-04-05 exists to catch.

**[PIVOT]** Check the account's activity immediately after any success for sensitive actions — payment-method change, email-address change, bulk data export. Check WAF or bot-mitigation logs for the same source across other endpoints, not just this one. Check whether MFA is enabled for the account; if not, a landed guess is immediately exploitable with no further hurdle.

### QC-04-05 — Successful authentication immediately following a single-account failure burst

| Field | Value |
|---|---|
| **Pattern ID** | `QC-04-05` |
| **MITRE** | T1110.001 (Password Guessing) |
| **Behavior** | A successful authentication event on an account that accumulated a failure burst on the same account in the preceding window, on any one of the RDP, SSH, VPN, or web-application login surfaces above — the highest-signal single moment this part covers. |
| **DEH cross-ref** | DEH Part 12 §4 (DET-12-03, the same failure-then-success shape at the cloud IdP layer); DEH Part 12 §7 (account-takeover composite scoring this signal feeds); DEH Part 7 (Time — clock-skew fundamentals, see Blind Spot below) |
| **Languages covered** | Sigma: `N/A` (see below); KQL (Sentinel/Defender), SPL, AQL (QRadar — investigative search only, see below), YARA-L, Elastic (EQL) |

**[CONCEPT]** Every pattern above answers "is someone guessing against this account." This one answers the question that actually matters operationally: did a guess land. DEH Part 12 §4's DET-12-03 already builds this shape for cloud identity-provider sign-in logs; this pattern applies the same ordered failure-then-success logic to the telemetry QC-04-01 through QC-04-04 cover, where no IdP sign-in log exists to catch it.

**[HUNTER]** Run this hunt with a tighter failure threshold than any pattern above — a success after even three or four failures on one account, from one source, is worth escalating regardless of whether it crossed QC-04-01 through QC-04-04's own thresholds. Reach for it once a brute-force hunt above already produced a hit and the next question is whether it mattered.

**[QUERY]** **KQL (Sentinel/Defender).** Correlates an RDP failure burst against a subsequent success for the same account; the same `let`/`join` structure applies to SSH, VPN, or web tables by substituting the event source.

CONCEPTUAL SAMPLE — threshold, window, and join illustrative; validate against your own `SecurityEvent` schema

```kql
let FailureBursts = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625 and LogonType in (10, 3)
| summarize FailedAttempts = count(), BurstEnd = max(TimeGenerated) by TargetUserName
| where FailedAttempts >= 5;
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624 and LogonType in (10, 3)
| join kind=inner FailureBursts on TargetUserName
| where TimeGenerated between (BurstEnd .. BurstEnd + 10m)
| project TimeGenerated, TargetUserName, IpAddress, FailedAttempts, BurstEnd
```

**Expected result:** A row names a `TargetUserName` with a `FailedAttempts` count of five or more, followed within 10 minutes by a successful 4624 for the same account. **Interpretation:** Plausible evidence a guess landed — not proof, since a legitimate password reset produces the identical shape; see [FALSE POSITIVE] below.

**[QUERY]** **SPL.** Uses Splunk's `transaction` command to bound a failure-then-success sequence by account within a fixed span — cheaper to write than KQL's explicit `join` above for this ordered shape.

CONCEPTUAL SAMPLE — `maxspan` and `eventcount` threshold illustrative; validate against your own event volume per account

```spl
index=wineventlog EventCode IN (4624, 4625) (Logon_Type=10 OR Logon_Type=3)
| transaction Target_User_Name startswith=(EventCode=4625) endswith=(EventCode=4624) maxspan=10m
| where eventcount >= 6
```

**Expected result:** A transaction with `eventcount` of six or more (five-plus failures and one closing success) for a given `Target_User_Name`. **Interpretation:** Same reading as the KQL result.

**[QUERY]** **AQL (QRadar).** The following is QRadar AQL (Ariel Query Language, not standard SQL). QRadar cannot express an ordered failure-then-success sequence as one query; a standing version needs a Building Block, a Reference Set holding accounts currently "in burst," and a Rule firing on a success while the account is in that set (DEH Part 27 §2–3). Below is the two-step investigative search an analyst runs by hand to validate the shape first, not a deployable query.

CONCEPTUAL SAMPLE — two-step investigative search; not a standing correlation

```sql
-- Step 1: find accounts with a recent failure burst
SELECT
  "Target Username" AS targetUser,
  COUNT(*) AS failedAttempts,
  MAX(devicetime) AS burstEnd
FROM events
WHERE EVENTID = '4625'
GROUP BY targetUser
ORDER BY failedAttempts DESC
LAST 1 HOURS
```

```sql
-- Step 2: for each account with failedAttempts >= 5 from Step 1, check for a success after burstEnd
SELECT
  "Target Username" AS targetUser,
  sourceip,
  devicetime
FROM events
WHERE EVENTID = '4624'
  AND targetUser IN ('<accounts carried forward from Step 1>')
LAST 1 HOURS
```

**Expected result:** Step 1 sorts candidate accounts by failure count; Step 2, run against the accounts an analyst carries forward, returns any success events for them. **Interpretation:** A success in Step 2 landing after the `burstEnd` timestamp from Step 1 is the same signal as the KQL/SPL results above, produced by hand instead of by one query.

**[QUERY]** **YARA-L.** Approximates the sequence using a timestamp comparison between two event variables within one `match` window.

CONCEPTUAL SAMPLE — ordering is approximated, not enforced; see the caveat below

```yaral
rule single_account_failure_burst_then_success {
  meta:
    description = "Successful logon immediately following a failed-logon burst on the same account"
    mitre_technique_id = "T1110.001"

  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.target.user.userid = $user

    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.target.user.userid = $user
    $success.metadata.event_timestamp.seconds > $fail.metadata.event_timestamp.seconds

  match:
    $user over 1h

  outcome:
    $failed_attempts = count($fail.metadata.id)

  condition:
    $failed_attempts >= 5 and #success > 0
}
```

YARA-L's `match` groups events sharing `$user` within the window but does not enforce strict sequence ordering the way EQL's `sequence` stage does below; the timestamp comparison approximates "success after burst" rather than guaranteeing it. **Expected result:** A match names `$user` with `$failed_attempts` at or above five and at least one qualifying success. **Interpretation:** Treat a hit as a strong candidate, not a proven sequence, until confirmed against raw timestamps.

**[QUERY]** **Elastic (EQL).** This is the one pattern in this part where an ordered, joined multi-event shape is the actual point, so it uses EQL's `sequence` stage directly rather than ES|QL, per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — `runs` count and `maxspan` illustrative; validate backend support for the `runs` keyword on your Elastic version

```eql
sequence by user.target.name with maxspan=1h
  [authentication where event.outcome == "failure"] with runs=5
  [authentication where event.outcome == "success"]
```

**Expected result:** A match names a `user.target.name` value with five failure events immediately followed, within one hour, by one success event, all sharing the join key. **Interpretation:** The strongest-typed version of this pattern's result among the languages shown — EQL's `sequence` enforces the ordering YARA-L only approximates.

Sigma's `correlation` spec has a `type: temporal_ordered` variant that could in principle express "N failures then a success," but per this book's honesty standard (§4.4, "structurally poor fit, not impossible") it is currently supported by only a small subset of Sigma backends and converters, and a rule written against it can silently fail to translate on most SIEM pySigma pipelines rather than erroring loudly. This pattern's sequence logic is shown instead in KQL, SPL, EQL, and YARA-L above, where ordered multi-event support is native to the backend rather than an edge feature of the rule format.

> **Blind Spot**
> This sequence compares timestamps that may come from two different logging pipelines — an endpoint agent's clock and a network device's clock on a different NTP sync schedule. A few seconds of skew can reorder a success that actually landed after the burst so it appears to precede it, silently breaking every ordered query above. See DEH Part 7 for time-normalization fundamentals, and validate NTP sync across every source this pattern spans before trusting a boundary-case ordering result.

**[FALSE POSITIVE]** The single most important driver, given this pattern's severity, is a legitimate password reset: several failures on the old credential, a reset event, then a real success on the new one — the same field shape a landed guess produces. Do not suppress every hit with a reset in between: an attacker who resets the account's own password after gaining access some other way produces that exact shape too. Instead, confirm the reset request came from an already-authenticated, expected session before downgrading a hit.

**[PIVOT]** This is the highest-value pivot in the whole part: check every other telemetry source for the same account or session in the minutes right after the success — new MFA method registration, mailbox rule creation, a new SSH key, privilege escalation, outbound data movement. This is exactly the composite scoring DEH Part 12 §7 builds toward; feed this hit into that model rather than treating it as a standalone verdict.

**[SOC MANAGEMENT]** A confirmed hit here — a real burst immediately followed by a real success, no matching reset event in between — is one of this book's few patterns that should page out immediately rather than wait for the next hunt cadence, the same zero-tolerance framing DEH Part 12 §7 gives an unexplained account-takeover signal. Tune the upstream burst threshold in QC-04-01 through QC-04-04 to control hunt volume; do not tune this final check into a lower-severity queue.

## Cross-references

- DEH Part 12 (Identity: Access & Authentication Detection) §2 (DET-12-02), §4 (DET-12-03), §7 (account-takeover composite scoring)
- DEH Part 3 (Telemetry Engineering I: Host & Identity Sources) §6–§7.4 (Linux host telemetry and DET-03-01)
- DEH Part 8 (Windows Detection Engineering) §3 (4624/4625/4648 logon events and logon types)
- DEH Part 14 (Network Detection Engineering) §6 (SSH abuse at the network layer)
- DEH Part 16 (Web Detection Engineering) §9 (Credential stuffing at the web layer)
- DEH Part 40 (Detection Autopsy) §3 ("five failed logins equals brute force")
- DEH Part 7 (Time) for clock-skew and ordering fundamentals
- DEH Parts 23–29 (query-language syntax and translation-loss fundamentals) and DEH Parts 41–43 (Detection Coverage, Quality, and Debt methodology, applied to this book's own catalog in Part 28)
- This book's Part 5 (Password Spraying), Part 6 (MFA Abuse & Authentication Anomalies), and Part 16 (Lateral Movement via Admin Tools & Remote Services)
