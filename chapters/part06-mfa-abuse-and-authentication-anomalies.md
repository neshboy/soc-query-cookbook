---
title: "MFA Abuse & Authentication Anomalies"
part: 6
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 6 — MFA Abuse & Authentication Anomalies

## Why this part exists

This part covers four behavior shapes named in `BOOK-INDEX.md`'s Part 6 scope row — MFA-fatigue push-bombing, cross-country "impossible travel" sign-ins, new-device/new-country sign-ins against a per-account baseline, and a successful sign-in landing inside a failed-login burst — plus one closely related fifth pattern this part adds inside its five-pattern budget: MFA method re-registration immediately preceding a sign-in from an unfamiliar device. All five share one structural property: no single event justifies a verdict on its own, and each pattern's `[HUNTER]` framing exists specifically because a hunter under time pressure wants the ad hoc version of a correlation before investing in the standing rule.

**Explicit boundary against neighboring parts.** Part 4 (Brute Force) and Part 5 (Password Spraying) own the *failure-volume* shapes this part's QC-06-04 deliberately builds on top of, not re-derives — this part starts where a failure burst ends. Part 7 and Part 17 own credential *theft* and stolen-ticket *reuse*; this part's patterns assume the credential and MFA factor are the account owner's own, abused or bypassed in place, not stolen outright. Part 24 owns OAuth/app-consent-grant abuse and conditional-access *bypass* at the cloud-application layer; QC-06-05 stops at the identity-provider's own MFA-enrollment audit trail and does not re-cover Part 24's consent-grant ground.

**Primary DEH cross-refs:** DEH Part 12 (Identity: Access & Authentication Detection), whose §§4–6 carry DET-12-03 through DET-12-05, the canonical detections QC-06-01, QC-06-02, and QC-06-04 adapt into hunt form; and DEH Part 31 (Baselining), whose cold-start problem (§2) and per-account baseline pattern (DET-31-01) QC-06-03 depends on directly — a new-device/new-country hunt is meaningless without a maintained history to compare against.

---

### QC-06-01 — MFA push-notification fatigue (push bombing)

| Field | Value |
|---|---|
| **Pattern ID** | `QC-06-01` |
| **MITRE** | T1621 (Multi-Factor Authentication Request Generation); T1078 (Valid Accounts) — the attacker already holds a valid password and is trying to clear the second factor |
| **Behavior** | Four or more MFA push/OTP challenges issued to one account inside a short window, commonly ending in an eventual approval. |
| **DEH cross-ref** | DEH Part 12 §5 (DET-12-05 — repeated MFA prompts in a short window) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) |

**[HUNTER]** A standing rule for this shape is easy to write and easy to get wrong on the threshold alone — every IdP paces retries and step-up prompts differently, so the count that's "clearly an attack" in one tenant is routine in another. Run the ad hoc version first, pull the resource the prompts targeted alongside the count, and use that to set a threshold worth graduating into a standing rule rather than guessing one.

**[QUERY]** Sigma, expressed as the series' standard two-part correlation rule: a base rule matching any issued MFA-challenge event, and a correlation rule counting matches per account.

CONCEPTUAL SAMPLE — illustrative Sigma; correlation-rule support for `value_count` varies by backend, see `[FALSE POSITIVE]` below.
```yaml
title: MFA challenge issued
id: 8e2a4f10-6b3d-4c91-9a7e-2d5f8b1c3e60
status: test
description: Matches a single MFA push/OTP challenge issuance event.
logsource:
  category: authentication
  product: azure
detection:
  selection:
    EventType: 'mfa_challenge_issued'
  condition: selection
---
title: Dense MFA challenge volume for one account
id: 1f6c3a92-4d7e-4b18-8a2f-9c6e5d1b7f34
status: test
description: >
  Correlates the MFA-challenge base rule above into a burst pattern: four or
  more challenges for the same account within a 10-minute window.
correlation:
  type: value_count
  rules:
    - 8e2a4f10-6b3d-4c91-9a7e-2d5f8b1c3e60
  group-by:
    - UserPrincipalName
  timespan: 10m
  condition:
    gte: 4
level: medium
tags:
  - attack.credential_access
  - attack.t1621
```
A match is one correlation-rule alert per account crossing the `gte: 4` threshold inside the `timespan`, referencing the four-plus underlying base-rule matches it aggregated. This is consistent with a push-bombing burst against that account; Sigma's `value_count` type has no equivalent to a per-resource breakdown, so the resource-spread differentiator below comes from a companion query, not this rule alone.

**[QUERY]** Microsoft Sentinel/Defender KQL, base selection plus a native `summarize` — no correlation object needed, since this is a single-table threshold.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own tenant's `SigninLogs` schema and push-retry baseline before use.
```kql
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where isnotempty(MfaDetail)
| summarize PromptCount = count(), Resources = make_set(ResourceDisplayName, 5) by UserPrincipalName, bin(TimeGenerated, 10m)
| where PromptCount >= 4
```
A match plausibly shows one account with `PromptCount` between 4 and a dozen inside one 10-minute bin, `Resources` holding a single value if the attacker is hammering one login surface. Four-plus prompts against one resource for one account inside ten minutes is consistent with push-bombing; the same count spread across several distinct `Resources` values more plausibly reflects a step-up conditional-access burst, not an attack.

**[QUERY]** SPL, targeting a generic MFA-event sourcetype normalized into `user`, `resource`, and `result` fields.

CONCEPTUAL SAMPLE — sourcetype and field names illustrative; adjust to your own TA's extraction.
```spl
index=identity sourcetype=mfa_events earliest=-10m
| stats count as prompt_count, values(resource) as resources, values(result) as results by user
| where prompt_count >= 4
```
Expect one row per flagged account with `prompt_count` in the same 4–12 range as the KQL result, `resources` showing whether the prompts concentrated on one app. `results` mixing denials and one eventual approval is the shape most worth escalating over one that shows only denials so far.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL; a simple grouped count over a bounded window fits a single AQL statement without needing a chained rule object.

CONCEPTUAL SAMPLE — QID name and threshold illustrative; confirm your MFA log source's actual QID mapping before trusting a zero-row result as "clean."
```sql
SELECT username, COUNT(*) AS prompt_count
FROM events
WHERE QIDNAME(qid) ILIKE '%MFA challenge%'
GROUP BY username
HAVING COUNT(*) >= 4
LAST 10 MINUTES
```
Expect the same 4-plus count per flagged `username` as the other languages; QRadar's DSM normalization for third-party MFA providers varies, and a denial and a timeout sometimes collapse into one QID, which can undercount the true prompt volume relative to an IdP-native log.

**[QUERY]** Google SecOps YARA-L, matching the MFA-challenge UDM event type per account.

CONCEPTUAL SAMPLE — illustrative YARA-L; UDM event-type and window values not validated against a live tenant.
```yaral
rule qc_06_01_mfa_push_fatigue {
  meta:
    author = "soc-query-cookbook"
    description = "Dense MFA challenge volume for one account"
    mitre_technique_id = "T1621"
    severity = "MEDIUM"

  events:
    $mfa.metadata.event_type = "USER_UNCATEGORIZED"
    $mfa.metadata.product_event_type = "mfa_challenge_issued"
    $mfa.target.user.userid = $user

  match:
    $user over 10m

  condition:
    #mfa >= 4

  outcome:
    $risk_score = 55
    $distinct_resources = count_distinct($mfa.target.resource.name)
}
```
A firing rule carries `#mfa` at 4 or more for one `$user` inside the 10-minute match window, with `$distinct_resources` in the outcome distinguishing a single-target burst from a multi-app morning. This reads the same as the KQL/SPL results above; the UDM `product_event_type` value is parser-dependent, so confirm your specific MFA provider's Chronicle parser actually populates it before relying on the filter.

**[QUERY]** Elastic ES\|QL — chosen over EQL because this pattern is a threshold/aggregation shape, not an ordered sequence.

CONCEPTUAL SAMPLE — index pattern and field names illustrative.
```esql
FROM logs-identity-mfa*
| WHERE event.action == "mfa_challenge_issued"
| STATS prompt_count = COUNT(*), resources = VALUES(target.resource.name) BY user.name, BUCKET(@timestamp, 10 minute)
| WHERE prompt_count >= 4
```
Expect one row per flagged `user.name`/bucket pair with `prompt_count` in the 4-plus range and `resources` either a single value or several, mirroring the KQL interpretation directly above.

**[FALSE POSITIVE]** A flaky mobile connection produces three or four automatic client-side re-prompts when an approval never reaches the server, ending in a same-device approval — indistinguishable from an attack on count alone. A step-up conditional-access policy can also legitimately prompt one user for several distinct challenges (VPN, a sensitive SaaS app, email) inside one login burst. The cheapest differentiator across every language above is the resource/target field: real push-bombing repeats the same target, since the attacker wants into one thing; a legitimate multi-app burst spreads across several. QRadar's coarser QID normalization is the one language-specific wrinkle — it can undercount true prompt volume where other backends distinguish denial from timeout.

**[PIVOT]** Pull who approved the eventual prompt and from which device — a device that never received any of the preceding denied prompts is the strongest available signal of a push-bombing win, not a flaky retry. Check the account's helpdesk/self-service portal for a same-day "I got a bunch of MFA prompts" ticket, which is the single most reliable disambiguator triage actually uses.

> **Hunter's Note**
> Pull the denial/timeout code before you pull anything else. Number-matching push MFA logs a distinct code for "user tapped deny" versus "prompt timed out with no response" on most IdPs, and a long run of *timeouts* rather than *denials* usually means the account owner isn't even looking at their phone right now — which changes how urgently you escalate relative to a run of active denials from someone who is watching the attack happen in real time.

---

### QC-06-02 — Cross-country consecutive sign-ins (impossible-travel proxy)

| Field | Value |
|---|---|
| **Pattern ID** | `QC-06-02` |
| **MITRE** | T1078 (Valid Accounts); T1078.004 (Valid Accounts: Cloud Accounts) where the IdP is cloud-hosted |
| **Behavior** | Two successful authentications for the same account resolving to two different countries, closer together in time than plausible travel allows. |
| **DEH cross-ref** | DEH Part 12 §6 (DET-12-04 — geovelocity-based impossible travel) |
| **Languages covered** | Sigma: **N/A** (structurally poor fit — see below); KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) |

**[HUNTER]** DET-12-04's full geovelocity math (distance ÷ elapsed time against a travel-speed threshold) is worth building once as a standing rule, but a hunter chasing one specific account right now usually wants the cheaper proxy first: did this account's last two successful sign-ins resolve to different countries closer together than any commercial flight allows. That's enough to justify pulling the account's full session history before investing in per-country-pair travel-time tables.

*Sigma — N/A, structurally poor fit: Sigma's correlation types (`event_count`, `value_count`, `temporal`, `temporal_ordered`) count or order matching events; none can assert that two matched events differ in a specific field's value, which is this pattern's actual logic.*

**[QUERY]** Microsoft Sentinel/Defender KQL, walking each account's successful sign-ins in order and comparing each to the immediately preceding one.

CONCEPTUAL SAMPLE — field names and the 120-minute constant illustrative; DET-12-04 documents why a single global cutoff is a starting point, not a validated value.
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| where isnotempty(tostring(LocationDetails.countryOrRegion))
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName),
         PrevCountry = prev(tostring(LocationDetails.countryOrRegion))
| where UserPrincipalName == PrevUser
| extend MinutesBetween = datetime_diff('minute', TimeGenerated, PrevTime)
| where tostring(LocationDetails.countryOrRegion) != PrevCountry and MinutesBetween < 120
```
A match returns one row per account pair of consecutive sign-ins with `MinutesBetween` under 120 and two different resolved countries — plausibly a handful of rows tenant-wide per day at this threshold before any allowlist tuning. This is consistent with either a stolen-credential sign-in from new infrastructure or a resolution artifact (see `[FALSE POSITIVE]`), not confirmed account takeover on its own.

**[QUERY]** SPL, using `streamstats` to carry each account's previous country and timestamp into the current row.

CONCEPTUAL SAMPLE — sourcetype and field names illustrative.
```spl
index=identity sourcetype=signin_logs result=success earliest=-24h
| sort 0 user, _time
| streamstats current=f last(country) as prev_country, last(_time) as prev_time by user
| eval minutes_between=round((_time-prev_time)/60,1)
| where country!=prev_country AND minutes_between<120
```
Expect the same shape as the KQL result: one row per flagged account pair, `minutes_between` under 120, `country` and `prev_country` naming the two resolved locations.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. QRadar's own approach to this pattern is a Reference Set of "each account's last known country," updated by one rule and checked by a second — a multi-object deployment, not one query. The block below is the investigative search that validates the pattern exists before building those standing objects, not the deployed detection itself.

CONCEPTUAL SAMPLE — investigative form only; field names depend on your identity DSM's extraction.
```sql
SELECT username, "Source Country", starttime
FROM events
WHERE QIDNAME(qid) = 'Authentication Success'
  AND username = '<account under review>'
ORDER BY starttime DESC
LAST 24 HOURS
```
This returns the raw ordered country/timestamp history an analyst reads by eye to spot an implausible pair; it does not compute `MinutesBetween` or flag anything itself. The standing version adds Reference Set `RS-LastKnownCountry-By-User` and a second Rule Test comparing the current event's country against it.

**[QUERY]** Google SecOps YARA-L, binding two successive sign-in events to the same user and asserting the country differs.

CONCEPTUAL SAMPLE — illustrative YARA-L; confirm `principal.location.country_or_region` is populated by your specific IdP's UDM parser before relying on it.
```yaral
rule qc_06_02_cross_country_signin {
  meta:
    description = "Two successful sign-ins for one account from different countries inside 2 hours"
    mitre_technique_id = "T1078"

  events:
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "ALLOW"
    $e1.target.user.userid = $user
    $e1.principal.location.country_or_region = $country1

    $e2.metadata.event_type = "USER_LOGIN"
    $e2.security_result.action = "ALLOW"
    $e2.target.user.userid = $user
    $e2.principal.location.country_or_region = $country2

    $e2.metadata.event_timestamp.seconds > $e1.metadata.event_timestamp.seconds
    $country1 != $country2

  match:
    $user over 2h

  condition:
    $e1 and $e2
}
```
A match binds one pair of events for one `$user` with two different resolved countries inside the 2-hour match window — the same underlying claim as the KQL/SPL results, expressed as YARA-L's native multi-event correlation rather than a windowed self-comparison.

**[QUERY]** Elastic ES\|QL — chosen over EQL because comparing a computed field (country) between two rows sharing a key is an aggregation-shaped problem EQL's `sequence` cannot express; ES\|QL's `STATS` can.

CONCEPTUAL SAMPLE — index pattern illustrative.
```esql
FROM logs-identity-signin*
| WHERE event.outcome == "success" AND @timestamp > NOW() - 2 hours
| STATS countries = VALUES(source.geo.country_iso_code), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY user.name
| WHERE MV_COUNT(countries) > 1
```
Expect one row per account whose sign-ins inside the 2-hour lookback resolved to more than one country; `first_seen`/`last_seen` give the elapsed time an analyst checks against travel plausibility by hand, since this simplified query does not compute per-pair distance.

**[FALSE POSITIVE]** Corporate VPN concentrators and mobile carrier NAT gateways routinely resolve to a country far from the user's physical location, and a user roaming between a home connection and a corporate VPN mid-session produces this exact pattern with zero real travel involved — the single largest driver of alerts on this pattern in most tenants. Maintain a reviewed allowlist of known corporate egress ASNs/ranges and exclude them before flagging, rather than widening the time threshold, which just makes the query blind to a shorter real impossible-travel window too.

**[PIVOT]** Check whether the device fingerprint or browser/OS signature is identical across both sign-ins — the same device resolving to two countries points at network-path change (VPN, roaming), not physical travel; a different device in each country is the stronger takeover signal. Cross-reference the second country against the account's known corporate-VPN egress ranges before escalating.

---

### QC-06-03 — New-device or new-country sign-in against an established baseline

| Field | Value |
|---|---|
| **Pattern ID** | `QC-06-03` |
| **MITRE** | T1078 (Valid Accounts); T1078.004 (Valid Accounts: Cloud Accounts) where applicable |
| **Behavior** | A successful authentication from a device fingerprint or country never previously observed for this specific account. |
| **DEH cross-ref** | DEH Part 31 §3 (DET-31-01 — per-account baseline pattern and its cold-start problem, §2); DEH Part 12 §6 (conceptual framing) |
| **Languages covered** | Sigma: **N/A** (structurally poor fit — see below); KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) |

**[HUNTER]** Unlike QC-06-02, this pattern needs no velocity math at all — the entire question is "has this exact device or country ever appeared for this account before," which only means anything against a maintained per-account history. Reach for this hunt when a device or country looks unusual on its face but doesn't fail the DET-12-04-style velocity check, because it's simply the account's *first ever* use of that device or country rather than a physically impossible jump from the last one.

*Sigma — N/A, structurally poor fit: the base Sigma spec has no construct for a maintained per-entity historical watchlist or lookup list; every correlation type (DEH Part 24 §4) evaluates matches within a bounded timespan, not against an entity's entire prior history.*

**[QUERY]** Microsoft Sentinel/Defender KQL, anti-joining current sign-ins against a maintained watchlist of each account's known devices/countries.

CONCEPTUAL SAMPLE — assumes a `KnownDevicesByUser` Sentinel Watchlist exists and is kept current; see `[FALSE POSITIVE]`.
```kql
let KnownDevices = _GetWatchlist('KnownDevicesByUser');
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| extend DeviceId = tostring(DeviceDetail.deviceId)
| join kind=leftanti KnownDevices on UserPrincipalName, DeviceId
```
A match is one row per account/device pair with no matching entry in `KnownDevicesByUser` — a plausibly small number tenant-wide per hour once the watchlist has enough history behind it. This is consistent with a genuinely new device for the account, which is either legitimate (new laptop, phone upgrade) or the first sign of a takeover; the query cannot tell those apart on its own.

**[QUERY]** SPL, using a maintained lookup table in place of a watchlist.

CONCEPTUAL SAMPLE — assumes `known_devices_by_user.csv` is rebuilt on a schedule from prior sign-in history.
```spl
index=identity sourcetype=signin_logs result=success earliest=-1h
| lookup known_devices_by_user.csv user, device_id OUTPUT known
| where isnull(known)
```
Expect the same shape as the KQL result: rows for account/device pairs absent from the lookup, freshest first.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. The standing version of this pattern is exactly QRadar's Reference Set model: one rule populates `RS-KnownDevices-By-User` from historical sign-ins, a second checks new sign-ins against it and fires the Offense — a multi-object deployment, not one query. The block below pulls the raw per-account device history an analyst reviews before building those objects.

CONCEPTUAL SAMPLE — investigative form only.
```sql
SELECT username, "Device Id", MIN(starttime) AS first_seen, COUNT(*) AS times_seen
FROM events
WHERE QIDNAME(qid) = 'Authentication Success'
  AND username = '<account under review>'
GROUP BY username, "Device Id"
ORDER BY first_seen ASC
LAST 90 DAYS
```
This surfaces every distinct device the account has ever authenticated from and when it first appeared — a device with `times_seen` of 1 and a `first_seen` inside the last hour is the manual equivalent of the KQL/SPL anti-join result above.

**[QUERY]** Google SecOps YARA-L, checking the current sign-in's device against a maintained Chronicle reference list.

CONCEPTUAL SAMPLE — assumes a `%known_devices_by_user%` reference list is populated and kept current from prior sign-in history.
```yaral
rule qc_06_03_new_device_signin {
  meta:
    description = "Successful sign-in from a device not on the account's known-device list"
    mitre_technique_id = "T1078"

  events:
    $login.metadata.event_type = "USER_LOGIN"
    $login.security_result.action = "ALLOW"
    $login.target.user.userid = $user
    $login.principal.asset.hardware.serial_number = $device_id
    not $device_id in %known_devices_by_user%

  condition:
    $login
}
```
A match fires once per qualifying sign-in whose `device_id` isn't present in the maintained reference list — the same underlying claim as the anti-join forms above, with the freshness of `%known_devices_by_user%` as the load-bearing dependency.

**[QUERY]** Elastic ES\|QL, using `ENRICH` against a known-devices lookup index in place of a join.

CONCEPTUAL SAMPLE — assumes a `known_devices` enrich policy exists, keyed on user and device fingerprint.
```esql
FROM logs-identity-signin*
| WHERE event.outcome == "success" AND @timestamp > NOW() - 1 hour
| ENRICH known_devices_policy ON user.name WITH known_device
| WHERE known_device != true
```
Expect rows for sign-ins whose device fingerprint has no match in the enrichment policy — again, the same underlying result as the other four languages above.

**[FALSE POSITIVE]** Cold start is the dominant driver: a new hire, a freshly provisioned account, or any account whose baseline table simply hasn't accumulated enough history yet will show every device and country as "new" by definition, not because anything is wrong (DEH Part 31 §2). A routine browser or OS update can also change the device-fingerprint hash some IdPs compute, producing a false "new device" for a device that's actually unchanged.

**[PIVOT]** Check the account's creation date and the watchlist/lookup/reference-list's own coverage window for that account before treating a hit as meaningful — an account younger than the baseline's own history window is a cold-start hit, not a deviation. Where the account is mature, check for a recent hardware-refresh or travel-notice ticket that would explain a legitimate new device or country.

> **Blind Spot**
> None of the five query forms above can distinguish a genuinely new account from a four-year-old account being hit on its first-ever sign-in from a country it simply never happened to use before. Both produce an identical "no matching history" result. Routing every hit through the same triage queue with no account-age context attached means a real four-year-old account's first Tokyo sign-in gets the same priority as a two-day-old test account's routine setup traffic — check account age before triage priority, not after.

---

### QC-06-04 — Successful sign-in immediately following a failed-login burst

| Field | Value |
|---|---|
| **Pattern ID** | `QC-06-04` |
| **MITRE** | T1110 (Brute Force); T1078 (Valid Accounts) |
| **Behavior** | Five or more failed authentications against one account, followed by a success for that same account within roughly fifteen minutes. |
| **DEH cross-ref** | DEH Part 12 §4 (DET-12-03 — successful sign-in following a failure burst) |
| **Languages covered** | Sigma: **N/A** (structurally poor fit — see below); KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (EQL) |

**[HUNTER]** A failure burst that ends in nothing is a nuisance; one that ends in a success is the moment a brute-force or spray hunt actually earns its keep. Reach for this pattern when Part 4's or Part 5's own failure-volume queries already flagged an account or source, and the next question is whether any of those attempts actually landed.

*Sigma — N/A, structurally poor fit: this pattern needs a count threshold on one selection (five-plus failures) combined with `temporal_ordered` sequencing relative to a second selection (the later success); that specific combination has narrow, inconsistent backend support (DEH Appendix A5 §8) even where `event_count` alone is well supported.*

**[QUERY]** Microsoft Sentinel/Defender KQL, joining a per-account failure-burst aggregation against later successes for the same account.

CONCEPTUAL SAMPLE — thresholds illustrative; validate `FailureThreshold` and `FollowWindow` against your own baseline before trusting them as a cutoff.
```kql
let FailureThreshold = 5;
let FollowWindow = 15m;
let Failures =
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType in ("50126", "50053")
    | summarize FailedCount = count(), LastFailure = max(TimeGenerated) by UserPrincipalName
    | where FailedCount >= FailureThreshold;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| join kind=inner Failures on UserPrincipalName
| where TimeGenerated between (LastFailure .. LastFailure + FollowWindow)
| project UserPrincipalName, LastFailure, SuccessTime = TimeGenerated, IPAddress
```
A match returns one row per account whose success landed inside the 15-minute tail of its own 5-plus failure burst, with `IPAddress` on the success row either matching or differing from the failing attempts' source. Same-source is consistent with the attacker simply guessing correctly on a later attempt; a different source is closer to the false-positive shape below.

**[QUERY]** SPL, using `streamstats` to carry the running failure count and last-failure time per account into the row that eventually succeeds.

CONCEPTUAL SAMPLE — thresholds illustrative.
```spl
index=identity sourcetype=signin_logs earliest=-1h
| sort 0 user, _time
| streamstats count(eval(result="failure")) as failed_count by user
| eval last_failure_time=if(result="failure", _time, null())
| streamstats last(last_failure_time) as last_failure by user
| where result="success" AND failed_count>=5 AND (_time - last_failure)<=900
```
Expect the same shape: one row per account whose success arrived within 900 seconds of accumulating five or more failures.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. QRadar's own version of this pattern is a chained Building Block (failure-count threshold) feeding a Rule Test that checks for a following success — a multi-object deployment. The block below is the investigative pull that validates the pattern before building those objects.

CONCEPTUAL SAMPLE — investigative form only.
```sql
SELECT username, starttime, "Result"
FROM events
WHERE QIDNAME(qid) IN ('Authentication Failure', 'Authentication Success')
  AND username = '<account under review>'
ORDER BY starttime ASC
LAST 1 HOURS
```
This returns the raw ordered failure/success timeline for one account for manual review — the same underlying evidence the KQL/SPL joins compute automatically, without the threshold or window logic applied.

**[QUERY]** Google SecOps YARA-L — a natural fit, since binding a count-threshold event set and a following single event to the same principal is exactly the multi-event correlation YARA-L's `match`/`condition` sections are built for.

CONCEPTUAL SAMPLE — illustrative YARA-L; window and threshold not validated against a live tenant.
```yaral
rule qc_06_04_success_after_failure_burst {
  meta:
    description = "Successful sign-in landing inside the tail of a failed-login burst"
    mitre_technique_id = "T1110"

  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.target.user.userid = $user

    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.target.user.userid = $user
    $success.metadata.event_timestamp.seconds > $fail.metadata.event_timestamp.seconds

  match:
    $user over 15m

  condition:
    #fail >= 5 and $success

  outcome:
    $risk_score = 70
}
```
A match binds five or more `$fail` events and one later `$success` event to the same `$user` inside the 15-minute match window — the same claim as the KQL/SPL results, expressed natively rather than through a self-join.

**[QUERY]** Elastic EQL — the natural surface for an ordered, entity-joined sequence; expressed here as five explicit failure stages rather than a true dynamic count, since EQL `sequence` matches a fixed number of stages, not "N or more" of one stage.

CONCEPTUAL SAMPLE — illustrative EQL; five fixed failure stages matching the five-attempt threshold, see the note below.
```eql
sequence by user.name with maxspan=15m
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "success"]
```
A match is a six-event sequence for one `user.name`: five failures followed by a success, all inside 15 minutes. Because every failure stage shares the same filter, the sequence engine satisfies each stage with the earliest unconsumed failure event, so a burst of six or more failures before the success still matches — it simply leaves the extra failures unconsumed by this sequence. This lines up with the 5-failure threshold used in the other languages for "5 or more," not just "exactly 5"; treat it as a close analog rather than a guaranteed equivalent, since EQL's sequence stages are still fixed positions, not a native count operator.

**[FALSE POSITIVE]** A legitimate user who mistypes their password two or three times before getting it right, from their own normal device and location, satisfies every query above just as well as an attacker does. The distinguishing signal across every language shown above is whether the success shares a source/device with the failures (consistent with a retry) or doesn't (closer to an attacker who found a working credential mid-burst) — this pattern is meant to feed a composite score alongside device/location context, not stand alone as a verdict.

**[PIVOT]** Compare the success event's source IP and device fingerprint against the failing attempts' — a match favors an innocent retry, a mismatch favors compromise. Check whether MFA was required and satisfied on the success leg; an MFA-protected account clearing this pattern with a valid second factor is a materially different claim than one with MFA disabled entirely.

> **Detection Autopsy — "any failure-then-success is a compromise"**
>
> **The rule:** Fires on any account with one or more failed sign-ins followed by a success, no device or source comparison, no minimum failure count.
>
> **Why it shipped:** It sounds airtight in a design review — "they failed, then they got in" — and needs no baseline or watchlist to build, unlike QC-06-03.
>
> **How it failed:** Every employee who fat-fingers a password once before succeeding trips it. A rule with no minimum failure count and no same-source check pages on ordinary typos dozens of times a day per active user population, and gets tuned into an ignored queue within a week.
>
> **The fix:** Require a minimum failure count (5, tuned per environment) and treat same-source-as-failures versus different-source-from-failures as separate confidence tiers, exactly as this pattern's `[PIVOT]` does — not a single undifferentiated alert.

---

### QC-06-05 — MFA method re-registration immediately preceding a sign-in from an unfamiliar device

| Field | Value |
|---|---|
| **Pattern ID** | `QC-06-05` |
| **MITRE** | T1556.006 (Modify Authentication Process: Multi-Factor Authentication); T1098.005 (Account Manipulation: Device Registration) |
| **Behavior** | A self-service MFA method change or new-device enrollment for an account, followed shortly by a successful sign-in from a device or country absent from that account's prior history. |
| **DEH cross-ref** | DEH Part 18 (Cloud Identity & SaaS Detection Engineering) — no dedicated DEH detection for this composite shape; extends DEH Part 12 §5's MFA-abuse framing to the enrollment step itself and composes with this part's own `QC-06-03` |
| **Languages covered** | Sigma (partial — front-half event only, see below), KQL (Sentinel/Defender), SPL, AQL, YARA-L: **N/A** (missing schema field), Elastic (EQL) |

**[HUNTER]** An attacker who already holds a password but not the second factor increasingly skips push-bombing entirely and instead uses the account's own self-service portal to register a *new* MFA method — a new phone number, a new authenticator enrollment — then signs in cleanly through the factor they just added themselves. Hunt for the re-enrollment event itself first; by the time the sign-in happens, the attacker already has everything they need.

**[QUERY]** Sigma, covering only the front half of the pattern — the re-enrollment event alone, as a single-event base rule. The full two-stage join to a following sign-in needs `temporal_ordered` correlation, which has the same narrow, inconsistent backend support named for `QC-06-04`; this rule is deliberately scoped to what Sigma expresses cleanly, leaving the join to the languages below.

CONCEPTUAL SAMPLE — illustrative Sigma; covers the enrollment event only, not the composite pattern.
```yaml
title: MFA method registered or changed for an account
id: 4c8e1b7a-2f9d-4a63-9e1c-7b3d5f2a8c14
status: test
description: Matches a self-service MFA method registration or change event.
logsource:
  category: authentication
  product: azure
  service: AuditLogs
detection:
  selection:
    OperationName:
      - 'Update user'
      - 'Register security info'
  condition: selection
level: low
tags:
  - attack.persistence
  - attack.t1556.006
```
A match is one audit-log event per re-enrollment action, with no claim yet about what sign-in follows it — this rule alone is a leading indicator worth logging, not alerting on standalone, given how routine legitimate re-enrollment is.

**[QUERY]** Microsoft Sentinel/Defender KQL, joining the enrollment audit event to a following sign-in that also fails `QC-06-03`'s known-device check.

CONCEPTUAL SAMPLE — assumes the same `KnownDevicesByUser` watchlist used in `QC-06-03`.
```kql
let KnownDevices = _GetWatchlist('KnownDevicesByUser');
let Enrollments =
    AuditLogs
    | where TimeGenerated > ago(1h)
    | where OperationName in ("Update user", "Register security info")
    | project UserPrincipalName = tostring(TargetResources[0].userPrincipalName), EnrollTime = TimeGenerated;
SigninLogs
| where TimeGenerated > ago(1h) and ResultType == "0"
| extend DeviceId = tostring(DeviceDetail.deviceId)
| join kind=inner Enrollments on UserPrincipalName
| where TimeGenerated between (EnrollTime .. EnrollTime + 30m)
| join kind=leftanti KnownDevices on UserPrincipalName, DeviceId
```
A match is one account whose MFA enrollment was followed, within 30 minutes, by a successful sign-in from a device absent from its known-device history — a materially stronger claim than either signal alone.

**[QUERY]** SPL, joining an identity-audit sourcetype to the authentication sourcetype across the same account and window.

CONCEPTUAL SAMPLE — sourcetype and field names illustrative.
```spl
index=identity_audit sourcetype=mfa_enrollment earliest=-1h
| rename _time as enroll_time
| join user [ search index=identity sourcetype=signin_logs result=success earliest=-1h
             | rename _time as signin_time ]
| where (signin_time - enroll_time) <= 1800 AND signin_time > enroll_time
```
Expect one row per account with an enrollment followed by a success inside 1,800 seconds — the same shape as the KQL result, minus the known-device cross-check unless separately joined against a lookup as in `QC-06-03`.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. This pattern spans two distinct log-source event categories (identity audit, authentication), which QRadar deploys as a Building Block on the enrollment category feeding a Reference Set consulted by a second Rule Test on the authentication category — a multi-object model. The block below pulls both categories side by side for manual review.

CONCEPTUAL SAMPLE — investigative form only.
```sql
SELECT username, starttime, QIDNAME(qid) AS event_type
FROM events
WHERE QIDNAME(qid) IN ('MFA Method Changed', 'Authentication Success')
  AND username = '<account under review>'
ORDER BY starttime ASC
LAST 1 HOURS
```
This surfaces the raw ordered timeline of enrollment and sign-in events for one account, the manual equivalent of the KQL/SPL join above.

*YARA-L — N/A, missing schema field: no UDM event type or field this book can confirm as a stable equivalent for "MFA method registration," distinct from a generic user-resource-update event, across Chronicle's parser set (DEH Part 28 §1.1's `GrantedAccess` precedent for the same class of gap). Coverage depends entirely on which parser normalized the source IdP's audit log, so a rule built against one tenant's parser output may match nothing against another's.*

**[QUERY]** Elastic EQL, expressing the two-stage order directly as a `sequence`.

CONCEPTUAL SAMPLE — illustrative EQL; event categories and field names not validated against a live deployment.
```eql
sequence by user.name with maxspan=30m
  [iam where event.action == "mfa-method-changed"]
  [authentication where event.outcome == "success"]
```
A match is a two-event sequence for one `user.name`: an MFA-method change followed by a successful sign-in, both inside 30 minutes — the same claim as the KQL/SPL/AQL results, native to EQL's ordering model.

**[FALSE POSITIVE]** Legitimate MFA re-enrollment after a lost or replaced phone is extremely common, and a genuine user re-enrolling and then signing in from their new device produces this exact sequence with zero attacker involvement. The differentiator is whether the re-enrollment is helpdesk-assisted and ticket-backed or purely self-service with no supporting record — an unassisted self-service change followed immediately by a sign-in from a never-before-seen device and country together is a materially stronger claim than either alone.

**[PIVOT]** Check the ITSM/helpdesk system for a device-loss or replacement ticket for this account around the enrollment time. Check whether the *previous* MFA method was disabled or removed as part of the same change — an attacker taking over an account frequently removes the legitimate method to lock the real owner out, which a benign upgrade rarely does.

> **What Would Change My Mind**
> This pattern's confidence rests on self-service re-enrollment with no supporting ticket being rare enough to be worth flagging on its own. If a review of confirmed-benign hits showed a large share of an organization's users routinely re-enroll MFA methods without ever opening a helpdesk ticket — common in orgs with a mature self-service identity portal — this pattern's confidence would need to drop from a standalone lead to a component of the composite scoring described in DEH Part 12 §7, the same demotion DET-12-03 and DET-12-04 already accept for their own signals.

---

## Cross-references

DEH Part 12 §§4–7 (Identity: Access & Authentication Detection — DET-12-03, DET-12-04, DET-12-05, and the composite account-takeover scoring `QC-06-01`–`QC-06-04` extend into hunt form); DEH Part 31 §§2–3 (Baselining — cold start, DET-31-01) for `QC-06-03`'s dependency on a maintained per-account history; DEH Part 18 (Cloud Identity & SaaS Detection Engineering) for `QC-06-05`'s enrollment-audit telemetry; DEH Appendix A5 §§4–8 for the Sigma correlation-type, EQL sequence, and AQL multi-object-model limitations named throughout. Within this book: Part 4 (Brute Force) and Part 5 (Password Spraying) for the failure-volume precursor to `QC-06-04`; Part 7 and Part 17 for credential-theft and stolen-ticket-reuse patterns this part does not cover; Part 24 (Cloud Identity & SaaS Abuse) for OAuth consent-grant abuse and conditional-access bypass adjacent to but out of scope for `QC-06-05`.
