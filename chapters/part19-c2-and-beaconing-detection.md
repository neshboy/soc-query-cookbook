---
title: "C2 & Beaconing Detection"
part: 19
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 19 — C2 & Beaconing Detection

## Why this part exists

**[CONCEPT]** A compromised host that has an implant on it eventually has to talk to something outside the network it's sitting in — check in for tasking, pull a second stage, or push out whatever it collected. That outbound conversation is beaconing: a network signature that exists regardless of which C2 framework generated it, because the implant author still has to pick a check-in cadence, a protocol to hide inside, and a destination to talk to. DEH Part 14 §2 already develops the core insight this whole part builds on — the tell isn't the protocol or the payload, it's the *regularity*, scored as the coefficient of variation of inter-connection intervals — and this part does not re-derive that insight, only cites it and extends it into the query-pattern shapes a hunter needs across six languages.

This part covers six patterns, at the top of this book's 4–6 budget (per `BOOK-INDEX.md`), because C2/beaconing spans several structurally different query shapes rather than one behavior repeated with minor variation: tight fixed-interval timing, long-period timing a short lookback window misses entirely, destination rarity as a corroborating signal, endpoint-side process correlation, TLS client-fingerprint pivoting, and the SNI/CDN-metadata shape domain fronting produces. One explicit boundary: Part 18 (Suspicious DNS) owns DNS-tunnelling and domain-name rarity/entropy scoring exclusively — this part's rare-destination pattern (`QC-19-03`) stays at the IP/ASN/connection-tuple level, the same domain-vs-IP split DEH Part 14 §3 draws for its own equivalent section.

This part does not teach Sigma, KQL, SPL, AQL, YARA-L, or Elastic syntax fundamentals — see DEH Parts 24–29 and DEH Appendix A5 for language semantics and the cross-language translation-loss framework every query below assumes. It does not score these patterns' Detection Coverage, Quality, or Debt tier — see DEH Parts 41–43 for that methodology and this book's own Part 28 for how it applies to the cookbook's catalog. Every query in every pattern below defaults to `CONCEPTUAL SAMPLE` per STYLE-GUIDE.md §12: none of it is guaranteed to run unmodified against a real product, and every threshold shown is illustrative until validated against your own baseline.

## Patterns in this part

### QC-19-01 — Fixed-interval beacon detection via inter-connection time-delta clustering

| Field | Value |
|---|---|
| **Pattern ID** | `QC-19-01` |
| **MITRE** | T1071.001 (Application Layer Protocol: Web Protocols); cf. T1573 (Encrypted Channel) where the same cadence rides a TLS-wrapped session |
| **Behavior** | A single (source, destination) pair produces many connections whose inter-arrival times cluster tightly around one value — a low coefficient of variation — inside a bounded lookback window. |
| **DEH cross-ref** | DEH Part 14 §2, §2.1 (Beaconing and command-and-control traffic patterns — the coefficient-of-variation worked detection this pattern adapts, including its own stated 30-second-to-3,600-second scope boundary) |
| **Languages covered** | KQL (Sentinel/Defender), SPL — Sigma, AQL, YARA-L, and Elastic: `N/A`, see below |

**[HUNTER]** DEH Part 14 §2.1 already hands you a worked SPL detection for this shape and is explicit that its own thresholds — more than 20 connections, coefficient of variation under 0.15, average interval between 30 seconds and one hour — are illustrative and untested against production beacon traffic. The case for hunting this by hand: re-run the same logic with a wider lookback to catch a pair that hasn't yet crossed the connection-count floor, and periodically sweep with a looser coefficient-of-variation ceiling to see what a lightly jittered implant looks like in your own traffic before trusting where that line is drawn.

**[QUERY]** Sentinel/Defender KQL against a firewall or proxy session-log table normalized into `CommonSecurityLog` or an equivalent custom table with one row per connection.

```kql
// CONCEPTUAL SAMPLE — field names, bucket width, and thresholds illustrative;
// validate against your own connection-log schema and baseline before use.
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where isnotempty(DestinationIP) and DestinationIP !startswith "10." and DestinationIP !startswith "192.168."
| sort by SourceIP, DestinationIP, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1), PrevSourceIP = prev(SourceIP, 1), PrevDestinationIP = prev(DestinationIP, 1)
// prev() walks the whole sorted result set, not just the current group — this guard drops the
// one row per (SourceIP, DestinationIP) pair where PrevTime actually belongs to the prior pair.
| where SourceIP == PrevSourceIP and DestinationIP == PrevDestinationIP
| extend DeltaSeconds = datetime_diff('second', TimeGenerated, PrevTime)
| where DeltaSeconds > 0
| summarize Connections = count(), AvgInterval = avg(DeltaSeconds), StdevInterval = stdev(DeltaSeconds)
    by SourceIP, DestinationIP
| extend CoefficientOfVariation = StdevInterval / AvgInterval
| where Connections > 20 and CoefficientOfVariation < 0.15 and AvgInterval between (30 .. 3600)
```

**Plausible expected result:** on most fleets this returns nothing over a 24-hour window; a genuine hit names one source/destination IP pair with a `CoefficientOfVariation` well under 0.15 and an `AvgInterval` sitting close to a round number of seconds.

**Interpretation:** consistent with a fixed check-in cadence between that pair — not confirmation of C2, since [FALSE POSITIVE] below names a routine driver that produces the identical signature.

**[QUERY]** Splunk SPL against Zeek `conn.log`, scoring the same coefficient of variation on a per-connection-pair basis.

```spl
// CONCEPTUAL SAMPLE — bucket width, sort order, and thresholds illustrative;
// the explicit sort before streamstats matters, see DEH Part 14 §2.1's own note on why.
index=zeek sourcetype=zeek:conn dest_ip!="10.0.0.0/8" dest_ip!="192.168.0.0/16"
| sort 0 src_ip, dest_ip, _time
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip
| eval delta=_time-prev_time
| where delta > 0
| stats count as connections avg(delta) as avg_interval stdev(delta) as stdev_interval by src_ip, dest_ip
| eval cv=stdev_interval/avg_interval
| where connections > 20 AND cv < 0.15 AND avg_interval > 30 AND avg_interval < 3600
```

**Plausible expected result:** the same shape as the KQL block — a short list of (`src_ip`, `dest_ip`) pairs, usually empty on a quiet day.

**Interpretation:** same read as the KQL block above; running both against independent telemetry sources (firewall vs. Zeek) is a stronger corroboration than either alone.

*Elastic: `N/A` — Aggregation ceiling. Every Elastic surface fails this pattern for the same underlying reason Sigma, AQL, and YARA-L do below: none of EQL, Elastic KQL, or ES\|QL has a `LAG`/`prev`-style row-window primitive to compute a per-event inter-arrival delta ahead of the `STATS`/aggregation stage. Substituting an aggregate already sitting on the event, such as `event.duration`, is not an honest stand-in — it scores the length of individual sessions, not the gap between successive sessions, which is a different question from the one this pattern asks. Run this pattern's KQL or SPL version against the same telemetry and treat the result as the cross-language-comparable one instead.*

*Sigma: `N/A` — Aggregation ceiling. DEH Appendix A5 §4 marks Sigma's aggregation table with no native dispersion-statistic correlation type; `event_count` thresholds a raw connection count per group, but nothing in the correlation specification computes a standard deviation of inter-event deltas. A count-only substitute would test connection volume, not interval regularity — a different question.*

*AQL (QRadar): `N/A` — Structurally poor fit, not impossible. AQL has its own function set and no general-purpose window or `LAG`-style construct (DEH Appendix A5 §5 makes the same point for ordered multi-event logic); there is no way to compute a per-event inter-arrival delta inside one `SELECT`. A bucketed-count substitute exists (`QC-19-02`, where that is the actual question) but would misrepresent this pattern's hypothesis if forced here.*

*YARA-L: `N/A` — Aggregation ceiling. DEH Part 28 §2.5's `outcome` section supports `count`, `count_distinct`, `sum`, `min`, and `max` — no variance function exists to score interval dispersion.*

**[FALSE POSITIVE]** DEH Part 14 §2.1's own False Positive Trap names the dominant driver, unchanged here: cron-driven syncs, monitoring-agent heartbeats, license-check phone-homes, and update checkers all connect to a fixed endpoint on a fixed schedule — precisely what a low coefficient of variation measures. Expect the first run to surface a short, stable list of your own legitimate automation before anything else. Maintain a destination-keyed allowlist (not source-keyed, since many hosts share one update checker); raising the threshold to compensate just opens room for a real beacon in the same band.

**[PIVOT]** Check the destination's rarity first (`QC-19-03`): a tight-interval pair talking to a destination the fleet has contacted for months reads very differently from one first seen an hour ago. If the destination is TLS, pull its JA3/JA3S fingerprint (`QC-19-05`) — a rare or previously-unseen fingerprint on a tight-interval destination is a materially stronger combined signal than either check alone.

> **Detection Test**
> **Setup:** Lab host with outbound connectivity to a destination you control and can log connections from.
> **Action:** A scheduled task issuing an outbound request every 45 seconds for at least 20 minutes, clearing the `connections > 20` floor with a deliberately non-round interval.
> **Expected result:** the KQL block returns that pair with `CoefficientOfVariation` well under 0.15 and `AvgInterval` near 45. Re-run this periodically, not just at deployment — a silent break in the upstream field mapping degrades the statistic quietly rather than erroring, the same risk DEH Part 14 §2.1 names for its own SPL version.

---

### QC-19-02 — Long-period, low-frequency beacon detection via wide-lookback bucket aggregation

| Field | Value |
|---|---|
| **Pattern ID** | `QC-19-02` |
| **MITRE** | T1071.001 (Application Layer Protocol: Web Protocols); cf. T1008 (Fallback Channels) where the long-period beacon rotates destinations between check-ins |
| **Behavior** | A (source, destination) pair produces a small, consistent connection count per wide time bucket — for example, one to three connections per six-to-twelve-hour bucket — sustained across multiple weeks. |
| **DEH cross-ref** | DEH Part 14 §2.1 (its own worked query explicitly bounds `avg_interval` to under 3,600 seconds; this pattern is the wide-lookback counterpart for the cadence that boundary excludes by design); DEH Part 31 §7 (Time and seasonality) |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) — Sigma: `N/A`, see below |

**[HUNTER]** `QC-19-01` and its DEH source query both stop working once a beacon's sleep interval clears roughly one hour — not because the statistic is wrong, but because the bucket resolution and lookback window were never built to see a check-in that happens four times a day. A hunt looking across two to four weeks at a coarser bucket size catches exactly the configuration a red team would pick to evade the tighter rule: sleep eight to twelve hours, jitter lightly, check in twice a day.

**[QUERY]** Sentinel/Defender KQL, bucketing connections into 6-hour windows over a 21-day lookback and scoring how many of those buckets came back non-zero with a similar count.

```kql
// CONCEPTUAL SAMPLE — bucket width and day-count threshold illustrative;
// validate against your own long-run per-pair traffic before trusting the cutoff.
CommonSecurityLog
| where TimeGenerated > ago(21d)
| where isnotempty(DestinationIP) and DestinationIP !startswith "10." and DestinationIP !startswith "192.168."
| summarize BucketCount = count() by SourceIP, DestinationIP, bin(TimeGenerated, 6h)
| summarize ActiveBuckets = count(), AvgPerBucket = avg(BucketCount), StdevPerBucket = stdev(BucketCount)
    by SourceIP, DestinationIP
| extend BucketCoV = StdevPerBucket / AvgPerBucket
| where ActiveBuckets >= 40 and BucketCoV < 0.3 and AvgPerBucket between (1.0 .. 5.0)
```

**Plausible expected result:** a small handful of pairs at most; a genuine hit shows `ActiveBuckets` close to the theoretical maximum for 21 days of 6-hour buckets (84) and a low `BucketCoV`.

**Interpretation:** consistent with a long-period, low-frequency check-in that a shorter-window query would never accumulate enough connections to flag — treat this as a candidate for the same corroboration approach as `QC-19-01`, not as a stronger claim on its own.

**[QUERY]** Splunk SPL, using `bucket` at a 6-hour span over the same 21-day window.

```spl
// CONCEPTUAL SAMPLE — bucket width and day-count threshold illustrative;
// validate against your own long-run per-pair traffic before trusting the cutoff.
index=zeek sourcetype=zeek:conn earliest=-21d dest_ip!="10.0.0.0/8" dest_ip!="192.168.0.0/16"
| bucket _time span=6h
| stats count as bucket_count by src_ip, dest_ip, _time
| stats count as active_buckets avg(bucket_count) as avg_per_bucket stdev(bucket_count) as stdev_per_bucket
    by src_ip, dest_ip
| eval bucket_cov=stdev_per_bucket/avg_per_bucket
| where active_buckets >= 40 AND bucket_cov < 0.3 AND avg_per_bucket >= 1 AND avg_per_bucket <= 5
```

**Plausible expected result:** the same pair-level shape as the KQL block above.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, QRadar's Ariel Query Language, not standard SQL. This is a native fit for AQL's `GROUP BY`/`COUNT`/time-bucketing capability — unlike `QC-19-01`, the question here is genuinely "how many connections landed in each wide bucket," which AQL answers directly without needing a per-event delta.

```sql
-- CONCEPTUAL SAMPLE — CIDR-approximation via LIKE and the day-count threshold illustrative;
-- validate against your own DSM field names and long-run per-pair traffic.
SELECT sourceip, destinationip,
       COUNT(*) AS connectionCount
FROM events
WHERE NOT (destinationip LIKE '10.%' OR destinationip LIKE '192.168.%')
GROUP BY sourceip, destinationip
LAST 21 DAYS
```

**Plausible expected result:** a per-pair total connection count over the full 21-day window; pairs landing roughly between 40 and 120 total connections (1–3 per 6-hour bucket, most buckets active) are worth pulling into the KQL or SPL version above for the actual dispersion score.

**Interpretation:** a candidate list, not a verdict — AQL has no native way to bucket-then-score dispersion in one statement, so this narrows the field rather than computing the consistency statistic itself.

**[QUERY]** Google SecOps YARA-L, scoring connection count per pair inside a multi-day `match` window.

```yaral
// CONCEPTUAL SAMPLE — UDM field names illustrative; verify your rule's configured
// match-window ceiling supports 21 days, or run this as a retrohunt instead of a
// real-time rule if your deployment's real-time window is capped shorter.
rule long_period_beacon_candidate {
  meta:
    description = "Low-frequency, sustained connection cadence between one pair"
    severity = "Medium"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.target.ip = $dest_ip
    $e.principal.ip = $src_ip

  match:
    $src_ip, $dest_ip over 21d

  outcome:
    $connection_count = count($e.metadata.id)

  condition:
    $e and $connection_count >= 40
}
```

**Plausible expected result:** a match per (`$src_ip`, `$dest_ip`) pair whose connection count over 21 days clears 40 — a coarse volume floor, since YARA-L's `outcome` section has no bucket-dispersion function either.

**Interpretation:** same candidate-list caveat as the AQL block above — worth a closer look with a dispersion-capable language, not confirmation on its own.

**[QUERY]** Elastic ES\|QL, the wide-lookback aggregation shape this surface is built for.

```esql
// CONCEPTUAL SAMPLE — bucket width and day-count threshold illustrative;
// double-STATS availability depends on your installed ES|QL release, see below.
FROM logs-network*
| WHERE NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
| STATS bucket_count = COUNT(*) BY source.ip, destination.ip, BUCKET(@timestamp, 6h)
| STATS active_buckets = COUNT(*), avg_per_bucket = AVG(bucket_count), stdev_per_bucket = STDDEV_POP(bucket_count)
    BY source.ip, destination.ip
| EVAL bucket_cov = stdev_per_bucket / avg_per_bucket
| WHERE active_buckets >= 40 AND bucket_cov < 0.3 AND avg_per_bucket >= 1 AND avg_per_bucket <= 5
```

**Plausible expected result:** the same shape as the KQL/SPL blocks; version availability for the double-`STATS` pattern shown here should be checked against your installed ES\|QL release before relying on it.

**Interpretation:** same read as the KQL block above.

*Sigma: `N/A` — Aggregation ceiling. This pattern's core question — is the connection count *consistent across many separate time buckets spanning weeks* — compares aggregated values across multiple timeframes against each other, not a single count against a single threshold inside one timeframe. Sigma's correlation model evaluates one timeframe at a time; there is no primitive for scoring bucket-to-bucket consistency across an arbitrarily long series of buckets.*

**[FALSE POSITIVE]** The dominant driver is the same class of infrastructure noise as `QC-19-01`, just coarser: license servers, certificate-renewal checks, and scheduled batch jobs running a handful of times a day against a fixed endpoint produce an identical low-bucket-count, high-consistency signature. A destination-keyed allowlist from your own change-management records resolves most of this; a candidate with no documented business reason for its cadence is the one worth escalating.

**[PIVOT]** Same first two pivots as `QC-19-01` — destination rarity (`QC-19-03`) and JA3/JA3S fingerprint (`QC-19-05`) — plus one specific to this pattern's longer observation window: check whether the destination IP itself changed partway through the 21-day window while the cadence stayed the same, which is consistent with a beacon rotating infrastructure on a schedule rather than a single static destination, and would not surface in any of the single-pair queries above.

> **Hunter's Note**
> Sort a candidate list from this pattern by `active_buckets` as a fraction of the theoretical maximum for your lookback window, not by raw connection count — a pair with 90% of its expected buckets active and a tight `bucket_cov` is a far stronger candidate than one with the same total connection count concentrated into a handful of days and otherwise silent, even though both could return a similar `avg_per_bucket`.

---

### QC-19-03 — Rare or first-seen external destination hunting per host baseline

| Field | Value |
|---|---|
| **Pattern ID** | `QC-19-03` |
| **MITRE** | No clean single-technique mapping — see [HUNTER] framing |
| **Behavior** | A host contacts an external IP, domain, or ASN it has not been observed contacting anywhere in a preceding baseline window. |
| **DEH cross-ref** | DEH Part 14 §3 (Rare destinations, without the DNS layer); DEH Part 31 §3, §6 (User/host and network baselines this scoring depends on) |
| **Languages covered** | Sigma: `N/A`, see below; KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) |

**[HUNTER]** DEH Part 14 §3 is direct about this pattern's limitation: deployed alone as a standing alert, "has this host ever talked to this IP before" has an unworkable false-positive rate at scale, since new legitimate destinations get created constantly. Its value as a *hunt* differs from its value as a standing rule: run it on demand against a host already flagged by another pattern in this part, where "first contact, right now" is a useful corroborating fact rather than the whole basis for an alert.

**Sigma — N/A (no first-seen/new-term primitive).** The SigmaHQ Correlation Rules Specification defines exactly seven correlation types — `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, and `value_percentile` — and none of them expresses "this value hasn't been seen before within a baseline window." A first-seen check needs a maintained historical baseline external to any single rule evaluation; that baseline gets consumed by a plain selection rule doing an anti-join against it — the same shape the KQL/SPL/AQL/ES|QL implementations below use — not by a Sigma correlation type.

**[QUERY]** Sentinel/Defender KQL, computing each destination's first-seen timestamp across a 30-day window and filtering to destinations first seen inside the last 24 hours for a specific host under review.

```kql
// CONCEPTUAL SAMPLE — baseline window illustrative; validate against your own retention.
let baseline = CommonSecurityLog
    | where TimeGenerated > ago(30d)
    | where SourceIP == "<host_under_review>"
    | summarize FirstSeen = min(TimeGenerated) by DestinationIP;
baseline
| where FirstSeen > ago(24h)
| project DestinationIP, FirstSeen
```

**Plausible expected result:** a short list of destinations for the host in question, most of which resolve to routine new-vendor or CDN traffic on inspection.

**Interpretation:** the same corroborating-fact read as above — treat as one input into a broader review, not a standalone finding.

**[QUERY]** Splunk SPL, using a summary index of prior-seen destinations per host as the baseline lookup.

```spl
// CONCEPTUAL SAMPLE — baseline lookup name and window illustrative; validate against your own retention.
index=network host="<host_under_review>" earliest=-24h
| lookup dest_baseline_30d.csv host dest_ip OUTPUT first_seen
| where isnull(first_seen)
| table _time, host, dest_ip
```

**Plausible expected result:** the same shape as the KQL block — a short list of destinations with no matching entry in the 30-day baseline lookup.

**Interpretation:** same read as above; the quality of this result depends entirely on how completely the baseline lookup was populated, which is why DEH Part 31 §6's own network-baseline construction is the section to read before trusting an empty result as "nothing new."

**[QUERY]** The following is AQL, not standard SQL. This is the investigative form: a wide-window search finding each destination's earliest appearance for a host, run by hand against a candidate already surfaced by another pattern rather than built as a fleet-wide standing rule, which would need a QRadar Reference Set of known destinations per host population to avoid recomputing a 30-day baseline on every evaluation (DEH Part 27 §2–§3).

```sql
-- CONCEPTUAL SAMPLE — baseline window illustrative; validate against your own retention.
SELECT destinationip, MIN(starttime) AS firstSeen
FROM events
WHERE sourceip = '<host_under_review>'
GROUP BY destinationip
LAST 30 DAYS
```

**Plausible expected result:** one row per destination the host has contacted over the full window, each with its earliest timestamp; filtering to `firstSeen` within the last 24 hours surfaces the candidates.

**Interpretation:** same corroborating-fact read as above — a candidate list, not the fleet-wide standing detection a Reference Set–backed version would be.

**[QUERY]** Google SecOps YARA-L, using `outcome` to compute the count of distinct days a destination has been seen for a given source inside a 30-day match window.

```yaral
// CONCEPTUAL SAMPLE — UDM field names illustrative.
rule rare_destination_for_host {
  meta:
    description = "Destination seen on very few distinct days across a 30-day window"
    severity = "Low"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.ip = $src_ip
    $e.target.ip = $dest_ip

  match:
    $src_ip, $dest_ip over 30d

  outcome:
    $distinct_days_seen = count_distinct($e.metadata.event_timestamp.seconds)

  condition:
    $e and $distinct_days_seen <= 1
}
```

**Plausible expected result:** a match per (source, destination) pair seen on one or zero distinct days across the window — a coarse proxy, since this counts distinct event timestamps rather than a genuine calendar-day bucket.

**Interpretation:** same corroborating-fact read as above; verify `distinct_days_seen` actually buckets by calendar day in your own deployment before trusting it as equivalent.

**[QUERY]** Elastic ES\|QL, computing minimum first-seen timestamp per destination across a wide window.

```esql
// CONCEPTUAL SAMPLE — baseline window illustrative; validate against your own retention.
FROM logs-network*
| WHERE source.ip == "<host_under_review>"
| STATS first_seen = MIN(@timestamp) BY destination.ip
| WHERE first_seen > NOW() - 1 DAY
```

**Plausible expected result:** the same shape as the KQL/AQL blocks above.

**Interpretation:** same read as above.

**[FALSE POSITIVE]** New SaaS vendor onboarding, routine CDN edge-IP rotation, and any newly provisioned internal or partner infrastructure all generate first-contact events at a volume that makes this pattern unusable as a standalone alert — the exact concern DEH Part 14 §3 raises, governing every language block above identically. Treat a hit as context weighted by what else is true about the same host and destination, never as a page-worthy finding alone.

**[PIVOT]** If the flagged destination also shows up in `QC-19-01` or `QC-19-02`'s cadence-scoring output, or carries a rare JA3 fingerprint per `QC-19-05`, escalate the combination. On its own, a rare-destination hit's next useful step is passive DNS or WHOIS history on the destination IP — a domain registered days before first contact is a materially different case than a five-year-old CDN IP the fleet simply hadn't reached yet.

> **False Positive Trap**
> Running this pattern immediately after any bulk infrastructure change — a CDN migration, a new SSO/SaaS rollout, a firewall rule change that newly permits a previously-blocked destination class — produces a flood of first-contact matches that have nothing to do with an attacker and everything to do with the change itself. Suppress this pattern's output fleet-wide for a stated window after any known infrastructure change, rather than trying to tune the underlying baseline window to absorb it; a shorter baseline window just makes ordinary destination churn look "rare" more often, not less.

---

### QC-19-04 — Process-correlated persistent low-volume beacon session

| Field | Value |
|---|---|
| **Pattern ID** | `QC-19-04` |
| **MITRE** | T1071.001 (Application Layer Protocol: Web Protocols) |
| **Behavior** | A single process on a host repeatedly opens short-lived or long-lived, low-byte-count connections to the same remote IP and port, visible directly in endpoint telemetry rather than only at the network perimeter. |
| **DEH cross-ref** | DEH Part 9 §3.2 (Sysmon Event ID 3, Network Connect); DEH Part 11 (Endpoint Detection Engineering); DEH Part 14 §2 (the network-side version of the same behavior) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, YARA-L, Elastic (ES\|QL) — AQL: `N/A`, see below |

**[HUNTER]** Every query in `QC-19-01` and `QC-19-02` assumes the beacon is visible from the network perimeter — a firewall, proxy, or Zeek sensor sitting in the traffic's path. A host on a segment those sensors don't cover needs the same "same process, same destination, repeated" question asked from the endpoint's own network-connection telemetry instead. This pattern exists for that visibility gap, not as a redundant re-check where both already exist.

**[QUERY]** Sigma correlation rule using the `event_count` type, keyed on the initiating image and destination IP, against Sysmon Event ID 3.

```yaml
# CONCEPTUAL SAMPLE — count threshold and timespan illustrative; validate against your
# own per-process baseline before trusting this as a cutoff.
title: Repeated Low-Volume Network Connection From Single Process
status: experimental
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
  condition: selection
correlation:
  type: event_count
  rules:
    - selection
  group-by:
    - Image
    - DestinationIp
    - DestinationPort
  timespan: 6h
  condition:
    gte: 15
falsepositives:
  - A background sync or polling client (chat app, cloud-storage sync, monitoring agent) legitimately reconnecting to one endpoint
level: medium
```

**Plausible expected result:** a match returns the source image path, destination IP/port, and a connection count for the 6-hour window; a healthy fleet may show a small, stable set of recognizable applications here that need allowlisting once, not zero results.

**Interpretation:** consistent with a process maintaining a repeated low-volume channel to one destination — see [FALSE POSITIVE] below before treating an unfamiliar process name here as confirmed.

**[QUERY]** Sentinel/Defender KQL against `DeviceNetworkEvents` (Microsoft Defender for Endpoint's advanced-hunting schema).

```kql
// CONCEPTUAL SAMPLE — threshold and timespan illustrative.
DeviceNetworkEvents
| where Timestamp > ago(6h)
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count() by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where ConnectionCount >= 15
```

**Plausible expected result:** a small result set naming a device, process, and remote endpoint with a connection count clearing the threshold.

**Interpretation:** same read as the Sigma block above.

**[QUERY]** Splunk SPL against Sysmon Event ID 3 ingested via the standard Windows TA.

```spl
// CONCEPTUAL SAMPLE — threshold and timespan illustrative.
index=sysmon EventCode=3 earliest=-6h
| stats count as connection_count by ComputerName, Image, DestinationIp, DestinationPort
| where connection_count >= 15
```

**Plausible expected result:** the same shape as the KQL block above.

**Interpretation:** same read as above.

**[QUERY]** Google SecOps YARA-L against UDM `NETWORK_CONNECTION` events joined to the initiating process.

```yaral
// CONCEPTUAL SAMPLE — UDM field names illustrative.
rule process_repeated_low_volume_connection {
  meta:
    description = "Single process repeatedly connecting to one remote endpoint"
    severity = "Medium"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.process.file.full_path = $proc_path
    $e.target.ip = $dest_ip
    $e.target.port = $dest_port

  match:
    $proc_path, $dest_ip, $dest_port over 6h

  outcome:
    $connection_count = count($e.metadata.id)

  condition:
    $e and $connection_count >= 15
}
```

**Plausible expected result:** a match keyed on process path, destination IP, and destination port whenever the connection count clears 15 inside the 6-hour match window.

**Interpretation:** same read as above.

**[QUERY]** Elastic ES\|QL against endpoint network-connection telemetry, chosen for the same threshold/wide-lookback reasoning as the earlier patterns in this part.

```esql
// CONCEPTUAL SAMPLE — threshold and timespan illustrative.
FROM logs-endpoint.events.network*
| WHERE @timestamp > NOW() - 6 HOURS
| STATS connection_count = COUNT(*) BY host.name, process.executable, destination.ip, destination.port
| WHERE connection_count >= 15
```

**Plausible expected result:** the same shape as the other language blocks above.

**Interpretation:** same read as above.

*AQL (QRadar): `N/A` — Missing schema field. QRadar's default DSMs for endpoint sources rarely normalize a single event carrying both the initiating process image and the destination IP/port the way Sysmon-native or EDR-native backends do; without a confirmed custom-property extension mapping process identity onto the network-connection event for your specific log source, there is no reliable field to key this pattern's `GROUP BY` on. A deployment with a custom DSM extension that does expose both fields on one event could adapt the KQL/SPL logic above directly — this `N/A` reflects the unconfirmed default schema, not an inherent AQL limitation.*

**[FALSE POSITIVE]** Chat applications, cloud-storage sync clients, and monitoring or update agents that maintain a frequently-reconnecting channel to one vendor endpoint are the dominant driver, and typically clear a 15-connections-per-6-hours threshold with room to spare. Build the allowlist on the process's full signed path, not its file name — a binary renamed to match a legitimate client is exactly the case a path/signature check catches and a name-only exclusion doesn't.

**[PIVOT]** Cross-reference the same destination against `QC-19-01`/`QC-19-02` for a network-side corroboration where perimeter visibility exists, and against `QC-19-03` for destination rarity. Independently, pull the flagged process's parent process and full command line — a legitimate application's own installed binary looks very different from a generic loader or scripting host reaching the same destination.

> **Engineering Reality**
> Endpoint network-connection telemetry (Sysmon Event ID 3, most EDR network events) typically records connection establishment, not connection duration or byte counts the way a firewall session log or Zeek `conn.log` does — DEH Part 9 §3.2 covers exactly this gap. A process opening the same destination 15 times in six hours could be 15 one-second beacons or one long-lived socket the endpoint agent logged multiple times across a keepalive cycle; where both endpoint and network telemetry exist for the same host, corroborate the connection *count* shown here against the network-side view's *duration and byte* fields before assuming which shape you're actually looking at.

---

### QC-19-05 — JA3/JA3S TLS client-fingerprint pivoting

| Field | Value |
|---|---|
| **Pattern ID** | `QC-19-05` |
| **MITRE** | T1573 (Encrypted Channel) |
| **Behavior** | A TLS ClientHello's JA3 fingerprint, or the paired JA3S ServerHello fingerprint, matches a hash already attributed to a known C2 framework or malware family, or is rare/first-seen across the fleet. |
| **DEH cross-ref** | DEH Part 14 §4 (TLS and encrypted-traffic signals — the JA3/JA3S fingerprint framing and its ECH-driven Blind Spot) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** DEH Part 14 §4 frames JA3/JA3S as one of the metadata signals detection still has left once payload inspection stops being possible — a hash of the cipher-suite and extension order a TLS client presents, computed before anything is encrypted. The hunt use case is less "does this hash match a known-bad list" and more "pivot fleet-wide from one hash a hunter has already attributed": given one JA3 value from an incident, find every other host that has ever presented it, independent of destination, since a malware build reuses the same TLS library fingerprint across every channel it opens.

**[QUERY]** Sigma rule matching a network-connection or TLS logsource against a maintained list of attributed JA3 hashes.

```yaml
# CONCEPTUAL SAMPLE — JA3 hash values are placeholders; substitute hashes your own
# team has attributed via threat intelligence, not the illustrative values shown here.
title: Known or Attributed JA3 Fingerprint Observed
status: experimental
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  selection:
    ja3_hash:
      - '<attributed_ja3_hash_1>'
      - '<attributed_ja3_hash_2>'
  condition: selection
falsepositives:
  - A shared TLS client library (a common HTTP client, a scripting-language TLS stack) producing the same fingerprint for unrelated legitimate software
level: high
```

**Plausible expected result:** a match returns the source host, destination, and the specific hash matched — expect this to fire rarely on a healthy fleet if the hash list is genuinely attributed rather than a broad public feed pulled in wholesale.

**Interpretation:** consistent with the same TLS client library — and plausibly the same malware build — connecting from this host; see [FALSE POSITIVE] and the Blind Spot below before treating a match as attribution on its own.

**[QUERY]** Sentinel/Defender KQL against a Zeek- or NDR-sourced SSL/TLS table normalized into Log Analytics.

```kql
// CONCEPTUAL SAMPLE — table/field names illustrative depending on your TLS-metadata ingestion path.
ZeekSslLog_CL
| where TimeGenerated > ago(7d)
| where ja3_hash_s in ("<attributed_ja3_hash_1>", "<attributed_ja3_hash_2>")
| project TimeGenerated, SourceIP = id_orig_h_s, DestinationIP = id_resp_h_s, ja3_hash_s
```

**Plausible expected result:** the same shape as the Sigma match — sparse rows naming source, destination, and hash.

**Interpretation:** same read as above.

**[QUERY]** Splunk SPL against Zeek `ssl.log`.

```spl
// CONCEPTUAL SAMPLE — JA3 hash values are placeholders; substitute your own attributed hashes.
index=zeek sourcetype=zeek:ssl (ja3="<attributed_ja3_hash_1>" OR ja3="<attributed_ja3_hash_2>")
| table _time, id.orig_h, id.resp_h, ja3, server_name
```

**Plausible expected result:** the same shape as the blocks above, with `server_name` (SNI, where present) available as an immediate secondary check.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, not standard SQL. JA3 must exist as a custom event property on your QRadar deployment, typically populated when ingesting Zeek or Suricata TLS logs through a DSM that extracts the field — a plain default DSM will not expose it.

```sql
-- CONCEPTUAL SAMPLE — JA3 hash values are placeholders; substitute your own attributed hashes.
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS eventTime,
       sourceip, destinationip, "JA3 Hash" AS ja3Hash
FROM events
WHERE "JA3 Hash" IN ('<attributed_ja3_hash_1>', '<attributed_ja3_hash_2>')
LAST 7 DAYS
```

**Plausible expected result:** the same shape as the other language blocks, contingent entirely on whether your log source extraction actually populates the `JA3 Hash` custom property.

**Interpretation:** same read as above — an empty result here is ambiguous between "genuinely clean" and "field not populated for this log source," which is a check worth making before trusting a zero-count as reassuring.

**[QUERY]** Google SecOps YARA-L against UDM's TLS client fingerprint field.

```yaral
// CONCEPTUAL SAMPLE — UDM field name illustrative.
rule attributed_ja3_observed {
  meta:
    description = "TLS ClientHello fingerprint matches an attributed hash"
    severity = "High"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.network.tls.client.ja3 = /^(<attributed_ja3_hash_1>|<attributed_ja3_hash_2>)$/
  condition:
    $e
}
```

**Plausible expected result:** one match per connection presenting an attributed hash, with `principal.ip` and `target.ip` populated.

**Interpretation:** same read as above.

**[QUERY]** Elastic KQL, chosen as the single-event boolean surface per STYLE-GUIDE.md §4.2.

```kql
// CONCEPTUAL SAMPLE — JA3 hash values are placeholders; substitute your own attributed hashes.
tls.client.ja3 : ("<attributed_ja3_hash_1>" or "<attributed_ja3_hash_2>")
```

**Plausible expected result:** the same shape as every block above.

**Interpretation:** same read as above.

**[FALSE POSITIVE]** JA3 fingerprints a TLS library, not an application — many unrelated pieces of software built on the same HTTP client or scripting-language TLS stack share an identical fingerprint. A match against a broadly-sourced public JA3 feed, rather than a hash your own team attributed from an incident, surfaces this library-sharing noise at a rate that makes the feed close to unusable without cross-referencing destination reputation or another signal from this part.

**[PIVOT]** Pull every connection presenting the same JA3 hash fleet-wide, regardless of destination — that pivot, not the single flagged connection, is this pattern's actual value, since it surfaces other infected hosts a destination-based or interval-based query would never connect to the same finding. Cross-reference any newly discovered host against `QC-19-01`/`QC-19-02` for its own beacon cadence.

> **Blind Spot**
> JA3 is only as durable as the attacker's indifference to it. Reordering TLS extensions or cipher suites, upgrading a C2 framework's TLS library, or using a JA3-randomization wrapper changes the hash completely while leaving every other observable behavior — including the beacon cadence `QC-19-01` and `QC-19-02` would still catch — unchanged. Treat a clean JA3 sweep as evidence that a *specific known hash* isn't present, never as evidence that no TLS-wrapped C2 is present at all; DEH Part 14 §4's own Blind Spot on TLS 1.3 and encrypted ClientHello names the deeper version of the same erosion.

---

### QC-19-06 — Domain-fronting and CDN-abuse shaped traffic

| Field | Value |
|---|---|
| **Pattern ID** | `QC-19-06` |
| **MITRE** | T1090.004 (Proxy: Domain Fronting) |
| **Behavior** | A TLS connection's outer SNI names a trusted CDN edge or front domain — or carries no SNI at all — while other available evidence (a decrypted HTTP Host header, where SSL-inspection telemetry exposes it, or the destination's ASN alone for the no-SNI case) indicates the real destination is an unrelated, hidden domain riding the same CDN's shared IP space. |
| **DEH cross-ref** | DEH Part 14 §4 (TLS and encrypted-traffic signals; the TLS 1.3/encrypted-ClientHello Blind Spot this pattern's naive form runs into directly) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Classic domain fronting — an SNI naming one domain while the encrypted HTTP Host header names another, both served off the same CDN IP — has been substantially closed off by the major CDN providers since around 2019, worth knowing before trusting this pattern's naive form as a live threat rather than a historical one; the Detection Autopsy below walks through why. What remains genuinely worth hunting: an SNI that is blank or absent on a connection to a known CDN ASN, and — where SSL-decrypt telemetry exists — a Host header that still doesn't match the SNI it rode in on.

**[QUERY]** Sigma rule, scoped to the SNI-absent-to-CDN-ASN sub-case, which needs only the TLS event and no cross-event join.

```yaml
# CONCEPTUAL SAMPLE — CDN ASN/IP-range list illustrative; substitute your own current
# CDN-range reference data, since these ranges change over time.
title: TLS Connection With Blank SNI To Known CDN Range
status: experimental
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  selection:
    server_name: ''
    destination_asn:
      - 'AS13335'
      - 'AS54113'
      - 'AS20940'
      - 'AS16509'
  condition: selection
falsepositives:
  - Legitimate clients that omit SNI by design, and CDN health checks or internal monitoring probes
level: medium
```

**Plausible expected result:** a small number of matches on most fleets; each names a source host and destination ASN with an empty `server_name` field.

**Interpretation:** consistent with a client deliberately avoiding SNI on a CDN-fronted connection — see [FALSE POSITIVE] below for the routine driver that produces the same shape.

**[QUERY]** Sentinel/Defender KQL, covering both the SNI-absent sub-case and, where a proxy table exposes it, the SNI-versus-decrypted-Host-header mismatch sub-case on a single normalized event.

```kql
// CONCEPTUAL SAMPLE — assumes an SSL-decrypting proxy log with both fields on one record;
// most environments without SSL inspection can only run the SNI-absent variant below.
let cdnAsns = dynamic(["AS13335", "AS54113", "AS20940", "AS16509"]);
ProxyLog_CL
| where TimeGenerated > ago(24h)
| where DestinationAsn_s in (cdnAsns)
| where isempty(TlsSni_s) or (isnotempty(HttpHost_s) and TlsSni_s != HttpHost_s)
| project TimeGenerated, SourceIP = SrcIp_s, TlsSni_s, HttpHost_s, DestinationAsn_s
```

**Plausible expected result:** sparse rows; a genuine SNI/Host mismatch row names both fields explicitly, letting an analyst see the front domain and the real one side by side.

**Interpretation:** the SNI-absent rows carry the same read as the Sigma block; a genuine mismatch row is a stronger, more specific signal, but depends entirely on SSL-decrypt telemetry existing in your environment.

**[QUERY]** Splunk SPL against a Zeek `ssl.log` and `http.log` join on connection UID, for environments running SSL decryption inline.

```spl
// CONCEPTUAL SAMPLE — CDN ASN list illustrative; substitute your own current CDN-range reference data.
index=zeek sourcetype=zeek:ssl dest_asn IN ("AS13335","AS54113","AS20940","AS16509")
| join uid
    [ search index=zeek sourcetype=zeek:http
    | rename host as http_host ]
| where (server_name="" ) OR (isnotnull(http_host) AND server_name!=http_host)
| table _time, "id.orig_h", server_name, http_host, dest_asn
```

**Plausible expected result:** the same shape as the KQL block — most environments will only see the SNI-absent rows populate, since the join depends on `http.log` existing at all, which itself requires SSL decryption upstream of the sensor.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, not standard SQL. This variant needs SSL-decrypt telemetry (a proxy with TLS inspection enabled) to expose both the SNI and the decrypted Host header as custom properties on one event; without it, only the SNI-absent-to-CDN sub-case below is answerable.

```sql
-- CONCEPTUAL SAMPLE — CDN ASN list illustrative; substitute your own current CDN-range reference data.
SELECT sourceip, "TLS SNI" AS tlsSni, "HTTP Host" AS httpHost, destinationip
FROM events
WHERE ("TLS SNI" = '' OR ("HTTP Host" IS NOT NULL AND "TLS SNI" != "HTTP Host"))
LAST 24 HOURS
```

**Plausible expected result:** sparse rows on an environment with SSL-decrypt telemetry populated; an environment without it should expect this query to return only the blank-SNI rows, since `HTTP Host` will simply be null throughout.

**Interpretation:** same read as above.

**[QUERY]** Google SecOps YARA-L, scoped to the SNI-absent-to-CDN sub-case — UDM's TLS and HTTP fields for a given connection commonly live on separate event types rather than one merged record, so the full SNI/Host mismatch variant is not reliably expressible as one YARA-L rule without a confirmed joined schema; that limitation is named again in [FALSE POSITIVE] below rather than repeated here.

```yaral
// CONCEPTUAL SAMPLE — UDM field names illustrative.
rule blank_sni_to_cdn_range {
  meta:
    description = "TLS connection with no SNI to a known CDN ASN"
    severity = "Medium"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.network.tls.client.server_name = ""
    $e.network.asn = /^(13335|54113|20940|16509)$/
  condition:
    $e
}
```

**Plausible expected result:** a match per connection with an empty SNI to one of the listed ASNs.

**Interpretation:** same SNI-absent read as the Sigma block — the mismatch variant is out of scope for this rule as written.

**[QUERY]** Elastic KQL, chosen as the single-event boolean surface — scoped to the SNI-absent-to-CDN sub-case only. Unlike Sentinel/Defender KQL, SPL, and AQL, the Kibana Query Language has no operator for comparing one field's value against another field's value on the same document, so the SNI/Host mismatch sub-case shown in the blocks above cannot be expressed as an Elastic KQL filter at all; run that sub-case in ES\|QL (via `EVAL`) or a Painless script query instead.

```kql
// CONCEPTUAL SAMPLE — CDN ASN list illustrative; substitute your own current CDN-range reference data.
network.asn : ("13335" or "54113" or "20940" or "16509") and tls.client.server_name : ""
```

**Plausible expected result:** the same shape as the Sigma block's SNI-absent matches above — a small number of rows naming a source host and destination ASN with an empty `server_name`.

**Interpretation:** the same SNI-absent read as the Sigma block; this surface cannot corroborate the mismatch sub-case on its own.

**[FALSE POSITIVE]** Encrypted Client Hello (ECH), increasingly deployed by major CDNs, produces a blank or non-informative outer SNI on a large and growing share of entirely legitimate traffic — DEH Part 14 §4's own Blind Spot names this trend directly. The SNI-absent sub-case gets noisier as ECH adoption grows, not quieter; treat a rising baseline as an infrastructure trend, not a rising attack rate, and re-baseline periodically rather than trusting a fixed threshold to stay meaningful. The mismatch sub-case's driver is narrower: multi-tenant CDN hosting where one certificate legitimately covers several customer domains can produce a differing Host header with nothing adversarial happening — check the certificate's SAN list before escalating.

**[PIVOT]** For a genuine SNI/Host mismatch, pull the destination IP's full connection history — a domain-fronted C2 channel typically shows a small number of source hosts repeatedly hitting the same front domain, which overlaps directly with `QC-19-01`'s cadence scoring. For the SNI-absent sub-case, check whether the same source host's other connections to the same CDN ASN carry a normal, non-empty SNI — a host that fronts selectively, rather than omitting SNI universally, is a more specific signal than one that simply has ECH enabled at the browser level for everything.

> **Detection Autopsy**
> **The naive rule:** "alert on any TLS connection where the SNI doesn't match the decrypted HTTP Host header," treated as if it still directly catches domain fronting the way it did when the technique was first documented.
> **Why it quietly stopped working:** the major CDN providers classic domain fronting relied on — routing that let a front domain's certificate serve an unrelated backend Host header — largely closed that specific behavior off starting around 2019, once it was used to evade censorship and, by the same mechanism, to hide C2 traffic. A mismatch rule built against that old behavior now mostly fires on the mundane, structural reasons a Host header and an SNI legitimately differ on a modern multi-tenant CDN — shared certificates, load-balancer edge cases, ECH — because the classic technique is rarer than the false positives that resemble it.
> **The better version:** treat SNI/Host mismatch as one weak signal among several, not a standalone alert, and weight the SNI-absent-to-CDN-ASN sub-case and the cadence/rarity signals from `QC-19-01` through `QC-19-03` at least as heavily — the techniques that still work are better caught by combining this pattern with the timing and rarity patterns elsewhere in this part than by a mismatch check alone.

---

## Cross-references

- DEH Part 14 §2, §2.1, §3, and §4 (Network Detection Engineering — the coefficient-of-variation beaconing detection, rare-destination framing, and TLS/JA3/ECH signal set this entire part adapts and extends) for the mechanics behind `QC-19-01` through `QC-19-06`.
- DEH Part 9 §3.2 (Sysmon Detection Engineering — Event ID 3, Network Connect) and DEH Part 11 (Endpoint Detection Engineering) for the telemetry mechanics behind `QC-19-04`.
- DEH Part 31 §3, §6, §7 (Baselining — user/host, network, and time/seasonality baselines) for the baseline construction `QC-19-02` and `QC-19-03` depend on.
- DEH Parts 24–29 and Appendix A5 §2, §4, §5, §8 for the Sigma/KQL/SPL/AQL/YARA-L/Elastic syntax fundamentals, aggregation-ceiling table, and multi-event correlation model this part assumes rather than teaches.
- DEH Parts 41–43 and this book's own Part 28 for how these six patterns would be scored on the Detection Coverage/Quality/Debt scales rather than this part inventing its own scoring.
- This book's Part 18 (Suspicious DNS) for the explicit domain-name-rarity/DNS-tunnelling boundary `QC-19-03` and this part's "Why this part exists" section state.
- This book's Part 27 (Multi-Behavior Hunt Chains) as the likely destination for a chain citing `QC-19-01` through `QC-19-06` alongside earlier-stage discovery and lateral-movement patterns from Parts 15–17, and later-stage exfiltration patterns from Part 20.
