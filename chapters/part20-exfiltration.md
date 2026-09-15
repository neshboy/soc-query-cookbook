---
title: "Exfiltration"
part: 20
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 20 — Exfiltration

## Why this part exists

**[CONCEPT]** Exfiltration is the tactic-level moment data actually leaves the environment — not the staging, not the discovery, not the access that made it possible, just the transfer itself crossing the boundary a defender can still watch. This part covers three named shapes of that transfer, per `BOOK-INDEX.md`'s scope column: large or anomalous outbound transfer volume, exfiltration carried over an alternate protocol (DNS, ICMP) instead of a normal web/file-transfer channel, and exfiltration to an unsanctioned cloud-storage destination. Five patterns, at this book's standard 4–6 budget: `QC-20-01` and `QC-20-02` cover the volume shape (a single oversized session versus an accumulated low-and-slow total), `QC-20-03` and `QC-20-04` cover the alternate-protocol shape (ICMP and DNS respectively), and `QC-20-05` covers the cloud-storage-destination shape.

Four explicit boundaries against neighboring parts, so this part's patterns don't quietly re-derive work that already belongs elsewhere:

- **Part 18 (Suspicious DNS)** owns DNS-tunnelling *signature* logic exclusively — entropy, label shape, NXDOMAIN churn, the composite score deciding "this looks like a tunnel." `QC-20-04` is scoped to the *volume* side of DNS abuse instead: how much data moved, not whether the channel is shaped like a tunnel. A hit pivots into Part 18 for signature confirmation; it does not restate it.
- **Part 19 (C2 & Beaconing Detection)** owns the destination's *behavioral* signature — connection-interval regularity, JA3/TLS fingerprinting, rare-destination-as-beacon scoring. `QC-20-01` uses a rare-or-first-seen destination as one input to a volume query, but it is not a beacon detection; a hit pivots into Part 19 to check for beacon-shaped intervals.
- **Part 21 (Insider Threat & Data Staging)** owns the behavior *before* the transfer — mass archive creation, unusual bulk file access, staging activity. This part starts where Part 21 leaves off: the data is already gathered and now moving across the boundary.
- **Parts 25–26 (Cloud Infrastructure Abuse; Cloud-Native Lateral Movement)** own the cloud *control-plane* side of data leaving a cloud environment — IAM abuse, snapshot/object sharing, storage-bucket exposure. `QC-20-05` is the network/endpoint-side view of the same phenomenon: a host or SaaS session uploading to an unsanctioned cloud-storage destination, detected from egress traffic rather than the provider's own audit trail.

This part does not teach Sigma, KQL, SPL, AQL, YARA-L, or EQL/ES\|QL syntax fundamentals — see DEH Parts 23–29 and DEH Appendix A5 for language semantics and the cross-language translation-loss framework every query below is implicitly built on. It also does not score these patterns' Detection Coverage, Quality, or Debt tier — see DEH Parts 41–43 for that methodology and this book's own Part 28 for how it applies to the cookbook's pattern catalog specifically.

## 1. Volume and alternate-protocol exfiltration signals

### QC-20-01 — Oversized single session to a rare or first-seen external destination

| Field | Value |
|---|---|
| **Pattern ID** | `QC-20-01` |
| **MITRE** | T1041 (Exfiltration Over C2 Channel); a destination confirmed to be a separate, non-C2 channel instead points to T1048.003 (Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol) — see [HUNTER] below for why this pattern doesn't force the distinction upfront. |
| **Behavior** | A single completed outbound session — one proxy access-log row or one flow/IPFIX record — moves an unusually large byte count to a destination the source host has not talked to before, or that is rare across the environment. |
| **DEH cross-ref** | DEH Part 14 §8 (Data exfiltration signals; adapts DET-14-06's byte-ratio/rare-destination logic to a single-flow shape rather than DET-14-06's own hourly-bucket aggregation); DEH Part 31 (Baselining — the rare/first-seen-destination enrichment this pattern's `WHERE` clause assumes already exists) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** DEH Part 14 §8's own worked detection (DET-14-06) scores byte ratio over an hourly window; this pattern is the simpler, cheaper cousin — a single flow or proxy record already carries a total-bytes field for the whole session, so no bucketing is needed to catch the loud, single-burst case. The reason to hunt this rather than only trust a standing rule: the standing version almost always excludes an allowlist of known-large legitimate destinations (backup targets, CDN endpoints, SaaS vendors), and that allowlist is exactly where a hunt should look first — an attacker riding a compromised session through an already-allowlisted destination, or a genuinely new destination that hasn't hit the allowlist review queue yet, both slip past the tuned version.

**[QUERY]** Sigma rule against a proxy or flow logsource, matching a single session above a fixed byte floor to a destination flagged as first-seen by an upstream rarity enrichment.

```yaml
# CONCEPTUAL SAMPLE — field names illustrative; align with your own proxy/flow logsource's actual byte and destination-rarity fields
title: Oversized Outbound Session To A Rare External Destination
status: experimental
logsource:
  category: proxy
detection:
  selection:
    bytes_out|gte: 104857600
    dest_rarity: 'first_seen'
  condition: selection
falsepositives:
  - Large legitimate upload to a genuinely new but authorized destination (a newly onboarded partner integration, a new backup target)
level: high
```

**Plausible expected result:** on a tuned estate this returns a handful of rows a week at most; a genuine hit names one source host, one external destination, and a total-bytes figure well above the 100 MB floor.

**Interpretation:** consistent with a single large transfer to a destination the environment hasn't seen before — worth an immediate look at what the destination actually is, not a verdict on its own.

**[QUERY]** Sentinel/Defender KQL against `DeviceNetworkEvents`, joined to a maintained rare-destination watchlist table.

```kql
// CONCEPTUAL SAMPLE — table/field names illustrative; align with your own proxy or NetFlow ingestion schema
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| where BytesSent >= 104857600
| join kind=leftouter (
    RareDestinationBaseline_CL
    | project RemoteUrl, FirstSeenDaysAgo = first_seen_days_ago_d
  ) on RemoteUrl
| where isnull(FirstSeenDaysAgo) or FirstSeenDaysAgo < 7
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, BytesSent, FirstSeenDaysAgo
```

**Plausible expected result:** sparse rows; each names the device, the destination, and the byte count, with `FirstSeenDaysAgo` either null (never seen before) or a low single-digit number.

**Interpretation:** the same read as the Sigma block — strong enough on volume plus novelty to warrant a look, not yet strong enough to call it confirmed.

**[QUERY]** Splunk SPL against a proxy access-log sourcetype, using a lookup for destination rarity.

CONCEPTUAL SAMPLE — index/sourcetype and lookup name illustrative; substitute your own proxy ingestion pipeline's schema.

```spl
index=proxy sourcetype=proxy_access
| where bytes_out >= 104857600
| lookup rare_destination_baseline dest AS dest_domain OUTPUT first_seen_days_ago
| where isnull(first_seen_days_ago) OR first_seen_days_ago < 7
| table _time, src_ip, user, dest_domain, bytes_out, first_seen_days_ago
```

**Plausible expected result:** the same shape as the KQL block above, surfaced through Splunk's own field names.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, QRadar's Ariel Query Language, not standard SQL. QRadar's reference-set membership operators (`INSET`/`NOTINSET`) stand in for the lookup-table join the other languages use above.

CONCEPTUAL SAMPLE — illustrative AQL; validate field and reference-set names against your own QRadar deployment.

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS eventTime,
       sourceip, destinationip, "Total Bytes" AS totalBytes
FROM flows
WHERE "Total Bytes" >= 104857600
  AND destinationip NOTINSET 'known_destinations_refset'
LAST 24 HOURS
```

**Plausible expected result:** a small result set naming the source IP, destination IP, and total bytes for any flow clearing both conditions.

**Interpretation:** same read as above; how strong that read is depends heavily on how current `known_destinations_refset` actually is — a stale reference set makes every recently-added legitimate destination look "rare" again.

**[QUERY]** Google SecOps YARA-L against a UDM network-connection event. UDM has no native "first seen" field; the rarity check here assumes a separate entity-graph or risk-analytics enrichment step has already written it onto the event, the same dependency the KQL and SPL joins above carry explicitly.

```yaral
// CONCEPTUAL SAMPLE — UDM field names illustrative; the destination_first_seen field assumes an upstream enrichment step, not a native UDM attribute
rule oversized_session_to_rare_destination {
  meta:
    description = "Single network session exceeding a volume threshold to a first-seen external destination"
    severity = "High"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.network.sent_bytes >= 104857600
    $e.security_result.detection_fields["destination_first_seen"] = "true"
  condition:
    $e
}
```

**Plausible expected result:** one match per qualifying session, with `principal.hostname` and `target.ip` populated.

**Interpretation:** same read as above; validate that the enrichment step feeding `destination_first_seen` is actually running before trusting a quiet result as clean.

**[QUERY]** Elastic KQL, chosen as the single-event boolean surface per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — field and tag names approximate ECS; validate against your own index mapping.

```kql
network.bytes >= 104857600 and destination.ip : * and tags : "first_seen_destination"
```

**Plausible expected result:** the same shape as the other language blocks, surfaced through ECS's `source.ip`/`destination.ip` fields.

**Interpretation:** same read as above.

**[FALSE POSITIVE]** A genuinely new but fully authorized destination — a new backup target, a newly signed vendor integration, a media/CDN endpoint that only recently entered rotation — produces the exact same shape as a real exfiltration event: large, novel, one-off. Maintain the destination allowlist as a living, reviewed artifact rather than a set-once list, and treat "the destination review queue hasn't caught up yet" as a genuine operational lag to track, not noise to suppress by loosening the byte threshold.

**[PIVOT]** Check whether the same destination is also showing beacon-shaped connection-interval regularity (`QC-19` series, this book's C2 & Beaconing part) — a single large transfer to a destination that's also beaconing is a materially stronger finding than either alone. Also check `QC-20-02`: an attacker aware that single-session thresholds exist will often split one large transfer into several sessions that each individually clear this pattern's floor by design.

---

### QC-20-02 — Aggregate outbound volume exceeding a per-host rolling baseline

| Field | Value |
|---|---|
| **Pattern ID** | `QC-20-02` |
| **MITRE** | T1020 (Automated Exfiltration); the attacker-side technique this pattern exists to counter is T1030 (Data Transfer Size Limits) — deliberately staying under any single-event threshold. |
| **Behavior** | No single session is large enough to trip `QC-20-01`, but the total bytes a source host sends outbound, summed across many sessions over a rolling window, clears a level that host's own baseline doesn't support. |
| **DEH cross-ref** | DEH Part 14 §8, which names this shape directly as an open coverage gap: "close to blind to genuinely low-and-slow exfiltration that stays under the... threshold... neither of this part's two hunts targets that gap directly." This pattern is this book's answer to that named gap. DEH Part 31 (Baselining — the per-host rolling-volume baseline this pattern's threshold depends on). |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) — Sigma: `N/A` (aggregation ceiling, see note below) |

**[HUNTER]** Every standing volume rule has a floor set to control false positives, and a floor is exactly the number an attacker who's done any reconnaissance on your environment will estimate and stay under. This pattern widens the aggregation window instead of raising the floor — summing bytes per host over a full day or week, rather than any single session — the same move DEH Part 15 §9's own low-and-slow DNS-tunnel hunt makes for query volume instead of transfer bytes.

**[QUERY]** *Sigma — `N/A` — aggregation ceiling.* Sigma's correlation-rule spec defines four types (`event_count`, `value_count`, `temporal`, `temporal_ordered`, per DEH Appendix A5 §4); none of them sums a numeric field across matched events, only counts events or counts distinct values. The only Sigma-native approximation — an `event_count` correlation counting how many medium-volume sessions a host produces in a day — answers a different question than "how many bytes did this host send," the same species of gap `QC-03-01` names for Sigma's missing distinct-count type: a host sending many sessions just above a low per-session floor and a host sending fewer, much larger ones can trip the same session-count threshold for very different real totals. Publishing that count as if it were this pattern's byte-sum threshold would be a misleading translation, not a lossy one, so this pattern skips Sigma rather than force it.

**[QUERY]** Sentinel/Defender KQL against `DeviceNetworkEvents`, summing bytes per host over a daily bucket.

```kql
// CONCEPTUAL SAMPLE — bucket width and threshold illustrative; validate against your own per-host volume baseline before trusting this as a cutoff
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| summarize TotalBytesOut = sum(BytesSent) by DeviceName, bin(Timestamp, 1d)
| where TotalBytesOut >= 524288000
```

**Plausible expected result:** an empty result set on most days for most hosts; a hit names a device and a day with total outbound volume above roughly half a gigabyte.

**Interpretation:** consistent with sustained accumulation rather than a single burst — the fixed 1-day bin used here has the same boundary-splitting gap DEH Part 15 §4 names for its own fixed-window NXDOMAIN aggregation: a host that spreads its volume across two adjacent bins never trips either one alone.

**[QUERY]** Splunk SPL, using the `Network_Traffic` data model summed over a daily span.

CONCEPTUAL SAMPLE — bucket width and threshold illustrative; validate against your own per-host volume baseline before trusting this as a cutoff.

```spl
| tstats sum(All_Traffic.bytes_out) as total_bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_category=external by All_Traffic.src span=1d
| where total_bytes_out >= 524288000
```

**Plausible expected result:** the same shape as the KQL block above.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, not standard SQL. AQL's `GROUP BY`/`HAVING` combination expresses the sum-and-filter directly in one query — `HAVING` filters on the `totalBytesOut` alias rather than the raw `SUM(...)` expression, per IBM's only documented AQL `HAVING` pattern (IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5: https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html) — without needing QRadar's multi-object Building Block chain, since this is still a single aggregation, not a stateful multi-event sequence (DEH Part 27 §2–§3).

CONCEPTUAL SAMPLE — illustrative AQL; validate field and dataset names against your own QRadar deployment.

```sql
SELECT sourceip, SUM("Total Bytes") AS totalBytesOut
FROM flows
WHERE "Total Bytes" > 0
GROUP BY sourceip
HAVING totalBytesOut >= 524288000
LAST 1 DAYS
```

**Plausible expected result:** a short list of source IPs whose summed daily flow volume clears the floor.

**Interpretation:** same read as above.

**[QUERY]** Google SecOps YARA-L, using the `match`/`outcome` aggregation shape to sum bytes per host over a rolling window.

```yaral
// CONCEPTUAL SAMPLE — match/outcome aggregation syntax illustrative; validate against your own YARA-L ruleset version
rule aggregate_outbound_volume_exceeds_daily_floor {
  meta:
    description = "Per-host outbound byte volume, summed over a rolling day, exceeds a fixed floor"
    severity = "Medium"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.hostname = $hostname
  match:
    $hostname over 1d
  outcome:
    $total_bytes_out = sum($e.network.sent_bytes)
  condition:
    $total_bytes_out >= 524288000
}
```

**Plausible expected result:** one match per host-day that clears the floor, with `$total_bytes_out` carrying the summed figure.

**Interpretation:** same read as above.

**[QUERY]** Elastic ES\|QL, chosen because this pattern's shape is a threshold aggregation over a wide window, which ES\|QL's `STATS ... BY` bucketing fits directly per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — illustrative ES|QL; check your installed version's `STATS ... BY BUCKET(...)` syntax before use.

```esql
FROM logs-network*
| STATS total_bytes_out = SUM(network.bytes) BY host.name, BUCKET(@timestamp, 1d)
| WHERE total_bytes_out >= 524288000
```

**Plausible expected result:** the same shape as the KQL/SPL/AQL variants above.

**Interpretation:** same read as above; check your installed ES\|QL version's `STATS ... BY BUCKET(...)` syntax before use, since aggregation-with-bucketing syntax has changed across recent Elastic releases.

**[FALSE POSITIVE]** Legitimate bulk workloads — nightly backup jobs, code-deployment pipelines, large media-asset syncs, patch-mirror replication — produce exactly this shape: high daily volume, spread across many sessions, from one host. Cross-check any hit against a known-schedule allowlist (backup windows, deployment calendars) before escalating, and resist the temptation to raise the threshold instead of building that allowlist — a higher threshold just raises the bar for a patient attacker too.

**[PIVOT]** Pull the destination list for the flagged host's sessions across the window — a single destination receiving the bulk of the volume reads very differently from many small transfers to many destinations. Cross-reference `QC-20-01` for any single session in the same window that independently cleared that pattern's own floor, and check the host's process-creation history (DEH Part 11) for what initiated the transfers, since "which process" is usually the fastest way to separate a backup agent from something else.

> **Hunter's Note**
> If this pattern's daily bucket comes back clean but the behavior you're chasing feels real, widen the window before giving up — a host trickling data out at a rate tuned to stay under even this pattern's daily floor is the same move DEH Part 15 §9's low-and-slow DNS-tunnel hunt assumes an attacker will make. Rerun the same aggregation at 7 days and 30 days with the threshold scaled accordingly, and expect a real review queue, not a clean answer on the first pass.

**[SOC MANAGEMENT]** Lowering this pattern's daily floor to catch a slower drip multiplies false positives from legitimate bulk workloads roughly in proportion — the same tradeoff DEH Part 14 §8's own SOC Management View names for byte-ratio exfiltration rules generally. Treat any threshold change here as a deliberate, documented risk-acceptance decision, and treat "we've never graduated this hunt into a standing rule" as a legitimate state, not a gap to apologize for — the aggregate-volume shape's false-positive rate against real backup and deployment traffic is high enough that keeping this as a periodically-run hunt, reviewed by a human against a schedule calendar, is often the more honest choice than a standing alert nobody trusts.

---

### QC-20-03 — Exfiltration over ICMP via oversized echo payloads

| Field | Value |
|---|---|
| **Pattern ID** | `QC-20-03` |
| **MITRE** | T1048.003 (Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol) |
| **Behavior** | ICMP echo request/reply traffic carries a payload well above what a normal `ping` produces, consistent with data smuggled inside the packet's data field rather than the protocol's usual liveness-check padding. |
| **DEH cross-ref** | DEH Part 14 §8 (Data exfiltration signals — this pattern extends the volume framing there to a carrier protocol DET-14-06 itself doesn't cover) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** ICMP is rarely inspected for content, and most perimeter controls treat it as a diagnostic protocol to allow rather than a data channel to restrict — exactly why it's a durable exfiltration carrier once a host is compromised. A default Windows or Linux `ping` payload is a few dozen bytes; a payload consistently near or above the protocol's practical ceiling (roughly 1,472 bytes before IPv4 fragmentation on a standard MTU) on a host that shouldn't be running custom ICMP tooling at all is the shape this hunt looks for.

**[QUERY]** Sigma rule against a Zeek-normalized ICMP logsource, matching an oversized echo request or reply.

```yaml
# CONCEPTUAL SAMPLE — payload-length field illustrative for a Zeek/Suricata-normalized ICMP logsource
title: Oversized ICMP Echo Payload
status: experimental
logsource:
  category: network_connection
  product: zeek
detection:
  selection:
    proto: icmp
    icmp_type:
      - 8
      - 0
    payload_len|gte: 900
  condition: selection
falsepositives:
  - Path-MTU-discovery tooling or deliberate large-payload ping diagnostics run by network engineering
level: medium
```

**Plausible expected result:** near-zero background rate on most estates; a hit names a source/destination pair and a payload length well above ordinary ping traffic.

**Interpretation:** consistent with ICMP being used as a data channel rather than a liveness check — worth confirming the initiating process on the source host before treating it as a diagnostic tool run by a network engineer.

**[QUERY]** Sentinel/Defender KQL against a firewall/flow table carrying protocol and byte detail for ICMP traffic.

```kql
// CONCEPTUAL SAMPLE — table and field names illustrative; align with your own ICMP-capable firewall or flow-log ingestion
CommonSecurityLog
| where DeviceCustomString1 == "ICMP"
| where SentBytes + ReceivedBytes >= 900
| project TimeGenerated, SourceIP, DestinationIP, SentBytes, ReceivedBytes
```

**Plausible expected result:** the same sparse shape as the Sigma block, surfaced through Sentinel's own field names.

**Interpretation:** same read as above.

**[QUERY]** Splunk SPL against a Zeek ICMP log.

CONCEPTUAL SAMPLE — sourcetype and field names illustrative; map to your own Zeek/Corelight ingestion.

```spl
index=zeek sourcetype=zeek:icmp (icmp_type=8 OR icmp_type=0) payload_len>=900
| table _time, orig_h, resp_h, icmp_type, payload_len
```

**Plausible expected result:** the same shape as above.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, not standard SQL. QRadar's flow collectors generate flow records for ICMP the same way they do for TCP/UDP, keyed on `protocolid`.

CONCEPTUAL SAMPLE — illustrative AQL; validate field and dataset names against your own QRadar deployment.

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS eventTime,
       sourceip, destinationip, "Total Bytes" AS totalBytes
FROM flows
WHERE protocolid = 1
  AND "Total Bytes" >= 900
LAST 24 HOURS
```

**Plausible expected result:** the same sparse result set.

**Interpretation:** same read as above.

**[QUERY]** Google SecOps YARA-L against a UDM network-connection event. UDM's confirmed schema reliably exposes `ip_protocol` and aggregate `sent_bytes` for ICMP flows; per-packet payload length isn't modeled at the same granularity TCP/UDP gets in most parsers, so this rule keys on flow-level bytes rather than a single-packet payload field.

```yaral
// CONCEPTUAL SAMPLE — keys on flow-level bytes, not per-packet payload length; validate against your own parser's ICMP normalization
rule oversized_icmp_payload {
  meta:
    description = "ICMP flow with byte volume consistent with an oversized or padded echo payload"
    severity = "Medium"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.network.ip_protocol = "ICMP"
    $e.network.sent_bytes >= 900
  condition:
    $e
}
```

**Plausible expected result:** one match per qualifying flow.

**Interpretation:** same read as above; a genuinely single-packet-shaped hunt needs raw packet capture, not this flow-level approximation.

**[QUERY]** Elastic KQL, chosen as the single-event boolean surface.

CONCEPTUAL SAMPLE — field names approximate ECS `network.transport`/`network.bytes`; validate against your own index mapping.

```kql
network.transport : "icmp" and network.bytes >= 900
```

**Plausible expected result:** the same shape as the other language blocks.

**Interpretation:** same read as above.

**[FALSE POSITIVE]** Path-MTU-discovery tools and a handful of legitimate network-diagnostic utilities deliberately send large ICMP payloads to test fragmentation behavior — network engineering running one of these during a change window looks identical to this pattern's target. Cross-check the source host's role (a network appliance or engineer's workstation during a documented change is a very different finding than a file server or a user endpoint with no diagnostic mandate) rather than excluding by payload size alone.

**[PIVOT]** An attacker aware that a single oversized packet stands out can trivially split the payload across many packets, each individually under this pattern's floor — check total ICMP byte volume per source host over a rolling window (the same aggregation shape as `QC-20-02`, applied to ICMP specifically) if a single-packet hit doesn't surface anything. Also check whether the destination IP resolves to infrastructure with no legitimate reason to receive ICMP traffic from that host at all.

---

### QC-20-04 — Aggregate DNS byte volume as a bulk-exfiltration signal

| Field | Value |
|---|---|
| **Pattern ID** | `QC-20-04` |
| **MITRE** | T1048.003 (Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol) — DEH Part 44 §12 notes DNS-based exfiltration falls under this specific sub-technique because ATT&CK splits T1048's sub-techniques by encryption status, not by carrier protocol, and plaintext DNS has no dedicated sub-technique of its own. |
| **Behavior** | The total byte volume a source host moves through DNS query names and response payloads, summed over a rolling window, is high enough to be consistent with bulk data transfer — independent of whether any individual query looks like a tunnel by label shape or entropy. |
| **DEH cross-ref** | DEH Part 14 §10 and DEH Part 15's own stated scope (DNS tunnelling and domain-rarity scoring "owned exclusively by Part 15") — this pattern deliberately does not touch that ownership; DEH Part 15 §9 (DET-15-05, the composite tunnelling-signature score this pattern's hits pivot into rather than duplicate) |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) — Sigma: `N/A` (aggregation ceiling, see note below) |

**[HUNTER]** DET-15-05 in DEH Part 15 §9 is a signature detection: it looks at label length, entropy, and query-type skew to decide whether traffic *looks like* a tunnel. This pattern asks a cheaper, different question first — how much data actually moved through DNS from this host — because a channel can move a meaningful amount of data through DNS without ever tripping an entropy or label-length threshold, if the encoding is chosen carefully. A volume hit here is not a tunnel confirmation; it's a reason to run this book's Part 18 patterns (built on DET-15-05) against the same host next.

**[QUERY]** *Sigma — `N/A` — aggregation ceiling.* Same ceiling as `QC-20-02`: Sigma has no correlation type that sums a numeric field across matched events (DEH Appendix A5 §4), only `event_count` (matching events) and `value_count` (distinct values). Counting how many long-query-name events a host produces in a day is a different claim than summing the actual query-name byte volume every other language below computes — this pattern skips Sigma rather than publish that count as if it were the byte-sum signal the pattern is actually named for.

**[QUERY]** Sentinel/Defender KQL against `DnsEvents`, summing query-name length as a byte-volume proxy per host per day.

```kql
// CONCEPTUAL SAMPLE — assumes DnsEvents via the Azure Monitor Agent DNS analytics solution; validate table/field names against your own workspace
DnsEvents
| extend QueryLen = strlen(Name)
| summarize TotalQueryBytes = sum(QueryLen) by ClientIP, bin(TimeGenerated, 1d)
| where TotalQueryBytes >= 10485760
```

**Plausible expected result:** an empty result set on most days for most hosts; a hit names a client IP with a summed daily query-name volume above roughly 10 MB, which is high relative to typical per-host DNS query volume.

**Interpretation:** consistent with bulk data movement through the query-name channel specifically; this doesn't yet distinguish query-side from response-side encoding — see [FALSE POSITIVE] below.

**[QUERY]** Splunk SPL against a normalized DNS log.

CONCEPTUAL SAMPLE — index/sourcetype and field names illustrative; substitute your own DNS ingestion pipeline's schema.

```spl
index=dns
| eval query_len=len(query)
| bin _time span=1d
| stats sum(query_len) as total_query_bytes by src_ip, _time
| where total_query_bytes >= 10485760
```

**Plausible expected result:** the same shape as the KQL block above.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, not standard SQL.

CONCEPTUAL SAMPLE — illustrative AQL; confirm your QRadar DNS DSM actually normalizes a queryable `Query` field before use. `HAVING` filters on the `totalQueryBytes` alias, same documented pattern as the AQL query above.

```sql
SELECT sourceip, SUM(LENGTH("Query")) AS totalQueryBytes
FROM dns
GROUP BY sourceip
HAVING totalQueryBytes >= 10485760
LAST 1 DAYS
```

**Plausible expected result:** a short list of source IPs whose summed daily query-name length clears the floor.

**Interpretation:** same read as above; confirm your QRadar DNS DSM actually normalizes a queryable `Query` field before trusting a zero-row result as clean.

**[QUERY]** Google SecOps YARA-L, summing DNS query-name length per host over a rolling day.

```yaral
// CONCEPTUAL SAMPLE — match/outcome aggregation syntax illustrative
rule aggregate_dns_query_volume_exceeds_floor {
  meta:
    description = "Per-host DNS query-name byte volume, summed over a rolling day, exceeds a fixed floor"
    severity = "Medium"
  events:
    $e.metadata.event_type = "NETWORK_DNS"
    $e.principal.hostname = $hostname
  match:
    $hostname over 1d
  outcome:
    $total_query_bytes = sum(strlen($e.network.dns.questions.name))
  condition:
    $total_query_bytes >= 10485760
}
```

**Plausible expected result:** one match per host-day that clears the floor.

**Interpretation:** same read as above.

**[QUERY]** Elastic ES\|QL, chosen for the same threshold/wide-lookback reason as `QC-20-02`.

CONCEPTUAL SAMPLE — illustrative ES|QL; check your installed version's `STATS ... BY BUCKET(...)` syntax before use.

```esql
FROM logs-dns*
| EVAL query_len = LENGTH(dns.question.name)
| STATS total_query_bytes = SUM(query_len) BY host.name, BUCKET(@timestamp, 1d)
| WHERE total_query_bytes >= 10485760
```

**Plausible expected result:** the same shape as the other language blocks.

**Interpretation:** same read as above.

**[FALSE POSITIVE]** Legitimate services with high query-name entropy or length by design — CDN and cloud-service health checks, some anti-malware and EDR cloud-reputation lookups, and certain enterprise software's own telemetry beacons — routinely generate long or unusual query names at real volume, and this pattern's query-name-length proxy cannot distinguish that from an encoded payload without the entropy/label-shape scoring Part 18 owns. Treat a hit here as a scoping trigger for Part 18's signature patterns, not a standalone finding, and maintain an allowlist of known chatty legitimate services by apex domain to keep the daily review queue workable.

**[PIVOT]** Run this book's Part 18 patterns (built on DEH Part 15 §9's DET-15-05) against the flagged host next, to check whether the query shapes actually look like an encoded tunnel rather than merely being long. If Part 18's signature check comes back clean, check whether the volume is concentrated under one apex domain — a single destination receiving the bulk of unusually long queries is a stronger finding than volume spread across many legitimate-looking domains.

> **Blind Spot**
> Every query above depends on seeing the DNS transaction in plaintext. A host resolving over DoH or DoT sends its queries inside an HTTPS or TLS-wrapped channel that never touches the resolver this pattern's telemetry source is watching — DEH Part 15 §10 names this same blind spot for the tunnelling-signature side, and it applies identically here: this pattern goes quiet, not wrong, against a DoH/DoT-wrapped channel, and a quiet result from a host known to use a DoH-capable browser or OS setting should not be read as "clean."

---

## 2. Exfiltration to unsanctioned cloud storage

**[CONCEPT]** A cloud-storage destination is a distinct sub-shape from the volume and protocol patterns above: the signal isn't how much moved or which protocol carried it, but *where* it went — a personal Dropbox, a personal Google Drive, a non-corporate OneDrive tenant, or a file-sharing service the organization has never sanctioned. The behavior routes through ordinary HTTPS, at ordinary volumes, which is exactly why destination categorization rather than volume or protocol is this pattern's core signal.

### QC-20-05 — Upload to an unsanctioned personal cloud-storage destination

| Field | Value |
|---|---|
| **Pattern ID** | `QC-20-05` |
| **MITRE** | T1567.002 (Exfiltration to Cloud Storage) |
| **Behavior** | A host or SaaS session uploads data to a cloud-storage destination categorized as personal or otherwise unsanctioned — a consumer Dropbox/Drive/Mega/WeTransfer-class service, or a corporate-branded service under a tenant the organization doesn't own — rather than an approved corporate storage destination. |
| **DEH cross-ref** | DEH Part 19 §7 (Mass access and exfiltration from cloud data stores — the cloud control-plane side of the same general egress phenomenon this pattern detects from the network/proxy side; DEH Part 19 §7 and this book's own Part 25 own the account-sharing/IAM half, T1537, this pattern does not); DEH Part 44 §12 (Blind Spot — exfiltration blended into an already-authorized sync channel, directly the mechanism named in [FALSE POSITIVE] below) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Most CASB and proxy platforms already ship a "personal cloud storage" or "unsanctioned file sharing" category, and most standing rules on top of it already exclude sanctioned SaaS storage destinations by tenant ID. The hunt case is checking the boundary itself: destinations that are new enough not to be categorized yet, and — per [FALSE POSITIVE] below — activity inside a *sanctioned* tenant that a category-based rule will never flag at all.

**[QUERY]** Sigma rule against a proxy logsource, matching an upload-shaped request to a destination categorized as personal cloud storage.

```yaml
# CONCEPTUAL SAMPLE — category and byte-threshold values illustrative; align with your own CASB/proxy category taxonomy
title: Upload To Unsanctioned Personal Cloud Storage
status: experimental
logsource:
  category: proxy
detection:
  selection:
    dest_category: 'personal_cloud_storage'
    bytes_out|gte: 26214400
  condition: selection
falsepositives:
  - Personal, non-sensitive use of a permitted consumer storage service on a BYOD device, where policy tolerates the destination but not necessarily the volume
level: high
```

**Plausible expected result:** a hit names the source host or user, the destination domain, and an upload byte count above roughly 25 MB.

**Interpretation:** consistent with bulk data leaving through a personal storage account — how strong that read is depends on what was uploaded, which this query alone cannot see.

**[QUERY]** Sentinel/Defender KQL against `CloudAppEvents`, filtering on app category and upload volume.

```kql
// CONCEPTUAL SAMPLE — CloudAppEvents field names illustrative; align with your own Defender for Cloud Apps categorization
CloudAppEvents
| where ActionType == "FileUploaded"
| where AppName has_any ("Dropbox", "Google Drive", "WeTransfer", "Mega")
| where isnotempty(AccountObjectId) and AccountObjectId !in (KnownCorporateTenantIds)
| summarize TotalUploadBytes = sum(toint(RawEventData.FileSize)) by AccountDisplayName, DeviceName, AppName
| where TotalUploadBytes >= 26214400
```

**Plausible expected result:** sparse rows; each names the account, device, and app, with a total upload volume above the floor.

**Interpretation:** same read as above.

**[QUERY]** Splunk SPL against a proxy index, matching the same destination-category and volume conditions.

CONCEPTUAL SAMPLE — index/sourcetype and category field illustrative; align with your own CASB/proxy category taxonomy.

```spl
index=proxy sourcetype=proxy_access dest_category="personal_cloud_storage" bytes_out>=26214400
| table _time, user, src_ip, dest_domain, bytes_out
```

**Plausible expected result:** the same shape as the Sigma block above.

**Interpretation:** same read as above.

**[QUERY]** The following is AQL, not standard SQL, using a reference set of personal-storage domains for the category match.

CONCEPTUAL SAMPLE — illustrative AQL; validate field and reference-set names against your own QRadar deployment.

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS eventTime,
       username, "Destination Domain" AS destDomain, "Total Bytes" AS totalBytes
FROM events
WHERE "Destination Domain" INSET 'personal_cloud_storage_domains_refset'
  AND "Total Bytes" >= 26214400
LAST 24 HOURS
```

**Plausible expected result:** a small result set naming the acting user, destination domain, and upload volume.

**Interpretation:** same read as above; the finding is only as current as `personal_cloud_storage_domains_refset`'s own maintenance.

**[QUERY]** Google SecOps YARA-L against a UDM HTTP/network event, matching a target domain list.

```yaral
// CONCEPTUAL SAMPLE — UDM field names illustrative; the domain list assumes a maintained reference list resource
rule upload_to_unsanctioned_cloud_storage {
  meta:
    description = "Upload-shaped session to a domain categorized as personal cloud storage"
    severity = "High"
  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.target.url = /dropbox\.com|drive\.google\.com|wetransfer\.com|mega\.nz/i
    $e.network.sent_bytes >= 26214400
  condition:
    $e
}
```

**Plausible expected result:** one match per qualifying upload session.

**Interpretation:** same read as above; a maintained domain list is doing the categorization work here, not a native UDM category field.

**[QUERY]** Elastic KQL, chosen as the single-event boolean surface.

CONCEPTUAL SAMPLE — domain list and field names illustrative; validate against your own ECS mapping and current CASB category feed.

```kql
destination.domain : ("dropbox.com" or "drive.google.com" or "wetransfer.com" or "mega.nz") and network.bytes >= 26214400
```

**Plausible expected result:** the same shape as the other language blocks.

**Interpretation:** same read as above.

**[FALSE POSITIVE]** Where policy tolerates personal use of a consumer storage service on a BYOD device, ordinary non-sensitive personal use (photos, personal documents) produces the same shape as a real exfiltration event, distinguishable only by content classification this query alone doesn't have — pair a hit with DLP/CASB content-inspection results where available before escalating, rather than trying to raise the byte threshold high enough to filter out personal use, which just raises the bar for a deliberate exfiltration attempt too.

**[PIVOT]** Check whether the same account shows anomalous authentication (this book's Part 6, MFA Abuse & Authentication Anomalies) or unusual OAuth consent-grant activity (Part 24, Cloud Identity & SaaS Abuse) in the same window — a personal-storage upload following either is a materially stronger finding than the upload alone. Cross-reference `QC-20-01`/`QC-20-02` for volume corroboration outside this pattern's destination-specific view.

> **Blind Spot**
> Every query above keys on the destination being categorized as unsanctioned. DEH Part 44 §12 names the exact case this misses: an attacker abusing a compromised session inside the organization's *own sanctioned* storage tenant — uploading sensitive files to a personal folder within the org's own approved Google Workspace or OneDrive account rather than an external destination — produces traffic to a fully sanctioned domain at a volume already treated as baseline-normal by any volume-based rule too. Catching that case needs sensitivity-aware, content-classification-joined detection on the sanctioned channel itself, not a better domain list; this pattern does not close that gap.

---

## Cross-references

- DEH Part 14 §8 (Network Detection Engineering — Data exfiltration signals; DET-14-06) for the byte-ratio and rare-destination logic `QC-20-01` and `QC-20-02` adapt, and for the named low-and-slow coverage gap `QC-20-02` targets directly.
- DEH Part 15 §9–§10 (DNS Detection Engineering — DET-15-05's composite tunnelling score, and the DoH/DoT blind spot) for the exclusive tunnelling-signature ownership `QC-20-04` deliberately does not duplicate.
- DEH Part 19 §7 (Cloud Infrastructure Detection Engineering — mass access and exfiltration from cloud data stores) for the control-plane side of the same phenomenon `QC-20-05` detects from the network/proxy side.
- DEH Part 31 (Baselining) for the per-host, per-destination baseline every rarity and rolling-volume threshold in this part depends on without re-deriving.
- DEH Part 44 §12 (Adversary Behaviour for Defenders — the Exfiltration tactic stage) for the ATT&CK sub-technique mapping this part relies on and for the authorized-sync-channel blind spot named in `QC-20-05`.
- DEH Parts 23–29 and Appendix A5 for the Sigma/KQL/SPL/AQL/YARA-L/EQL/ES\|QL syntax fundamentals this part assumes rather than teaches.
- DEH Parts 41–43 and this book's own Part 28 for how these five patterns would be scored on the Detection Coverage/Quality/Debt scales rather than this part inventing its own scoring.
- This book's Part 18 (Suspicious DNS), Part 19 (C2 & Beaconing Detection), Part 21 (Insider Threat & Data Staging), and Parts 25–26 (Cloud Infrastructure Abuse; Cloud-Native Lateral Movement) for the explicit scope boundaries stated in "Why this part exists" above.
- This book's Part 27 (Multi-Behavior Hunt Chains) as a likely destination for a chain citing `QC-20-01` through `QC-20-05` alongside earlier-stage patterns from Parts 21 and 22.
