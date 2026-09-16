---
title: "Suspicious DNS"
part: 18
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 18 — Suspicious DNS

## Why this part exists

**[CONCEPT]** DNS is almost always allowed outbound without deep inspection, resolved before most endpoint controls ever see a connection, and rarely retained at the same fidelity or duration as process or network-flow telemetry. That combination makes it one of the cheapest covert channels available to an attacker and one of the most argued-over telemetry sources in a SOC — a hunter who only waits on a standing DNS detection is trusting a control that was built against yesterday's tunnelling tool, not today's. This part covers five behavior patterns that recur across nearly every DNS-based attacker use case: tunnelling a channel through the query stream itself, generating candidate command-and-control (C2) domains algorithmically, resolving a domain nobody in the environment has ever queried before, failing to resolve dozens of candidate names in a burst, and resolving over an encrypted transport that bypasses on-network DNS logging entirely.

This part owns DNS-tunnelling detection logic exclusively, mirroring DEH Part 15's own exclusive ownership of DNS telemetry mechanics — no other part in this book re-derives it. Three explicit boundaries keep that ownership from silently overlapping a neighboring part:

- **Against Part 3 (Scanning & Enumeration):** internal zone or subdomain brute-forcing (`dnsrecon`, `massdns`-style wordlist enumeration against an internal zone) shows up as a burst of failed resolutions against many candidate names from one source — that shape is `QC-18-04` below, not Part 3's scope, even though the attacker's *goal* is enumeration.
- **Against Part 19 (C2 & Beaconing Detection):** Part 19 explicitly excludes DNS-tunnelling logic and owns every other C2 transport (HTTP/HTTPS beacons, JA3/TLS-fingerprint pivoting, domain fronting). A DNS tunnel is a beacon in the general sense, but its detection logic — query-shape and query-volume statistics, not connection interval regularity — belongs here.
- **Against Part 20 (Exfiltration):** Part 20 covers "exfiltration over an alternate protocol (DNS/ICMP)" from the data-loss-triage side — how much left, to where, and how that gets scoped once a channel is suspected. This part owns the detection logic that first reveals a DNS channel exists (`QC-18-01`). A hit here is the trigger to open a Part 20 investigation, not a restatement of it.

This part does not teach Sigma correlation syntax, KQL join semantics, or QRadar's Ariel Query Language from first principles — see DEH Parts 23–29 and DEH Appendix A5 for that. It does not score these patterns' coverage, quality, or debt against a standing detection program either — see DEH Parts 41–43, applied to this book's own catalog in Part 28.

The table below is a navigation aid only; Appendix A1 is the canonical, position-independent index.

| Pattern ID | Name | MITRE |
|---|---|---|
| `QC-18-01` | DNS tunnelling via high-volume, oversized-label queries to one apex domain | T1071.004 |
| `QC-18-02` | DGA-shaped domain generation | T1568.002 |
| `QC-18-03` | Rare / first-seen apex domain | No clean single-technique mapping |
| `QC-18-04` | NXDOMAIN burst from a single source | T1568.002 |
| `QC-18-05` | DNS-over-HTTPS/DoT to an unsanctioned resolver | T1071.004 |

---

### QC-18-01 — DNS tunnelling via high-volume, oversized-label queries to one apex domain

| Field | Value |
|---|---|
| **Pattern ID** | `QC-18-01` |
| **MITRE** | T1071.004 (Application Layer Protocol: DNS) |
| **Behavior** | One internal source issues an abnormally high rate of queries, with abnormally long or high-cardinality subdomain labels, against a single attacker-controlled apex domain — the query stream itself carries the payload. |
| **DEH cross-ref** | DEH Part 15 §2 (DNS Detection Engineering — tunnelling signatures); DEH Part 40 (seeded teardown: "long DNS label = tunnel") |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL — aggregation/threshold shape, per DEH Appendix A5 §8's decision table) |

**[HUNTER]** Tunnelling tools (`iodine`, `dnscat2`, Cobalt Strike's DNS beacon) chunk payload across many subdomain labels under one domain the attacker controls, because the protocol's own design — attacker-owned authoritative nameserver, arbitrary label content, near-universal outbound allow — is the point, not a bug they're exploiting. A tunnel is built to look like ordinary allowed DNS, so it slips past detections tuned to obvious payload markers; a periodic volume/shape aggregation hunt catches the channel even where nothing fired.

**[QUERY] Sigma** — a correlation rule (Sigma's 2024 correlation spec) over a base DNS-query selection, aggregating count by source within a rolling window; targets any backend with correlation-rule support.

```yaml
title: DNS Query Base
name: dns_query_base
logsource:
  category: dns_query
  product: zeek
detection:
  selection:
    query|endswith: '.'
  condition: selection
---
title: High-Volume DNS Queries to a Single Apex Domain
correlation:
  type: event_count
  rules:
    - dns_query_base
  group-by:
    - source.ip
    - dns.apex_domain
  timespan: 15m
  condition:
    gte: 200
```
CONCEPTUAL SAMPLE — correlation-rule syntax and the `dns.apex_domain` derived field are illustrative; confirm your backend implements Sigma correlation rules before relying on this shape.

Expected result: a handful of source IP/apex-domain pairs per day crossing 200+ queries in 15 minutes, almost always either a genuine tunnel or one of the FP drivers below. Interpretation: a sustained hit against a domain with no legitimate business reason to receive this volume is consistent with an active tunnel session, not proof of one.

**[QUERY] KQL (Sentinel/Defender)** — Azure DNS Analytics' `DnsEvents` table, aggregating query count and average label length per client over a 15-minute bin.

```kql
DnsEvents
| where TimeGenerated > ago(1h)
| extend ApexDomain = tostring(extract(@"([^.]+\.[^.]+)$", 1, Name))
| summarize QueryCount = count(),
            AvgLabelLen = avg(strlen(Name)),
            DistinctLabels = dcount(Name)
      by ClientIP, ApexDomain, bin(TimeGenerated, 15m)
| where QueryCount >= 200 and AvgLabelLen >= 40
| order by QueryCount desc
```
CONCEPTUAL SAMPLE — table name, field names, and thresholds illustrative; on Defender-only tenants without Azure DNS Analytics, substitute `DeviceEvents` filtered to `ActionType == "DnsQueryResponse"` and validate the equivalent fields exist in `AdditionalFields`.

Expected result: a client/apex-domain pair with several hundred queries and an average label length well above typical hostname length (most legitimate FQDNs sit under 30 characters end to end). Interpretation: high volume plus oversized labels together are the tunnel-shaped signal — either alone is common and not worth escalating on its own.

**[QUERY] SPL** — Splunk's Network Resolution (DNS) CIM data model, aggregated per source and apex domain over a 15-minute span.

```spl
| tstats count as query_count, avg(eval(len(query))) as avg_label_len
    from datamodel=Network_Resolution.DNS
    where DNS.message_type=QUERY
    by DNS.src, DNS.query, _time span=15m
| eval apex_domain=replace(DNS.query, "^.*?([^.]+\.[^.]+)$", "\1")
| stats sum(query_count) as total_queries, avg(avg_label_len) as avg_label_len,
        dc(DNS.query) as distinct_labels by DNS.src, apex_domain
| where total_queries >= 200 AND avg_label_len >= 40
```
CONCEPTUAL SAMPLE — assumes the Network Resolution data model is accelerated over your DNS index; thresholds illustrative.

Expected result: comparable output shape to the KQL block — one row per source/apex-domain pair with total query count, average label length, and distinct-label count. Interpretation: the same as the KQL block; a large `distinct_labels` count with low query repetition additionally suggests base32/base64-style chunking rather than simple retry traffic.

**[QUERY] AQL (QRadar)** — this is AQL, not standard SQL, run against events from a DNS log source, aggregating by source IP within a 15-minute search window. `HAVING` filters on the `query_count`/`avg_label_len` aliases rather than the raw aggregate expressions, per IBM's only documented AQL `HAVING` pattern (IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5: https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html).

```sql
SELECT sourceip AS src_ip,
       COUNT(*) AS query_count,
       AVG(LENGTH("DNS Query Name")) AS avg_label_len,
       UNIQUECOUNT("DNS Query Name") AS distinct_labels
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%DNS%'
GROUP BY sourceip
HAVING query_count >= 200 AND avg_label_len >= 40
LAST 15 MINUTES
```
CONCEPTUAL SAMPLE — `"DNS Query Name"` is a placeholder for whatever custom event property your DSM maps the query name to; this aggregates per source IP only, since AQL's string functions don't cleanly extract an apex domain from an arbitrary FQDN in one pass — group by apex domain in a second pass once a source is flagged.

Expected result: same shape, coarser grain — a source IP with high aggregate query count and average label length across all domains it queried in the window, not isolated to one apex domain yet. Interpretation: treat a hit here as "investigate this source's domain list," not "this domain is the tunnel," until you've pivoted to isolate the apex domain.

**[QUERY] YARA-L (Google SecOps)** — a UDM `NETWORK_DNS` match aggregating query count and average label length per source IP over a 15-minute window.

```yaral
rule dns_tunneling_high_volume_large_label {
  meta:
    description = "High query volume and oversized labels to one apex domain"
    severity = "MEDIUM"

  events:
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.principal.ip = $ip
    $dns.network.dns.questions.name = $qname

  match:
    $ip over 15m

  outcome:
    $query_count = count($qname)
    $avg_label_len = math.mean(strings.length($qname))

  condition:
    $dns and $query_count >= 200 and $avg_label_len >= 40
}
```
CONCEPTUAL SAMPLE — the `math.mean`/`strings.length` outcome functions and the exact aggregation syntax are illustrative; confirm the equivalent functions in your SecOps instance's YARA-L version.

Expected result: one detection per source IP per 15-minute window meeting both thresholds. Interpretation: identical to the KQL/SPL reading above.

**[QUERY] Elastic (ES\|QL)** — chosen over EQL because this is a threshold/aggregation shape, not an ordered sequence (DEH Appendix A5 §8); queries a `dns-*` data view.

```esql
FROM dns-*
| WHERE @timestamp > NOW() - 15 minutes
| EVAL label_len = LENGTH(dns.question.name)
| STATS query_count = COUNT(*),
        avg_label_len = AVG(label_len),
        distinct_labels = COUNT_DISTINCT(dns.question.name)
    BY source.ip
| WHERE query_count >= 200 AND avg_label_len >= 40
```
CONCEPTUAL SAMPLE — field/index names illustrative; validate against your own ECS DNS field mapping.

Expected result and interpretation: identical shape and reading to the KQL/SPL blocks above.

**[FALSE POSITIVE]** Legitimate services routinely produce high volume and long labels: CDN/cloud anycast health-check and latency-probe subdomains, mobile push-notification services (APNs/FCM) that embed long device-token-shaped strings in hostnames, and mail gateways performing SPF/DKIM/DMARC verification, which can issue dozens of TXT lookups per inbound message against many different sender domains in a burst. A naive "200 queries in 15 minutes" threshold catches a busy mail gateway doing legitimate verification lookups as readily as a tunnel. The fix is an apex-domain allowlist for known CDN/push/mail-security infrastructure plus a distinct-apex-domain-count filter — a mail gateway's high volume spreads across many legitimate apex domains, while a tunnel concentrates volume against one.

> **Detection Autopsy — "long DNS label = tunnel"**
>
> **The rule:** Fires on any single DNS query where the queried name exceeds a fixed character-length threshold (commonly 50–63 characters, the DNS label-length ceiling).
>
> **Why it shipped:** Tunnelling tools do encode payload into long labels, and a single-field length check is a one-line rule — cheap to write, easy to demo in a proof-of-concept.
>
> **How it failed:** Legitimate long labels are everywhere once you look — DKIM `_domainkey` selectors, S3 virtual-hosted bucket names, Kubernetes pod-generated internal names, and CDN cache-key subdomains routinely exceed the threshold, so the rule pages constantly on infrastructure nobody would call a tunnel.
>
> **The fix:** Require sustained volume and label size together against one apex domain, per `QC-18-01` above, instead of a single long label anywhere in the stream — see DEH Part 40 for the full teardown of this exact naive rule.

**[PIVOT]** Check the TXT/NULL-record ratio for the flagged apex domain — tunnelling tools disproportionately use TXT or NULL record types over A/AAAA. Check the apex domain's registration age and passive-DNS history (`QC-18-03` below covers the rare/first-seen angle directly). On the source host, pull the process that issued the queries via Sysmon Event ID 22 (DNS query) if available — a browser or update agent issuing this volume is a different investigation than an unsigned binary in a temp directory.

**[SOC MANAGEMENT]** This hunt is cheap to run and expensive to ignore: outbound DNS is rarely restricted, so a tunnel can run indefinitely once established. Run it at least weekly against egress-unrestricted network segments, daily if your environment has no forced internal resolver. Once you've built a stable allowlist of legitimate high-volume services (usually under two dozen apex domains in a mid-size environment), consider graduating the aggregation query to a standing correlation rule — the false-positive cost drops sharply once the allowlist stabilizes, which is the point at which a hunt earns its way into a detection.

---

### QC-18-02 — DGA-shaped domain generation

| Field | Value |
|---|---|
| **Pattern ID** | `QC-18-02` |
| **MITRE** | T1568.002 (Dynamic Resolution: Domain Generation Algorithms) |
| **Behavior** | A host resolves a sequence of short-lived, linguistically implausible hostnames — high digit density, long consonant runs, no recognizable word fragments — consistent with a domain generation algorithm (DGA) cycling through candidate C2 domains rather than a human-typed or application-configured name. |
| **DEH cross-ref** | DEH Part 15 §3 (DGA / algorithmic-domain detection); DEH Part 31 (Baselining) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL — single-event boolean match, per DEH Appendix A5 §8) |

**[CONCEPT]** A DGA embeds a seed — the date, a hardcoded value, sometimes both — into an algorithm that generates hundreds or thousands of candidate domain names per day; the malware's operator registers only a handful, so a defender who watches the full candidate stream sees mostly failed resolutions (`QC-18-04`) with an occasional live hit. This is a genuinely different query shape from `QC-18-01`'s tunnelling signature: DGA detection classifies one hostname's *naming pattern* at a time rather than aggregating volume against one apex domain.

**[HUNTER]** True Shannon-entropy scoring is a computation most query languages don't do natively — it needs a loop over characters that SQL-shaped and pipe-shaped query languages weren't built for. The queries below approximate high-entropy naming with proxy heuristics every listed language *can* compute natively: label length, digit density, and long consonant runs (no vowel for six or more consecutive characters). Treat a hit as a candidate for a closer look, not a scored entropy value — if your pipeline already enriches DNS logs with a real entropy score upstream (an ingest-time function or ML model), filter on that field directly instead.

**[QUERY] Sigma** — a single-event rule against DNS query logs, using the length/digit/consonant-run heuristics as the detection.

```yaml
title: Algorithmically-Generated-Looking DNS Query Name (Heuristic)
logsource:
  category: dns_query
  product: zeek
detection:
  selection:
    query|re: '^[a-z0-9]{16,}\.'
  digit_heavy:
    query|re: '^[a-z]*[0-9]{5,}[a-z0-9]*\.'
  consonant_run:
    query|re: '[bcdfghjklmnpqrstvwxyz]{6,}'
  condition: selection and (digit_heavy or consonant_run)
```
CONCEPTUAL SAMPLE — regex heuristics illustrative; tune the thresholds against your own environment's naming conventions before trusting the cutoffs.

Expected result: a small trickle of matches daily even in a clean environment (see False Positive Trap below), and a distinct burst — many different labels, same source, short window — when malware is actively cycling candidates. Interpretation: an isolated match is weak signal; a burst from one source is the pattern worth escalating, and usually co-occurs with `QC-18-04`.

**[QUERY] KQL (Sentinel/Defender)** — computes the same heuristics inline against `DnsEvents`.

```kql
DnsEvents
| where TimeGenerated > ago(1h)
| extend Label = tostring(split(Name, ".")[0])
| extend LabelLen = strlen(Label)
| extend DigitCount = strlen(replace_regex(Label, @"[^0-9]", ""))
| extend DigitRatio = todouble(DigitCount) / LabelLen
| where LabelLen >= 16
    and (DigitRatio >= 0.3 or Label matches regex @"[bcdfghjklmnpqrstvwxyz]{6,}")
| project TimeGenerated, ClientIP, Name, LabelLen, DigitRatio
```
CONCEPTUAL SAMPLE — thresholds illustrative; validate `DigitRatio` distribution against your own baseline before treating 0.3 as a real cutoff.

Expected result and interpretation: same as the Sigma block above.

**[QUERY] SPL** — computes label length, digit ratio, and consonant-run as `eval` fields against a DNS-sourced index.

```spl
index=dns sourcetype=dns_resolution
| eval label=mvindex(split(query, "."), 0)
| eval label_len=len(label)
| eval digit_count=len(replace(label, "[^0-9]", ""))
| eval digit_ratio=if(label_len>0, digit_count/label_len, 0)
| eval consonant_run=if(match(label, "[bcdfghjklmnpqrstvwxyz]{6,}"), 1, 0)
| where label_len >= 16 AND (digit_ratio >= 0.3 OR consonant_run=1)
| stats count by src, query
```
CONCEPTUAL SAMPLE — field names illustrative.

Expected result and interpretation: same as above.

**[QUERY] AQL (QRadar)** — this is AQL, not standard SQL; applies the digit-density and consonant-run checks via `REGEXP`.

```sql
SELECT sourceip AS src_ip,
       "DNS Query Name" AS qname,
       LENGTH("DNS Query Name") AS label_len
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%DNS%'
  AND LENGTH("DNS Query Name") >= 16
  AND ("DNS Query Name" REGEXP '[0-9]{5,}'
       OR "DNS Query Name" REGEXP '[bcdfghjklmnpqrstvwxyz]{6,}')
LAST 1 HOURS
```
CONCEPTUAL SAMPLE — `"DNS Query Name"` placeholder as in `QC-18-01`.

Expected result and interpretation: same as above.

**[QUERY] YARA-L (Google SecOps)** — a UDM `NETWORK_DNS` single-event match using the same regex heuristics.

```yaral
rule dga_shaped_dns_query_heuristic {
  meta:
    description = "High digit density or long consonant run in query label (DGA proxy heuristic)"
    severity = "LOW"

  events:
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.network.dns.questions.name = $qname
    re.regex($qname, `[0-9]{5,}`) or re.regex($qname, `[bcdfghjklmnpqrstvwxyz]{6,}`)

  condition:
    $dns
}
```
CONCEPTUAL SAMPLE — `re.regex` function name illustrative for your YARA-L version.

Expected result and interpretation: same as above.

**[QUERY] Elastic (KQL)** — a single-event boolean match, the cheapest Elastic surface for this shape (DEH Appendix A5 §8).

```kql
dns.question.name : /[a-z0-9]{16,}\..*/ and (dns.question.name : /[0-9]{5,}/ or dns.question.name : /[bcdfghjklmnpqrstvwxyz]{6,}/)
```
CONCEPTUAL SAMPLE — regex-in-KQL syntax illustrative; confirm your Elastic version supports inline regex in this field.

Expected result and interpretation: same as above.

**[FALSE POSITIVE]** Cloud and CDN infrastructure auto-generates hostnames that score identically to DGA output on length/digit/consonant heuristics alone: S3 virtual-hosted bucket names, Azure Blob Storage account subdomains, Kubernetes-generated pod hostnames, and ad-tech/analytics tracking domains all commonly contain long alphanumeric strings with no linguistic structure. A heuristic-only approach without a reputation or age check will flag your own cloud infrastructure daily. Fold in domain age (a bucket subdomain resolves under a long-established, well-known parent domain; a DGA candidate resolves under a domain registered days ago) rather than trying to tighten the heuristic thresholds further — tighter thresholds mostly just miss real DGA output instead of fixing this.

**[PIVOT]** Check the flagged apex domain's registration age and passive-DNS history. Correlate against `QC-18-04` — most DGA output produces a high ratio of NXDOMAIN responses with only rare successful resolutions, so a source matching this pattern with several NXDOMAIN hits nearby strengthens the read. Pull the requesting process on the source host; DGA-driven resolution is almost always issued by the malware's own process, not a browser or system service.

---

### QC-18-03 — Rare / first-seen apex domain

| Field | Value |
|---|---|
| **Pattern ID** | `QC-18-03` |
| **MITRE** | No clean single-technique mapping — see [HUNTER] framing |
| **Behavior** | A source resolves an apex domain that has never appeared anywhere in the organization's historical DNS telemetry, or appears for the first time across the entire environment within the current hunt window. |
| **DEH cross-ref** | DEH Part 15 §4 (rare-domain / baselining approach); DEH Part 31 (Baselining) |
| **Languages covered** | Sigma: `N/A`, see below; KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL — wide-lookback shape, per DEH Appendix A5 §8) |

**[HUNTER]** "Rare domain" is a generic anomaly method, not a single attacker technique — it surfaces C2 infrastructure (T1071.004), DNS-based exfiltration staging, and fresh phishing-kit domains about equally well, which is exactly why it doesn't get one clean MITRE mapping here; T1071.004 is the most common single technique behind a true positive, stated in prose rather than forced into the header table. The value of this hunt is that it needs no prior knowledge of the specific tool or campaign — it just needs a trailing baseline long enough that "first seen" means something.

**Sigma — N/A (no first-seen/new-term primitive).** The SigmaHQ Correlation Rules Specification defines exactly seven correlation types — `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, and `value_percentile` (SigmaHQ, "Sigma Correlation Rules Specification," v2.1.0: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md) — and none of them expresses "this value hasn't been seen before within a baseline window." A first-seen check needs a maintained historical baseline external to any single rule evaluation; that baseline gets consumed by a plain selection rule doing an anti-join against it — the same shape the KQL/SPL/AQL/ES|QL implementations below use — not by a Sigma correlation type.

**[QUERY] KQL (Sentinel/Defender)** — anti-joins today's apex domains against a 90-day trailing baseline.

```kql
let Baseline = DnsEvents
| where TimeGenerated between (ago(91d) .. ago(1d))
| summarize FirstSeenBaseline = min(TimeGenerated)
      by ApexDomain = tostring(extract(@"([^.]+\.[^.]+)$", 1, Name));
DnsEvents
| where TimeGenerated > ago(1d)
| extend ApexDomain = tostring(extract(@"([^.]+\.[^.]+)$", 1, Name))
| join kind=leftanti Baseline on ApexDomain
| summarize FirstSeenToday = min(TimeGenerated), QueryCount = count() by ClientIP, ApexDomain
```
CONCEPTUAL SAMPLE — the 90-day window is illustrative; a domain your organization visits quarterly will false-positive against a 90-day baseline every time, see [FALSE POSITIVE].

Expected result: a handful of genuinely new apex domains per host per day in most environments, spiking on days with new SaaS rollouts; KQL's anti-join makes the "never seen in the baseline window" logic explicit. Interpretation: a first-seen hit is a weak, high-recall signal by itself — consistent with anything from a new vendor to a new C2 domain, not diagnostic of either.

**[QUERY] SPL** — filters today's distinct apex domains against a lookup table maintained by a scheduled baseline-refresh search.

```spl
| tstats earliest(_time) as first_seen, count as query_count
    from datamodel=Network_Resolution.DNS
    where DNS.message_type=QUERY by DNS.src, DNS.query
| eval apex_domain=replace(DNS.query, "^.*?([^.]+\.[^.]+)$", "\1")
| lookup domain_baseline_90d apex_domain AS apex_domain OUTPUT seen_before
| where isnull(seen_before)
```
CONCEPTUAL SAMPLE — assumes a separately scheduled search populates `domain_baseline_90d`; SPL has no native cross-search state, so the baseline lookup is its own maintained artifact, not part of this one query.

Expected result and interpretation: as above.

**[QUERY] AQL (QRadar)** — investigative form only. This is AQL, not standard SQL; it approximates "first seen" within a single search rather than persisting state across searches. `HAVING` filters on the `first_seen` alias rather than the raw `MIN(devicetime)` expression, per IBM's documented AQL `HAVING` pattern (same citation as above).

```sql
SELECT "DNS Query Name" AS qname, MIN(devicetime) AS first_seen
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%DNS%'
GROUP BY "DNS Query Name"
HAVING first_seen > (NOW() - 86400000)
LAST 90 DAYS
```
CONCEPTUAL SAMPLE — validates whether a domain's *only* appearance in a 90-day AQL search window falls within the last 24 hours, which approximates first-seen without persisted state. A standing detection needs QRadar's multi-object model — a Reference Set of previously seen apex domains, updated nightly by a Building Block, with the rule then checking new queries against the set (DEH Part 27 §2–3) — rather than a single AQL search re-scanning 90 days on every run.

Expected result and interpretation: as above, with the caveat that this form is a validation query, not the production detection shape.

**[QUERY] YARA-L (Google SecOps)** — references a domain-prevalence context enrichment; field name unconfirmed.

```yaral
rule first_seen_apex_domain_90d {
  meta:
    description = "Apex domain absent from prevalence context for 90 days"
    severity = "LOW"

  events:
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.network.dns.questions.name = $qname
    $dns.principal.ip = $ip
    // Illustrative -- confirm the equivalent first-seen/prevalence enrichment
    // field name in your own instance before relying on this exact path.
    $context.domain.prevalence.first_seen_timestamp > timestamp.current_time() - 90d

  match:
    $ip over 1d

  condition:
    $dns
}
```
CONCEPTUAL SAMPLE — the `$context.domain.prevalence` field path is a placeholder; Google SecOps' actual domain-prevalence context enrichment field is unconfirmed at time of writing (missing schema field caveat, not a full `N/A` since the underlying mechanism — reference lists / context enrichment — does exist).

Expected result and interpretation: as above.

**[QUERY] Elastic (ES\|QL)** — a wide-lookback shape, the ES\|QL use case per DEH Appendix A5 §8.

```esql
FROM dns-*
| STATS first_seen = MIN(@timestamp) BY dns.question.name
| WHERE first_seen > NOW() - 1 day
```
CONCEPTUAL SAMPLE — a real implementation needs the underlying `dns-*` data view to actually retain 90 days of history at query time, or this reduces to "first seen within whatever retention window the index covers," not a true 90-day baseline; validate retention before trusting the result.

Expected result and interpretation: as above.

**[FALSE POSITIVE]** New SaaS rollouts, vendor onboarding, and seasonal applications (tax software every spring, an open-enrollment benefits portal every fall) all produce a burst of genuinely new apex domains resolved by dozens of employees the same day — indistinguishable from a simultaneous multi-target phishing campaign using freshly registered domains, by this pattern alone. The fix is not a longer baseline window (a six-month-old legitimate vendor domain a business unit visits quarterly will still trip a 90-day window every quarter) but corroboration: pair a first-seen hit with domain age, request volume shape (one employee vs. forty in the same hour), and reputation before treating it as more than a lead.

> **Blind Spot**
> "First seen in your environment" and "newly registered" are different facts, and this pattern only proves the first one. A domain registered eighteen months ago and reused across many unrelated campaigns — bulletproof hosting, compromised legitimate sites, shared CDN/cloud infrastructure — looks identical to a brand-new phishing domain under a pure first-seen lens. Pair this pattern with a domain-age/registration lookup or a passive-DNS reputation source before treating "rare here" as "rare anywhere."

**[PIVOT]** Look up the apex domain's registration date and passive-DNS history against a threat-intel or passive-DNS provider. Check whether the requesting host is also flagged by `QC-18-02`'s heuristic — a first-seen domain that also scores as algorithmically named is a much stronger combined signal than either alone. Check request volume shape: one host versus many hosts resolving the same new domain in the same window points toward different explanations (targeted implant vs. organization-wide new vendor).

---

### QC-18-04 — NXDOMAIN burst from a single source

| Field | Value |
|---|---|
| **Pattern ID** | `QC-18-04` |
| **MITRE** | T1568.002 (Dynamic Resolution: Domain Generation Algorithms) |
| **Behavior** | One source produces a high rate of NXDOMAIN (non-existent domain) responses across many distinct candidate names in a short window, rather than sustained volume against one live, resolving domain. |
| **DEH cross-ref** | DEH Part 15 §5 (NXDOMAIN / resolution-failure patterns); DEH Part 40 (naive fixed-threshold framing applies to this shape too) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL — aggregation/threshold shape) |

**[HUNTER]** A DGA that generates a thousand candidate domains a day and gets one or two registered produces, for a defender watching resolution outcomes, a burst of failures with an occasional live hit buried in it — the failure burst is often the more reliable signal to hunt because it doesn't depend on catching the rare successful resolution. This is also the shape internal DNS zone/subdomain brute-forcing produces (`dnsrecon`, `massdns`), which is why Part 3 explicitly hands this specific enumeration form to this part instead of covering it itself.

**[QUERY] Sigma** — a correlation rule over an NXDOMAIN-filtered base selection, aggregating count by source within a 5-minute window.

```yaml
title: NXDOMAIN Response Base
name: nxdomain_response_base
logsource:
  category: dns_query
  product: zeek
detection:
  selection:
    rcode: 'NXDOMAIN'
  condition: selection
---
title: NXDOMAIN Burst From a Single Source
correlation:
  type: event_count
  rules:
    - nxdomain_response_base
  group-by:
    - source.ip
  timespan: 5m
  condition:
    gte: 50
```
CONCEPTUAL SAMPLE — threshold illustrative.

Expected result: a source crossing 50 distinct-name NXDOMAIN responses in five minutes, which is well outside normal typo/retry behavior for a single user. Interpretation: consistent with a DGA cycling through unregistered candidates or an internal zone-enumeration tool; not distinguishable between the two without pivoting.

**[QUERY] KQL (Sentinel/Defender)** — aggregates NXDOMAIN responses per client over a 5-minute bin.

```kql
DnsEvents
| where TimeGenerated > ago(5m)
| where ResponseCode == "NXDOMAIN" or QueryStatus == "NXDOMAIN"
| summarize NxCount = count(), DistinctNames = dcount(Name) by ClientIP, bin(TimeGenerated, 5m)
| where NxCount >= 50
```
CONCEPTUAL SAMPLE — field name for the response-code column depends on your DNS Analytics schema version; illustrative.

Expected result and interpretation: as above.

**[QUERY] SPL** — filters to NXDOMAIN responses and aggregates by source over a 5-minute bucket.

```spl
index=dns sourcetype=dns_resolution reply_code=NXDOMAIN
| bucket _time span=5m
| stats count as nx_count, dc(query) as distinct_names by src, _time
| where nx_count >= 50
```
CONCEPTUAL SAMPLE — CIM field names illustrative.

Expected result and interpretation: as above.

**[QUERY] AQL (QRadar)** — this is AQL, not standard SQL; aggregates NXDOMAIN-coded events by source IP. `HAVING` filters on the `nx_count` alias rather than the raw `COUNT(*)` (same documented pattern as above).

```sql
SELECT sourceip AS src_ip,
       COUNT(*) AS nx_count,
       UNIQUECOUNT("DNS Query Name") AS distinct_names
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%DNS%'
  AND "DNS Response Code" = 'NXDOMAIN'
GROUP BY sourceip
HAVING nx_count >= 50
LAST 5 MINUTES
```
CONCEPTUAL SAMPLE — `"DNS Response Code"` placeholder as in earlier patterns.

Expected result and interpretation: as above.

**[QUERY] YARA-L (Google SecOps)** — a UDM `NETWORK_DNS` match filtered to NXDOMAIN responses, aggregated per source over 5 minutes.

```yaral
rule nxdomain_burst_single_source {
  meta:
    description = "High rate of NXDOMAIN responses to distinct candidate names from one source"
    severity = "MEDIUM"

  events:
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.principal.ip = $ip
    $dns.network.dns.response_code = "NXDOMAIN"
    $dns.network.dns.questions.name = $qname

  match:
    $ip over 5m

  outcome:
    $nx_count = count($qname)
    $distinct_names = count_distinct($qname)

  condition:
    $dns and $nx_count >= 50
}
```
CONCEPTUAL SAMPLE — aggregation function names illustrative.

Expected result and interpretation: as above.

**[QUERY] Elastic (ES\|QL)** — aggregation/threshold shape.

```esql
FROM dns-*
| WHERE dns.response_code == "NXDOMAIN" AND @timestamp > NOW() - 5 minutes
| STATS nx_count = COUNT(*), distinct_names = COUNT_DISTINCT(dns.question.name) BY source.ip
| WHERE nx_count >= 50
```
CONCEPTUAL SAMPLE — field/index names illustrative.

Expected result and interpretation: as above.

**[FALSE POSITIVE]** Two mechanisms drive this at real volume without any malware involved. First, some browsers deliberately probe random nonsense subdomains at startup to detect ISP or captive-portal DNS hijacking (checking whether a made-up name that should NXDOMAIN instead resolves to a hijacking page) — a small, fixed-count burst per device, not scaling with user activity. Second, Windows' DNS suffix search list multiplies a single mistyped or stale single-label hostname into one NXDOMAIN per suffix in the list — a client with an eight-entry suffix search list turns one typo into eight failures. Exclude the specific known browser-probe domain patterns by name, and count distinct *user-typed* base names rather than raw NXDOMAIN volume where a long suffix search list is in play.

**[PIVOT]** Pull the actual candidate-name list from the burst and score it against `QC-18-02`'s heuristic — a burst of algorithmically-shaped names is a stronger read than a burst of plausible-looking ones. Check the source host's running processes for anything unfamiliar. Watch for a transition from mostly-NXDOMAIN to an occasional successful resolution against a new apex domain — that transition is the DGA finally landing on a live C2 domain, and the newly-resolving domain is worth running back through `QC-18-01` and `QC-18-03`.

---

### QC-18-05 — DNS-over-HTTPS/DoT to an unsanctioned resolver

| Field | Value |
|---|---|
| **Pattern ID** | `QC-18-05` |
| **MITRE** | T1071.004 (Application Layer Protocol: DNS) |
| **Behavior** | A host resolves names over HTTPS (DoH) or TLS (DoT) against a resolver outside the organization's sanctioned/forced resolver set, which removes the resolution from on-network plaintext DNS logging entirely. |
| **DEH cross-ref** | DEH Part 15 §6 (encrypted DNS visibility); DEH Part 14 (Network Detection Engineering) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL — `N/A`, see below, YARA-L, Elastic (KQL — single-event boolean match) |

**[HUNTER]** Encrypted DNS is not itself malicious — it's a genuine, increasingly default, privacy feature — but it is also a clean way for an implant (or a user evading content filtering) to make the previous four patterns in this part unreadable, because none of them work against traffic that never generates a plaintext DNS event. The hunt here is at the network/TLS layer, not the DNS-log layer: connections to a known DoH/DoT provider hostname or IP that isn't the organization's own sanctioned resolver.

**[QUERY] Sigma** — a `network_connection` category rule matching destination hostname against known public DoH providers.

```yaml
title: Connection to a Known DNS-over-HTTPS Provider Endpoint
logsource:
  category: network_connection
  product: any
detection:
  selection:
    destination.domain:
      - 'dns.google'
      - 'cloudflare-dns.com'
      - 'doh.opendns.com'
      - 'dns.quad9.net'
    destination.port: 443
  filter_sanctioned_resolver:
    destination.domain: 'corp-doh.internal.example'
  condition: selection and not filter_sanctioned_resolver
```
CONCEPTUAL SAMPLE — the provider hostname list is a small, illustrative sample; a production version needs a maintained, larger list and should exclude your own organization's sanctioned DoH resolver if one is deployed.

Expected result: a small number of hosts per day connecting to a public DoH endpoint on port 443, which in most enterprise environments is either browser default behavior (see [FALSE POSITIVE]) or a deliberate bypass. Interpretation: a hit here means the host's DNS resolution for this session is invisible to every other pattern in this part, not that the specific query content was malicious — it's a visibility event, not a payload event.

**[QUERY] KQL (Sentinel/Defender)** — matches network/proxy telemetry against known DoH provider hostnames on port 443.

```kql
union DeviceNetworkEvents, CommonSecurityLog
| where RemoteUrl has_any ("dns.google", "cloudflare-dns.com", "doh.opendns.com", "dns.quad9.net")
      or DestinationHostName has_any ("dns.google", "cloudflare-dns.com", "doh.opendns.com", "dns.quad9.net")
| where RemotePort == 443 or DestinationPort == 443
| project TimeGenerated, DeviceName, RemoteUrl, DestinationHostName, RemotePort
```
CONCEPTUAL SAMPLE — table availability depends on which Defender/Sentinel connectors are enabled; illustrative.

Expected result and interpretation: as above.

**[QUERY] SPL** — matches proxy or network-flow telemetry against known DoH provider destinations on port 443.

```spl
index=proxy OR index=network dest_port=443
| search dest IN ("dns.google", "cloudflare-dns.com", "doh.opendns.com", "dns.quad9.net")
| stats count by src, dest, user
```
CONCEPTUAL SAMPLE — index names illustrative.

Expected result and interpretation: as above.

**[QUERY] AQL (QRadar)** — `N/A — Missing schema field`. QRadar's DNS-category AQL fields (queried in every other pattern in this part) exist only for on-network resolver telemetry parsed from a port-53 DNS log source; DoH traffic never generates a DNS-category event at all, since the resolution happens inside a TLS/HTTPS session the DNS log source has no visibility into. If flow or proxy log sources are ingested, the equivalent search runs against those event categories instead (matching destination hostname/SNI on port 443, the same logic as the SPL/KQL blocks above) — that is a flow query, not a DNS query, and isn't shown here as a DNS-pattern block to avoid implying QRadar's DNS fields have a reach they don't.

**[QUERY] YARA-L (Google SecOps)** — a UDM network/HTTP event match against a reference list of known DoH provider hostnames.

```yaral
rule doh_unsanctioned_resolver_connection {
  meta:
    description = "TLS/HTTP connection to a known public DoH provider hostname"
    severity = "LOW"

  events:
    $net.metadata.event_type = "NETWORK_HTTP" or $net.metadata.event_type = "NETWORK_CONNECTION"
    $net.principal.ip = $ip
    $net.target.hostname = $hostname
    $hostname in %doh_provider_hostnames

  condition:
    $net
}
```
CONCEPTUAL SAMPLE — `%doh_provider_hostnames` is a placeholder reference list; populate and maintain it against your own list of known DoH/DoT providers.

Expected result and interpretation: as above.

**[QUERY] Elastic (KQL)** — a single-event boolean match, the cheapest Elastic surface for this shape.

```kql
destination.domain: ("dns.google" or "cloudflare-dns.com" or "doh.opendns.com" or "dns.quad9.net") and destination.port: 443
```
CONCEPTUAL SAMPLE — provider list illustrative.

Expected result and interpretation: as above.

**[FALSE POSITIVE]** Modern browsers increasingly enable DoH by default — Firefox's Trusted Recursive Resolver defaults to a public provider for many builds, and Chrome auto-upgrades to DoH against the *same* effective resolver the network already hands out via DHCP when that resolver supports it, which is a protocol upgrade, not an evasion. The two look identical in a destination-hostname match; the distinguishing fact is whether the DoH endpoint matches the organization's own configured resolver (benign auto-upgrade) or a different, unsanctioned third-party provider (worth investigating). Maintain the sanctioned-resolver exclusion in every query above rather than trying to distinguish "corporate" from "personal" browser profiles, which isn't reliably visible from network telemetry alone.

**[PIVOT]** If the connection is TLS (DoT, typically port 853, or DoH over 443), check the certificate subject/SNI against the known-provider list independently of the destination IP, since these providers rotate IPs behind CDNs. Check whether your egress firewall policy allows arbitrary port 443 destinations — that's the root-cause control gap, not the individual host. Pull the requesting process on the endpoint; a browser doing this is a policy conversation, an unfamiliar binary doing this is an incident. If DoH/DoT is blocked or redirected at the egress layer, re-run `QC-18-01`, `QC-18-03`, and `QC-18-04` against the plaintext DNS traffic this forces back into visibility.

---

## Cross-references

DEH Part 15 (DNS Detection Engineering); DEH Part 40 (seeded naive-rule teardown, "long DNS label = tunnel"); DEH Part 31 (Baselining); DEH Part 14 (Network Detection Engineering); DEH Parts 23–29 and DEH Appendix A5 (query-language syntax and the Elastic-surface decision table cited throughout); DEH Parts 41–43 (Detection Coverage/Quality/Debt, applied to this catalog in Part 28) — this book's Part 3 (Scanning & Enumeration, internal DNS-enumeration handoff), Part 19 (C2 & Beaconing Detection, non-DNS transports), and Part 20 (Exfiltration, data-loss triage once a DNS channel is confirmed).
