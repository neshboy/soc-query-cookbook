---
title: "Part 3 — Scanning & Enumeration"
part: 3
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 3 — Scanning & Enumeration

## Why this part exists

**[CONCEPT]** Scanning and enumeration are the attacker's map-making step — before anything can be exploited, moved through, or exfiltrated, something first has to learn what exists: which ports answer, which hosts are alive, which shares are browsable, which client-side tool is doing the asking. This part covers that map-making at the network and session layer: port and service scanning (vertical and horizontal), host-existence sweeps at the ICMP/ARP layer, fingerprinting the scanning tool itself from its banner or client-identification string, and SMB null-session share enumeration as a pre-lateral-movement signal. Every pattern here is a hunt a threat hunter runs against connection-level or session-level telemetry — not a standing detection this book claims is already tuned for your environment.

Three scope boundaries keep this part from silently duplicating its neighbors:

- **DNS-specific enumeration — tunnelling, DGA-shaped queries, rare/first-seen domains, NXDOMAIN bursts — is owned exclusively by Part 18.** Where a pattern below references "rare destination," it means a rare IP/ASN/port combination, not a rare domain name, mirroring the same split DEH Part 14 draws against DEH Part 15.
- **Endpoint-command-level discovery — `net`, `nltest`, `whoami`, BloodHound-shaped LDAP walks — belongs to Part 15, not here.** This part's enumeration patterns are visible on the wire or in an authentication log regardless of whether the attacker ever runs a discovery command locally; Part 15 covers the case where the discovery *is* the command.
- **The lateral-movement use of an admin share (PsExec-style service installs, WMI, WinRM) is Part 16's scope; this part stops at discovery.** QC-03-05 below detects that a share was *enumerated*, not that it was subsequently used to move — Part 16 picks up from there.

The primary cross-reference for this part's aggregation-shaped patterns is DEH Part 14 §1 (Network Detection Engineering — port and service scanning), which teaches the vertical/horizontal scan distinction and ships two worked detections (DET-14-01, DET-14-02) this part's first two patterns extend into QRadar AQL, YARA-L, and Elastic ES\|QL — languages DEH's own Part 14 doesn't cover, since DEH teaches language semantics through one canonical detection family (Parts 24–29), not full six-language coverage per behavior. Where this part's patterns need Windows-native session context (SMB Logon Type 3, discovery event IDs), DEH Part 8 §3 and §8 own that ground and are cited, not re-taught.

---

## 1. Network-level scan and sweep patterns

This section covers the three patterns built on a threshold/distinct-count query shape: one source, one time window, a count of distinct ports, hosts, or targets that crosses a threshold. All three share the same structural Sigma limitation, explained once at QC-03-01 and not repeated at QC-03-02/03.

### QC-03-01 — Vertical port/service scan against a single host

| Field | Value |
|---|---|
| **Pattern ID** | `QC-03-01` |
| **MITRE** | T1595.002 (Active Scanning: Vulnerability Scanning); T1046 (Network Service Discovery) |
| **Behavior** | One source IP touches an unusually high number of distinct destination ports on a single destination host within a short window. |
| **DEH cross-ref** | DEH Part 14 §1.1 (worked vertical-scan detection, DET-14-01); DEH Appendix A5 §4 (distinct-count aggregation, Sigma's coverage gap) |
| **Languages covered** | KQL, SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) — Sigma: `N/A` (aggregation ceiling, see note below) |

**[HUNTER]** Reach for this hunt, rather than waiting on a standing rule, when a specific host just got interesting for another reason — it's newly internet-facing, it hosts a service that just had a CVE disclosed, or another signal (a beacon hit, a suspicious login) already pointed at it — and the question is narrowly "was this host probed for open ports recently, and from where." Running it ad hoc over a specific host and a wide lookback avoids tuning a threshold you'll only use once.

*Sigma: `N/A` — aggregation ceiling.* Sigma's correlation-rule spec defines four types (`event_count`, `value_count`, `temporal`, `temporal_ordered`); none of them is a native distinct-count type (DEH Appendix A5 §4 marks this row with an em dash for Sigma specifically). Expressing "more than 20 *distinct* ports" as a Sigma `event_count` correlation would count matching connection-attempt *events*, not distinct port *values* — a source that retries the same three ports seven times each produces 21 events and zero distinct ports over the real threshold, which is a different claim than the one this pattern makes, not a lossy translation of it.

This targets a generic connection-summary table (a Zeek `conn.log` export, a NetFlow/IPFIX collector, or a cloud VPC flow log) via Sentinel/Defender KQL, not Elastic KQL, grouping by source and destination and counting distinct destination ports touched in a rolling window.

CONCEPTUAL SAMPLE — field names approximate DeviceNetworkEvents / CommonSecurityLog shapes, not a literal schema; validate against your own tenant.

```kql
NetworkSessionEvents
| where ActionType in ("ConnectionAttempted", "ConnectionSuccess")
| summarize DistinctPorts = dcount(RemotePort), PortsTouched = make_set(RemotePort, 25)
    by SourceIP, RemoteIP, bin(Timestamp, 10m)
| where DistinctPorts > 20
| join kind=leftanti (KnownScannerAssets) on $left.SourceIP == $right.AssetIP
```

Expected result: a handful of rows per day on a quiet internal segment, each naming one `SourceIP`/`RemoteIP` pair with `DistinctPorts` in the 20s–100s and a capped `PortsTouched` sample list. Interpretation: a count well above the threshold, especially spanning both low and high port numbers, is consistent with a deliberate full-range probe against that one host rather than a handful of legitimate retries.

This targets Splunk SPL against Zeek `conn.log` fields shown directly (`id.orig_h`/`id.resp_h`/`id.resp_p`).

CONCEPTUAL SAMPLE — map field names to your own sourcetype before use.

```spl
index=zeek sourcetype=corelight_conn
| bin _time span=10m
| stats dc(id.resp_p) as distinct_ports values(id.resp_p) as ports_touched
    by id.orig_h, id.resp_h, _time
| where distinct_ports > 20
| lookup known_scanner_allowlist src as id.orig_h OUTPUT is_known_scanner
| where isnull(is_known_scanner)
```

Expected result: one row per (`id.orig_h`, `id.resp_h`, bucket) with `distinct_ports` above 20 and a `ports_touched` multivalue field a triager can scan for a full-range pattern (1–1024) versus a short, targeted list. Interpretation: the same as above — this is a plausible vertical-scan hit against that specific host, not yet a confirmed attacker.

The following targets QRadar's Ariel Query Language (AQL) — not standard SQL — against QRadar's Network Flow (QFlow/NetFlow) data source. AQL natively supports a post-aggregation `HAVING` clause when it filters on the aggregate's alias rather than the raw aggregate expression (IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5: https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html), so the threshold below is applied directly with `HAVING distinct_ports > 20` rather than wrapped in an outer `SELECT` over a subquery. (IBM's one documented `HAVING` gap — unsupported in a saved search feeding a scheduled report or time-series graph — doesn't apply to this ad hoc investigative search.)

CONCEPTUAL SAMPLE — illustrative AQL; validate field and dataset names against your own QRadar deployment.

```sql
SELECT sourceip AS src_ip, destinationip AS dst_ip,
       UNIQUECOUNT(destinationport) AS distinct_ports
FROM events
WHERE devicetype = 'NetworkFlow'
GROUP BY sourceip, destinationip
HAVING distinct_ports > 20
LAST 10 MINUTES
```

Expected result: a small result set of `(src_ip, dst_ip, distinct_ports)` rows for the last 10 minutes of flow data, `distinct_ports` above 20. Interpretation: same as the KQL/SPL versions; treat this ad hoc AQL search as the validation step before building the three-object Building Block/Reference Set/Rule chain DEH Part 27 §2–§3 describes if this graduates to a standing QRadar rule.

The following is a Google SecOps YARA-L rule using the `outcome` section's `count_distinct` function against UDM network-connection events.

CONCEPTUAL SAMPLE — illustrative UDM field names; validate against your own SecOps schema.

```yaral
rule vertical_port_scan_single_host {
  meta:
    description = "Single source touching many distinct ports on one destination in a short window"
    severity = "MEDIUM"

  events:
    $scan.metadata.event_type = "NETWORK_CONNECTION"
    $scan.principal.ip = $src_ip
    $scan.target.ip = $dst_ip
    $scan.target.port = $dst_port

  match:
    $src_ip, $dst_ip over 10m

  outcome:
    $distinct_ports = count_distinct($scan.target.port)

  condition:
    $scan and $distinct_ports > 20
}
```

Expected result: a detection instance per (`src_ip`, `dst_ip`) match window with `$distinct_ports` populated above 20 in the outcome. Interpretation: same claim as the other four — plausible vertical scan, pending allowlist and pivot checks below.

This threshold/wide-lookback shape is a natural ES\|QL fit per DEH Appendix A5 §8's decision table (EQL itself has no aggregation stage); the query below targets an ECS-mapped flow index.

CONCEPTUAL SAMPLE — illustrative ES|QL; field names approximate ECS `destination.port`/`source.ip`.

```esql
FROM network-flows-*
| WHERE event.action IN ("connection_attempted", "connection_success")
| STATS distinct_ports = COUNT_DISTINCT(destination.port)
    BY source.ip, destination.ip, bucket = BUCKET(@timestamp, 10 minutes)
| WHERE distinct_ports > 20
```

Expected result: rows per (`source.ip`, `destination.ip`, 10-minute bucket) with `distinct_ports` above 20. Interpretation: same as above.

**[FALSE POSITIVE]** A vulnerability scanner or asset-discovery tool running its normal profile probes on the order of a thousand ports per host regardless of how many resolve open — that comfortably crosses a 20-port threshold every time it runs, typically on a weekly or monthly schedule. Internal monitoring dashboards polling health-check endpoints across a multi-service host produce a smaller but still real version of the same pattern. Maintain an allowlist of known scanner and monitoring source IPs or asset tags, reviewed on a schedule; do not raise the threshold to accommodate them — a higher threshold also gives a real attacker more free ports to probe before tripping the rule.

**[PIVOT]** Check whether the same source IP produced a QC-03-02 (horizontal sweep) hit in the same window — a source running both patterns is building a fuller map, not making one exploratory probe. Check the destination host's own authentication log (DEH Part 8 §3) for logon attempts against any newly-discovered port/service shortly after. Check the source host's own process-creation telemetry (DEH Part 11) for scanning tooling, in case the source itself is already compromised rather than a sanctioned scanner.

---

### QC-03-02 — Horizontal port/service sweep across many hosts

| Field | Value |
|---|---|
| **Pattern ID** | `QC-03-02` |
| **MITRE** | T1595.001 (Active Scanning: Scanning IP Blocks); T1046 (Network Service Discovery) |
| **Behavior** | One source IP touches the same destination port (or a small port set) across many distinct destination hosts within a short window. |
| **DEH cross-ref** | DEH Part 14 §1.2 (worked horizontal-scan detection, DET-14-02) |
| **Languages covered** | KQL, SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) — Sigma: `N/A` (aggregation ceiling, same reason as QC-03-01) |

**[HUNTER]** This is the "who's running this service" shape rather than QC-03-01's "what's open on this host" shape — reach for it after an EDR or SOAR alert names a specific tool execution ("network scan tool detected") and the question becomes scoping which hosts on the subnet the tool actually touched, before deciding how many need a closer look.

*Sigma: `N/A` — aggregation ceiling*, for the same reason as QC-03-01: this pattern's threshold is a *distinct*-host count, and Sigma's correlation-rule spec has no native distinct-count type.

This targets the same generic connection-summary table as QC-03-01 via Sentinel/Defender KQL, not Elastic KQL, grouping by source and destination port and counting distinct destination hosts touched in a rolling window.

CONCEPTUAL SAMPLE — field names approximate DeviceNetworkEvents / CommonSecurityLog shapes, not a literal schema; validate against your own tenant.

```kql
NetworkSessionEvents
| where ActionType in ("ConnectionAttempted", "ConnectionSuccess")
| summarize DistinctHosts = dcount(RemoteIP), HostsTouched = make_set(RemoteIP, 25)
    by SourceIP, RemotePort, bin(Timestamp, 10m)
| where DistinctHosts > 15
| join kind=leftanti (KnownScannerAssets) on $left.SourceIP == $right.AssetIP
```

Expected result: rows naming a `SourceIP`/`RemotePort` pair with `DistinctHosts` in the teens to low hundreds, depending on subnet size. Interpretation: a count well above the subnet's own legitimate multi-host tooling baseline is consistent with a deliberate service sweep against that port across the segment.

This targets Splunk SPL against the same Zeek `conn.log` fields as QC-03-01.

CONCEPTUAL SAMPLE — map field names to your own sourcetype before use.

```spl
index=zeek sourcetype=corelight_conn
| bin _time span=10m
| stats dc(id.resp_h) as distinct_hosts values(id.resp_h) as hosts_touched
    by id.orig_h, id.resp_p, _time
| where distinct_hosts > 15
| lookup known_scanner_allowlist src as id.orig_h OUTPUT is_known_scanner
| where isnull(is_known_scanner)
```

Expected result: one row per (`id.orig_h`, `id.resp_p`, bucket) exceeding 15 distinct `id.resp_h` values, with the touched-host list attached. Interpretation: same as the KQL version.

The following is QRadar AQL, not standard SQL, against the Network Flow dataset. As at QC-03-01, AQL's native `HAVING` clause is applied directly here via the aggregate's alias, per IBM's documented pattern; the scheduled-report/time-series-graph limitation noted there doesn't apply to this ad hoc investigative search either.

CONCEPTUAL SAMPLE — illustrative AQL; validate field and dataset names against your own QRadar deployment.

```sql
SELECT sourceip AS src_ip, destinationport AS dst_port,
       UNIQUECOUNT(destinationip) AS distinct_hosts
FROM events
WHERE devicetype = 'NetworkFlow'
GROUP BY sourceip, destinationport
HAVING distinct_hosts > 15
LAST 10 MINUTES
```

Expected result: `(src_ip, dst_port, distinct_hosts)` rows above 15 for the last 10 minutes. Interpretation: same claim as above; validate before promoting to a standing three-object QRadar rule.

The following is a Google SecOps YARA-L rule using the same `count_distinct` outcome pattern as QC-03-01, grouped by source and destination port instead of source and destination host.

CONCEPTUAL SAMPLE — illustrative UDM field names; validate against your own SecOps schema.

```yaral
rule horizontal_service_sweep {
  meta:
    description = "Single source touching the same destination port across many distinct hosts"
    severity = "MEDIUM"

  events:
    $scan.metadata.event_type = "NETWORK_CONNECTION"
    $scan.principal.ip = $src_ip
    $scan.target.ip = $dst_ip
    $scan.target.port = $dst_port

  match:
    $src_ip, $dst_port over 10m

  outcome:
    $distinct_hosts = count_distinct($scan.target.ip)

  condition:
    $scan and $distinct_hosts > 15
}
```

Expected result: a match instance per (`src_ip`, `dst_port`) window with `$distinct_hosts` above 15. Interpretation: same as above.

The same threshold/wide-lookback shape as QC-03-01 fits ES\|QL here too; the query below targets an ECS-mapped flow index.

CONCEPTUAL SAMPLE — illustrative ES|QL; field names approximate ECS `destination.ip`/`source.ip`.

```esql
FROM network-flows-*
| WHERE event.action IN ("connection_attempted", "connection_success")
| STATS distinct_hosts = COUNT_DISTINCT(destination.ip)
    BY source.ip, destination.port, bucket = BUCKET(@timestamp, 10 minutes)
| WHERE distinct_hosts > 15
```

Expected result: rows per (`source.ip`, `destination.port`, bucket) with `distinct_hosts` above 15. Interpretation: same as above.

**[FALSE POSITIVE]** A forward proxy, NAT/CGNAT gateway, or DNS resolver is a single source address that legitimately talks to dozens or hundreds of distinct hosts on the same port (443, 53) continuously, not on a schedule — this is a bigger volume driver than a dedicated scanning tool because it fires on every run rather than weekly. Patch-management agents and backup software sweeping a whole subnet on one port add a second, smaller driver. Allowlist every known proxy/NAT/resolver source address explicitly, separately from the scanner allowlist in QC-03-01 — these are aggregation points, not scanners, and conflating the two lists makes both harder to maintain.

**[PIVOT]** Check whether the touched hosts actually responded (`ConnectionSuccess` versus only `ConnectionAttempted`) to separate confirmed service discovery from blind probing. Check whether the same source also produced a QC-03-01 hit against any of the touched hosts — full-range probing of a subset after a sweep is a stronger signal than either pattern alone. Check the source against the QC-03-01 scanner allowlist before treating it as unsanctioned.

> **Blind Spot**
> QC-03-01 and QC-03-02 both group by a single source IP and score within one fixed window. Spreading the same total port/host coverage across a pool of source addresses — a small botnet, one probe per bot, or a rotating proxy pool — or pacing it below the bucket size (one host every 40 seconds keeps a 10-minute bucket at 15 distinct hosts indefinitely while still covering hundreds of hosts over an hour) defeats either threshold without reducing the reconnaissance performed. Catching either evasion needs a longer lookback with aggregation keyed on source ASN or subnet rather than a single IP — neither query above does that.

---

### QC-03-03 — Internal host-discovery sweep via ICMP or ARP

| Field | Value |
|---|---|
| **Pattern ID** | `QC-03-03` |
| **MITRE** | T1018 (Remote System Discovery); T1046 (Network Service Discovery) |
| **Behavior** | One internal source generates ICMP echo requests (or ARP requests) against a large share of a subnet's address space in a short window. |
| **DEH cross-ref** | DEH Part 14 §1 (scan-detection framing, extended here to ICMP/ARP telemetry — DEH ships no dedicated worked analytic at this layer); DEH Part 4 (network telemetry survey — Zeek/NetFlow ICMP sources) |
| **Languages covered** | KQL, SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) — Sigma: `N/A` (aggregation ceiling, same reason as QC-03-01/02) |

**[CONCEPT]** QC-03-01 and QC-03-02 both ask "what's open" — a Layer 4 question. This pattern asks the question that usually comes first: "what's even alive here" — a Layer 3 (ICMP) or Layer 2 (ARP) existence check that precedes a port sweep once an attacker has a foothold on the segment and needs to scope it before spending effort on service discovery.

**[HUNTER]** Run this hunt after any signal that a workstation-class host has an unexplained new role on the network — an EDR alert naming `fping`/`arp-scan`, or simply scoping "what did this host touch" after an unrelated compromise indicator — rather than as a standing page, since legitimate host-discovery traffic on most estates is common enough that a standing rule needs heavier tuning than this hunt does.

*Sigma: `N/A` — aggregation ceiling*, for the same reason as QC-03-01/02: the threshold is a distinct-target count, which Sigma's correlation types don't express natively.

This targets a generic flow table with ICMP records included via Sentinel/Defender KQL, not Elastic KQL, restricted to private-to-private ICMP echo requests and grouped by source.

CONCEPTUAL SAMPLE — field names approximate a generic flow schema, not a literal DeviceNetworkEvents field set; validate against your own tenant.

```kql
NetworkSessionEvents
| where Protocol == "ICMP" and IcmpType == 8 // Echo Request
| where ipv4_is_private(SourceIP) and ipv4_is_private(RemoteIP)
| summarize DistinctTargets = dcount(RemoteIP) by SourceIP, bin(Timestamp, 5m)
| where DistinctTargets > 50
| join kind=leftanti (KnownScannerAssets) on $left.SourceIP == $right.AssetIP
```

Expected result: a source touching more than 50 distinct internal addresses with ICMP echo requests inside one 5-minute bucket — on a /24, that's a fifth or more of the address space. Interpretation: consistent with a deliberate ping sweep of the local subnet, most plausibly from a host that already has some level of network access and is scoping what else is reachable.

This targets Splunk SPL against Zeek `icmp.log`-style fields.

CONCEPTUAL SAMPLE — adjust field names to your own sourcetype.

```spl
index=zeek sourcetype=corelight_icmp icmp_type=8
| bin _time span=5m
| stats dc(id.resp_h) as distinct_targets by id.orig_h, _time
| where distinct_targets > 50
| lookup known_scanner_allowlist src as id.orig_h OUTPUT is_known_scanner
| where isnull(is_known_scanner)
```

Expected result: one row per (`id.orig_h`, bucket) above 50 distinct `id.resp_h` values. Interpretation: same as above.

The following is QRadar AQL, not standard SQL, filtered to ICMP flow records (`protocolid = 1`).

CONCEPTUAL SAMPLE — illustrative AQL; validate field and dataset names against your own QRadar deployment.

```sql
SELECT src_ip, distinct_targets
FROM (
    SELECT sourceip AS src_ip, UNIQUECOUNT(destinationip) AS distinct_targets
    FROM events
    WHERE devicetype = 'NetworkFlow' AND protocolid = 1
    GROUP BY sourceip
    LAST 5 MINUTES
)
WHERE distinct_targets > 50
```

Expected result: `(src_ip, distinct_targets)` rows above 50 for the last 5 minutes of ICMP flow data. Interpretation: same claim as above.

The following is a Google SecOps YARA-L rule filtered to ICMP traffic via the `network.ip_protocol` field.

CONCEPTUAL SAMPLE — illustrative UDM field names; this book has not confirmed a dedicated ICMP-specific UDM field beyond `network.ip_protocol` — validate against your own SecOps schema.

```yaral
rule internal_icmp_host_discovery_sweep {
  meta:
    description = "Single internal source ICMP-probing many distinct internal hosts in a short window"
    severity = "LOW"

  events:
    $ping.metadata.event_type = "NETWORK_CONNECTION"
    $ping.network.ip_protocol = "ICMP"
    $ping.principal.ip = $src_ip
    $ping.target.ip = $dst_ip

  match:
    $src_ip over 5m

  outcome:
    $distinct_targets = count_distinct($ping.target.ip)

  condition:
    $ping and $distinct_targets > 50
}
```

Expected result: a match instance per `src_ip` window with `$distinct_targets` above 50. Interpretation: same as above, with the added caveat that this rule's fidelity depends on the target UDM parser actually populating `network.ip_protocol` consistently for ICMP traffic — confirm against a known-good test sweep (see the Detection Test below) before trusting a quiet result as "no sweep happened."

The same threshold/wide-lookback shape as QC-03-01/02 fits ES\|QL here too; the query below targets an ECS-mapped flow index filtered to ICMP.

CONCEPTUAL SAMPLE — illustrative ES|QL; field names approximate ECS `network.transport`/`icmp` fields.

```esql
FROM network-flows-*
| WHERE network.transport == "icmp" AND icmp.type == 8
| STATS distinct_targets = COUNT_DISTINCT(destination.ip)
    BY source.ip, bucket = BUCKET(@timestamp, 5 minutes)
| WHERE distinct_targets > 50
```

Expected result: rows per (`source.ip`, bucket) above 50 distinct `destination.ip` values. Interpretation: same as above.

**[FALSE POSITIVE]** Asset-discovery and CMDB-reconciliation jobs, monitoring platforms doing a scheduled ICMP up/down sweep across a subnet, and DHCP/IP-conflict-detection tools all produce the same fan-out, usually on a predictable nightly or hourly schedule. Allowlist those source addresses; a genuinely notable hit is a workstation-class host with no discovery or monitoring role sweeping a subnet, not merely a high count from any source.

**[PIVOT]** Check the same source IP a few minutes later against QC-03-02 — a real lateral-movement precursor typically escalates from "who's alive" to "what's open on the responsive subset" within the same session. Check the source host's own process-creation telemetry (DEH Part 11) for `fping`, `arp-scan`, `nmap -sn`, or an equivalent PowerShell sweep script around the same timestamp. Check whether the source host itself shows any other compromise indicator from this book's Part 22 (Malware Indicators).

**[SOC MANAGEMENT]** ICMP/ARP telemetry is cheap to collect — most Zeek and NetFlow deployments already capture it without extra instrumentation — but a poor standing-detection candidate on its own, because legitimate host-discovery sweeps are common enough on most estates that an always-on version of this rule pages constantly before tuning. Run it as a periodic, scoped hunt (a specific subnet, after another signal raised suspicion) rather than committing analyst time to a standing page for this pattern alone.

> **Detection Test**
> **Setup:** Lab network segment with flow logging (Zeek or NetFlow/IPFIX) enabled on the segment's gateway or a mirrored tap, and a source host that can reach a /24 of other hosts.
> **Action:** `fping -a -g 192.168.1.0/24` (or `nmap -sn 192.168.1.0/24`) from the source host.
> **Expected result:** One ICMP Echo Request flow record per address in the range from the source host; the query above should return a `DistinctTargets`/`distinct_targets` value at or near the number of addresses probed for that source within the same 5-minute bucket — this undercounts if the telemetry source only logs ICMP replies rather than requests, since a probe against a dead address never generates a reply.

---

## 2. Signature- and session-level enumeration patterns

The two patterns in this section share a different query shape from Section 1: each is a single-event boolean match rather than a distinct-count threshold, which is why both achieve full six-language coverage where Section 1's patterns could not.

### QC-03-04 — Known scanner or automated-client signature fingerprint

| Field | Value |
|---|---|
| **Pattern ID** | `QC-03-04` |
| **MITRE** | T1595.002 (Active Scanning: Vulnerability Scanning); T1046 (Network Service Discovery) |
| **Behavior** | An inbound request carries an HTTP User-Agent, SSH version banner, or other client-identification string matching a known scanner or scripting-library signature. |
| **DEH cross-ref** | DEH Part 14 §1.3 (fingerprinting the scanner — banners, timing, User-Agent); DEH Part 40 §5 (Detection Autopsy, "curl in the User-Agent means it's an attacker," `DET-40-01`) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) |

**[HUNTER]** QC-03-01/02/03 tell you *that* something is scanning; they say nothing about *what*. When triage needs to move fast — a commercial vuln-scanner hit and a hand-rolled attacker tool don't carry the same urgency — a signature match against the same window's traffic is the cheapest way to add that context before escalating.

This targets a generic proxy/web-access-log source via a Sigma detection rule (not a correlation rule — a single-event match needs no aggregation type).

CONCEPTUAL SAMPLE — illustrative Sigma rule; validate the logsource category and field name against your own proxy/web-access-log pipeline mapping.

```yaml
title: Known Scanner or Recon-Tool User-Agent Against a Web-Facing Host
id: 3f9a2b10-6c41-4a2e-9d0a-1b7e5c9d4a11
status: experimental
logsource:
    category: proxy
    product: generic
detection:
    selection:
        c-useragent|contains:
            - 'Nmap Scripting Engine'
            - 'Nessus'
            - 'Qualys'
            - 'masscan'
            - 'python-requests'
            - 'Go-http-client'
    condition: selection
falsepositives:
    - Legitimate API clients and internal automation using the same HTTP client libraries
level: low
```

Expected result: one match per inbound request whose `c-useragent` field contains one of the listed strings. Interpretation: consistent with automated, tool-driven traffic rather than a human browser session — not, on its own, evidence of malicious intent (see the false-positive driver below).

This targets Microsoft Sentinel/Defender KQL, not Elastic KQL, against a generic web-access/proxy log table.

CONCEPTUAL SAMPLE — field names approximate CommonSecurityLog / W3CIISLog shapes, not a literal schema.

```kql
WebAccessLog
| where UserAgent has_any ("Nmap Scripting Engine", "Nessus", "Qualys", "masscan",
    "python-requests", "Go-http-client")
| project TimeGenerated, SourceIP, DestinationHost, RequestUrl, UserAgent
```

Expected result: a projected row per matching request with the full `UserAgent` string preserved for triage. Interpretation: same as the Sigma block.

This targets Splunk SPL against a generic web/proxy sourcetype.

CONCEPTUAL SAMPLE — adjust field names to your own log format.

```spl
index=web_proxy
| eval is_known_scanner_ua=if(match(useragent,
    "(?i)(nmap scripting engine|nessus|qualys|masscan|python-requests|go-http-client)"), 1, 0)
| where is_known_scanner_ua=1
| table _time, src_ip, dest_host, uri_path, useragent
```

Expected result: a table of matching requests with `uri_path` retained so a reviewer can see whether the same source touched multiple distinct paths. Interpretation: same as above; multiple distinct paths in a short window from one source strengthens the automated-tool read (see the pivot below).

The following is QRadar AQL, not standard SQL, against QRadar's web/proxy log source.

CONCEPTUAL SAMPLE — illustrative AQL; validate field and dataset names against your own QRadar deployment.

```sql
SELECT sourceip, "URL", "User Agent"
FROM events
WHERE devicetype = 'WebProxy'
AND ("User Agent" ILIKE '%Nmap Scripting Engine%'
     OR "User Agent" ILIKE '%Nessus%'
     OR "User Agent" ILIKE '%Qualys%'
     OR "User Agent" ILIKE '%masscan%'
     OR "User Agent" ILIKE '%python-requests%'
     OR "User Agent" ILIKE '%Go-http-client%')
LAST 24 HOURS
```

Expected result: rows naming the source IP, requested URL, and matched User-Agent string over the last 24 hours. Interpretation: same as above.

The following is a Google SecOps YARA-L rule matching the same User-Agent set against the UDM `network.http.user_agent` field.

CONCEPTUAL SAMPLE — illustrative UDM field names; validate against your own SecOps schema.

```yaral
rule known_scanner_user_agent {
  meta:
    description = "HTTP request carrying a known scanner or vuln-scan-tool user agent"
    severity = "LOW"

  events:
    $req.metadata.event_type = "NETWORK_HTTP"
    $req.network.http.user_agent = $ua
    $req.principal.ip = $src_ip

  match:
    $src_ip over 5m

  condition:
    $req and $ua = /(?i)(nmap scripting engine|nessus|qualys|masscan|python-requests|go-http-client)/
}
```

Expected result: a match instance per `src_ip` window where at least one request's `user_agent` satisfies the regular expression. Interpretation: same as above.

Elastic KQL, not Sentinel/Defender KQL, against an ECS-mapped HTTP index (single-event boolean match, the cheapest fit per DEH Appendix A5 §8's decision table).

CONCEPTUAL SAMPLE — field names approximate an ECS-mapped HTTP index, not a literal schema.

```kql
user_agent.original : ("*Nmap Scripting Engine*" or "*Nessus*" or "*Qualys*" or "*masscan*" or "*python-requests*" or "*Go-http-client*")
```

Expected result: matching documents with `user_agent.original` populated for review. Interpretation: same as above.

**[FALSE POSITIVE]** DEH Part 40 §5's own real honeynet capture (`DET-40-01`) is the worked case study for exactly this driver: the same scripting-library User-Agent classes this pattern matches on — `python-requests`, generic HTTP client libraries — are also what an organization's own internal health checks, CI/CD pipelines, and authorized vulnerability scanners send, and a commercial scanner (Nessus, Qualys) running your own sanctioned weekly scan matches by design, not by accident. The signature alone never distinguishes intent; it needs the same source allowlist discipline as QC-03-01/02, keyed to IP or asset tag — removing a specific library string from the list just pushes a real attacker to spoof a different common one.

**[PIVOT]** Check request-path diversity and timing from the same source — several distinct paths hit within a second or two, as in DEH Part 14 §1.3's honeynet capture, indicates an automated fingerprint sweep rather than a one-off probe. Cross-reference the source IP against QC-03-01/02 hits in the same window. If the User-Agent belongs to an internal asset not on the scanner allowlist, treat it as a possible compromised host running recon tooling rather than a sanctioned scan.

> **Hunter's Note**
> A User-Agent or banner string is the cheapest pivot you have and, for exactly that reason, the easiest one for an attacker to fake — treat a match as a filter that narrows down candidate automated traffic fast, never as a standalone verdict. DEH Part 40 §5's same capture that shows a legitimate internal scanner sending scripting-library signatures also shows a real external exploit attempt against a known CVE path carrying no distinctive User-Agent at all; a rule built only on this field is structurally blind to that second case.

---

### QC-03-05 — SMB null-session / anonymous share enumeration

| Field | Value |
|---|---|
| **Pattern ID** | `QC-03-05` |
| **MITRE** | T1135 (Network Share Discovery) |
| **Behavior** | An unauthenticated (`ANONYMOUS LOGON`) SMB network session establishes to a host, most commonly to `IPC$`, ahead of a share-listing or tree-connect attempt. |
| **DEH cross-ref** | DEH Part 8 §3 (Logon Type 3/Network — the vector this session rides on); DEH Part 11 (ransomware-precursor framing pairing T1135 with T1083, File and Directory Discovery) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) |

**[HUNTER]** A null session is rare enough on a modern, patched estate that a single confirmed hit is worth a human look rather than waiting on a standing rule tuned for volume — this hunt is most useful scoped to a specific subnet or domain controller when another signal already suggests internal recon is underway.

This targets Windows Security auditing via a Sigma detection rule (a single-event match needs no aggregation type).

CONCEPTUAL SAMPLE — illustrative Sigma rule; validate field names against your own EVTX forwarding pipeline mapping.

```yaml
title: Anonymous Logon Network Session (Logon Type 3)
id: 7a2e4f31-9b6c-4d8e-a3f0-2c5d1e8b9a44
status: experimental
logsource:
    category: authentication
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        TargetUserName: 'ANONYMOUS LOGON'
    condition: selection
falsepositives:
    - Legacy printers, some backup agents, and pre-modern-Windows-Server trust-relationship
      checks that still rely on null sessions
level: medium
```

Expected result: one match per Event ID 4624 with `LogonType` 3 and `TargetUserName` equal to `ANONYMOUS LOGON`. Interpretation: consistent with an unauthenticated SMB session establishment, the step that typically precedes a share-listing attempt — not yet confirmation that shares were actually enumerated.

Microsoft Sentinel/Defender KQL, not Elastic KQL, against `SecurityEvent`.

CONCEPTUAL SAMPLE — illustrative Sentinel/Defender KQL; validate table and field names against your own workspace.

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 3 and TargetUserName == "ANONYMOUS LOGON"
| project TimeGenerated, Computer, IpAddress, TargetUserName, LogonType
```

Expected result: a projected row per matching logon naming the target `Computer` and source `IpAddress`. Interpretation: same as above.

This targets Splunk SPL against Windows Security EVTX via a standard Splunk Windows TA field mapping.

CONCEPTUAL SAMPLE — validate field names against your own Windows TA version.

```spl
index=wineventlog EventCode=4624 Logon_Type=3 Target_User_Name="ANONYMOUS LOGON"
| table _time, Computer, Source_Network_Address, Target_User_Name, Logon_Type
```

Expected result: a table of matching logons with the source address preserved. Interpretation: same as above.

The following is QRadar AQL, not standard SQL, against QRadar's mapped Windows authentication QID.

CONCEPTUAL SAMPLE — illustrative AQL; validate field and QID names against your own QRadar deployment.

```sql
SELECT sourceip, destinationip, username, "Logon Type"
FROM events
WHERE QIDNAME(qid) = 'Successful Logon' AND username = 'ANONYMOUS LOGON' AND "Logon Type" = 3
LAST 24 HOURS
```

Expected result: rows naming source and destination IP for the last 24 hours of matching logons. Interpretation: same as above.

The following is a Google SecOps YARA-L rule matching a `USER_LOGIN` event with the target userid set to `ANONYMOUS LOGON`.

CONCEPTUAL SAMPLE — illustrative UDM field names; validate against your own SecOps schema.

```yaral
rule anonymous_logon_network_session {
  meta:
    description = "Network logon (type 3) authenticated as ANONYMOUS LOGON"
    severity = "MEDIUM"

  events:
    $logon.metadata.event_type = "USER_LOGIN"
    $logon.target.user.userid = "ANONYMOUS LOGON"
    $logon.principal.ip = $src_ip
    $logon.target.asset.hostname = $dst_host

  match:
    $src_ip, $dst_host over 5m

  condition:
    $logon
}
```

Expected result: one match instance per (`src_ip`, `dst_host`) pair with a qualifying login event. Interpretation: same as above.

Elastic KQL, not Sentinel/Defender KQL, against a Winlogbeat-shaped index.

CONCEPTUAL SAMPLE — field names approximate a Winlogbeat-mapped index, not a literal schema.

```kql
event.code : "4624" and winlog.event_data.LogonType : "3" and winlog.event_data.TargetUserName : "ANONYMOUS LOGON"
```

Expected result: matching documents with the target host and source address available in `winlog.event_data`. Interpretation: same as above.

**[FALSE POSITIVE]** A handful of legacy network devices (some printers and older NAS appliances), certain backup or EDR agents, and cross-forest or cross-domain trust-relationship checks on estates that haven't fully retired SMB1 still perform null-session binds. This is estate-specific and usually low-volume enough that a per-host allowlist, reviewed on a schedule, is the right fix rather than a threshold — there's no legitimate high-frequency reason for this pattern the way there is for QC-03-01/02's scanners.

**[PIVOT]** Check for a share-enumeration or tree-connect event immediately following (Windows Security 5140/5145, if object-access auditing is enabled) to confirm shares were actually listed rather than the session simply opening and closing. Check whether the same source IP produced a QC-03-02 hit against port 445 in the preceding window. Weigh the destination host's role — a domain controller or file server receiving this from an unexpected internal subnet is a materially different priority than a print server receiving it from its own printer VLAN.

> **Detection Autopsy — "any ANONYMOUS LOGON to IPC$ is an attacker enumerating shares"**
>
> **The rule:** Fires on any Event ID 4624 with `LogonType` 3 and `TargetUserName` equal to `ANONYMOUS LOGON`, no further conditions.
>
> **Why it shipped:** Null sessions are the textbook indicator for share enumeration, the query is a one-line filter, and on a fully patched, SMB1-retired modern estate this genuinely should almost never fire — a compelling story for a zero-tolerance rule.
>
> **How it failed:** On estates that haven't fully retired SMB1, or that still run older printers, certain backup agents, or cross-domain trust checks, this fires routinely from a small, stable set of non-attacker sources — and because the rule carries no destination-role or source-novelty context, every one of those routine hits looks identical in the queue to a genuine recon attempt against a domain controller.
>
> **The fix:** Pair the bare logon match with a per-host allowlist for known legacy sources, and weight severity by destination role (domain controller or file server versus a printer or backup target) rather than treating every match as equally urgent — the same principle DEH Part 40 §5 applies to signature-only rules generally: one weak-but-rare signal still needs source and destination context before it's a verdict.

---

## Cross-references

DEH Part 4 (Telemetry Engineering II — network telemetry sources, ICMP/NetFlow coverage for QC-03-03); DEH Part 8 §3, §8 (Windows logon types and discovery telemetry, for QC-03-05's Logon Type 3 vector); DEH Part 11 (endpoint discovery and ransomware-precursor framing for T1135/T1083); DEH Part 14 §1 (Network Detection Engineering — port and service scanning, DET-14-01/DET-14-02, the direct ancestor of QC-03-01/QC-03-02); DEH Part 40 §5 (Detection Autopsy, `DET-40-01` — the User-Agent false-positive driver cited at QC-03-04); DEH Appendix A5 §4, §8 (aggregation/correlation decision tables governing this part's Sigma `N/A` calls and Elastic-surface choices); DEH Parts 41–43 (Detection Coverage/Quality/Debt, applied to this book's own patterns in Part 28). Within this book: Part 15 (Host & Directory Discovery — the endpoint-command-level enumeration this part explicitly excludes); Part 16 (Lateral Movement via Admin Tools & Remote Services — the use of a share QC-03-05 only detects the discovery of); Part 18 (Suspicious DNS — the domain-rarity and tunnelling enumeration forms owned exclusively there); Part 23 (Ransomware Precursors — where a QC-03-05-shaped discovery chain most often leads); Appendices A1–A3 (Master Pattern Index, Behavior × Language Coverage Matrix, and MITRE Cross-Reference for all five patterns in this part).
