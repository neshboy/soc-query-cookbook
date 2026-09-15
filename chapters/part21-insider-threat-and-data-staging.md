---
title: "Insider Threat & Data Staging"
part: 21
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 21 — Insider Threat & Data Staging

## Why this part exists

**[CONCEPT]** Insider threat and data-staging behavior sits in an uncomfortable place for a SOC: almost every action a hunter can actually observe — compressing a folder, copying files to a USB drive, downloading more from a share than usual — is also completely ordinary employee behavior most days of the week. What separates a departing engineer backing up personal notes from an employee staging a customer database for sale is intent, and intent is exactly the one thing host and network telemetry cannot record. DEH Part 42's Analytic Confidence scale exists partly to name this problem directly: this behavior class runs at the low end of that scale by construction, not because the queries below are poorly written, and every pattern in this part is framed around the ambiguous, dual-use shape of the activity rather than around any assumed-malicious tool, because there usually isn't one — 7-Zip, Windows Explorer, and a USB port are the entire toolkit.

This part covers four named behavior threads inside that scope, at this book's standard 4–6 pattern budget: mass archive/compression creation ahead of a transfer, an unusual bulk file-access or copy-volume spike correlated to a known or suspected employee departure, removable-media write events, and staging-directory hunting — plus one composite pattern (`QC-21-05`) that chains the first three together, because DEH Part 42's own framing implies the honest way to raise this class's confidence is co-occurrence across weak signals, not asserting any single event more strongly than the telemetry supports.

Two explicit boundaries against this part's closest neighbors. Part 20 (Exfiltration) owns the network-transfer side of this exact story — large or anomalous outbound volume, exfiltration over DNS/ICMP, and uploads to unsanctioned cloud-storage destinations; this part stops at the host, before anything leaves the network, and a pattern here that fires alongside a Part 20 hit is a materially stronger combined signal than either alone, cited into Part 27's hunt chains rather than duplicated in either part. Part 15 (Host & Directory Discovery) owns the pre-lateral-movement enumeration commands (`net`, `nltest`, BloodHound-shaped queries); an insider already has the access they're abusing and rarely needs to enumerate anything first, so this part's patterns key on the volume and destination of already-legitimate access rather than on discovery tooling. Part 22 (Malware Indicators) and Part 24 (Cloud Identity & SaaS Abuse) are both adjacent but excluded on separate grounds: this part deliberately excludes malware-presence signals, since the tools in scope here are legitimate and almost always signed, and excludes OAuth/app-consent-grant abuse, which is a SaaS-identity-layer behavior rather than a host-file-staging one.

**[SOC MANAGEMENT]** No pattern in this part should run as a standing, real-time-paging detection on its own. DEH Part 42's confidence framing and this part's own false-positive drivers point the same direction: individually, every one of these signals fires on ordinary IT operations often enough that an always-page rule trains the SOC to ignore it within weeks. The workable cadence is a triggered hunt — run `QC-21-01` through `QC-21-04` against a specific user or host once HR, Legal, or an existing Part 20 exfiltration hit gives a documented reason to look, and reserve `QC-21-05`'s composite correlation for the cases that warrant its higher confidence bar. Any pattern that touches HR departure data (`QC-21-02` specifically) needs a documented Legal/HR governance sign-off before it runs against a named employee at all, not only before any escalation that follows a hit — that review belongs ahead of the query, not after it.

## Query patterns

### QC-21-01 — Mass archive creation from a sensitive or shared source path

| Field | Value |
|---|---|
| **Pattern ID** | `QC-21-01` |
| **MITRE** | T1560.001 (Archive Collected Data: Archive via Utility) |
| **Behavior** | A compression utility (`7z.exe`, `WinRAR.exe`, `rar.exe`, `tar`) is invoked against a network share, mapped drive, or another user's profile, producing an archive file outside a documented backup or IT process. |
| **DEH cross-ref** | DEH Part 3 (Telemetry Engineering I: Host and Identity Sources — process-creation and command-line visibility); DEH Part 11 (Endpoint Detection Engineering — dual-use tooling framing) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (KQL) |

**[HUNTER]** Archive utilities are the single most common tool an insider actually reaches for, precisely because they're legitimate, unmonitored by most EDR policies, and already installed. This hunt beats waiting on a standing rule because the interesting variable isn't the binary — it's the source path and the password flag — and a hunter checking a specific suspected user or host can apply that judgment far faster than a generic rule tuned across the whole fleet.

**[QUERY] Sigma** — Sysmon process-creation telemetry on Windows.

CONCEPTUAL SAMPLE — binary list, path substrings, and password-flag detection illustrative; validate against your own environment's actual archive tooling and share naming.
```yaml
title: Archive Utility Invoked Against a Network Share or Foreign Profile Path
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\7z.exe'
      - '\rar.exe'
      - '\WinRAR.exe'
  selection_source:
    CommandLine|contains:
      - '\\\\'          # UNC path
      - ':\Users\'       # another user's local profile
  condition: selection and selection_source
falsepositives:
  - See [FALSE POSITIVE] below
level: medium
```
Plausible expected result: a hit returns a command line such as `"C:\Program Files\7-Zip\7z.exe" a -pS3cr3t! C:\Users\jsmith\Desktop\export.7z \\fileserver01\Finance$\Q3_Reports\*`, with `ParentImage` typically `explorer.exe` or `cmd.exe`. Interpretation: consistent with a user compressing files pulled from a share into a portable, possibly password-protected archive on local disk — worth a look given the destination sits outside any documented backup path, not proof of intent on its own.

**[QUERY] KQL (Sentinel/Defender)** — `DeviceProcessEvents`.

CONCEPTUAL SAMPLE — path substrings illustrative; align with your own share and profile-path conventions.
```kql
DeviceProcessEvents
| where FileName in~ ("7z.exe", "rar.exe", "WinRAR.exe")
| where ProcessCommandLine has "\\\\" or ProcessCommandLine matches regex @":\\Users\\[^\\]+\\"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```
Plausible expected result: a sparse set of rows, each carrying the full command line and the acting account. Interpretation: same read as the Sigma block — treat the source path and password flag as the parts worth weighting, not the mere presence of the binary.

**[QUERY] SPL** — Sysmon or EDR process-creation index.

CONCEPTUAL SAMPLE — field names assume a standard Sysmon TA mapping.
```spl
index=sysmon EventCode=1
Image IN ("*\\7z.exe", "*\\rar.exe", "*\\WinRAR.exe")
(CommandLine="*\\\\*" OR CommandLine="*:\\Users\\*")
| table _time, host, User, ParentImage, CommandLine
| sort - _time
```
Plausible expected result: the same shape as the KQL output in table form. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, QRadar's Ariel Query Language, not standard SQL, run against the normalized Events view.

CONCEPTUAL SAMPLE — payload keyword matching is a coarse substitute for parsed command-line fields; confirm your log source extension actually parses `CommandLine` before relying on this shape.
```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS eventTime,
       username, UTF8(payload) AS commandLine
FROM events
WHERE (UTF8(payload) ILIKE '%7z.exe%' OR UTF8(payload) ILIKE '%rar.exe%' OR UTF8(payload) ILIKE '%WinRAR.exe%')
  AND (UTF8(payload) ILIKE '%\\\\%' OR UTF8(payload) ILIKE '%:\Users\%')
LAST 7 DAYS
```
Plausible expected result: a small result set, with the archive utility's full invocation recoverable from the raw payload text. Interpretation: unchanged from the other languages above.

**[QUERY] YARA-L** — Google SecOps UDM `PROCESS_LAUNCH` events.

CONCEPTUAL SAMPLE — UDM field paths illustrative; validate against your own ingestion pipeline.
```yaral
rule archive_utility_against_share_or_foreign_profile {
  meta:
    description = "Archive utility invoked against a UNC path or another user's profile"
    severity = "Medium"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /(7z\.exe|rar\.exe|WinRAR\.exe)$/i
    $e.target.process.command_line = /(\\\\|:\\Users\\)/i
  condition:
    $e
}
```
Plausible expected result: one match per invocation, with the acting principal and full command line intact. Interpretation: unchanged.

**[QUERY] Elastic (KQL)** — a single-event boolean match, so Elastic's own KQL surface is the cheapest fit per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — path substrings illustrative.
```kql
process.name : ("7z.exe" or "rar.exe" or "WinRAR.exe") and process.command_line : ("*\\\\*" or "*:\\Users\\*")
```
Plausible expected result: the same shape as every other language above, surfaced through `process.parent.name` and `user.name`. Interpretation: unchanged.

**[FALSE POSITIVE]** IT-run backup jobs and mailbox-migration tooling routinely shell out to 7-Zip or WinRAR from a service account at a fixed nightly time against a consistent destination — exclude that specific account-plus-path combination rather than the binary itself, since exempting the binary removes this pattern's only real signal. A second common driver: ordinary users compressing large project folders because an email attachment-size limit forces it, or a help-desk-driven PST-file archive ahead of a mailbox migration. A password-protected archive (`-p` flag) built by an ordinary user account with no associated change ticket is the narrower, stronger version of this signal worth prioritizing over volume alone.

**[PIVOT]** Check whether the resulting archive file was subsequently copied to removable media (`QC-21-03`) or written into a staging directory already flagged by `QC-21-04` — either co-occurrence raises this well above a routine compression job. Also check the account's normal role against the source share's data classification; an archive pulled from a share the account has no ordinary job-function reason to touch is a stronger read than the archive event alone.

---

### QC-21-02 — Bulk file-access volume spike inside an HR-flagged departure window

| Field | Value |
|---|---|
| **Pattern ID** | `QC-21-02` |
| **MITRE** | T1039 (Data from Network Shared Drive) |
| **Behavior** | A user's file-open, download, or copy event volume against a share or document repository spikes well above their own baseline inside the days preceding a known or suspected resignation or termination date. |
| **DEH cross-ref** | DEH Part 3 (host and file-access telemetry); DEH Part 31 (Baselining — a per-user access-volume baseline is required for "spike" to mean anything); DEH Part 42 (Analytic Confidence) |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) — Sigma: `N/A`, see below |

**[HUNTER]** This is deliberately the lowest-confidence pattern in this part: transitioning knowledge, printing handoff material, and backing up personal files are all normal parts of a real departure that have nothing to do with theft, and DEH Part 42 places this exact behavior class near the bottom of its Analytic Confidence scale for that reason. Reach for this hunt rather than a standing rule because the HR departure-date signal usually exists only as a manual notification security receives after a flagged resignation or termination, not as an automatable real-time feed in most environments.

*Sigma: `N/A` — Aggregation ceiling. Sigma's correlation model (`event_count`/`value_count`/`temporal`) has no reference-implementation primitive for joining a detection against an exogenous, per-user reference table like an HR departure date across most backends — there is no field in the raw telemetry itself to group by that carries "this user's last day of work," so the join this pattern depends on falls outside what a Sigma correlation rule can express portably.*

**[QUERY] KQL (Sentinel/Defender)** — `OfficeActivity` joined against an ingested HR-departure watchlist.

CONCEPTUAL SAMPLE — watchlist name, field names, and multiplier threshold illustrative; validate against your own baseline and HR feed schema.
```kql
let departures = _GetWatchlist('HRDepartureWatchlist')
    | project UserPrincipalName, LastDayOfWork = todatetime(LastDayOfWork);
let baseline = OfficeActivity
    | where TimeGenerated < ago(90d)
    | summarize AvgDailyAccess = count() / 90.0 by UserId;
OfficeActivity
| where Operation in ("FileAccessed", "FileDownloaded", "FileCopied", "FileSyncDownloadedFull")
| join kind=inner departures on $left.UserId == $right.UserPrincipalName
| where TimeGenerated between (LastDayOfWork - 14d .. LastDayOfWork)
| summarize WindowEvents = count() by UserId, LastDayOfWork
| join kind=inner baseline on UserId
| where WindowEvents > 5 * (AvgDailyAccess * 14)
```
Plausible expected result: a small number of UserIds where `WindowEvents` runs several times the expected 14-day baseline — for example, 1,200 access events against an expected ~150. Interpretation: consistent with a departing employee accessing far more files than their ordinary role activity in the run-up to their last day; this is a starting point for documented review, not evidence of intent, per DEH Part 42's confidence framing.

**[QUERY] SPL** — a lookup-driven join against an HR export.

CONCEPTUAL SAMPLE — lookup file and field names illustrative.
```spl
| inputlookup hr_departures.csv
| join type=inner user
    [ search index=o365 (Operation=FileAccessed OR Operation=FileDownloaded OR Operation=FileCopied)
      | bin _time span=1d
      | stats count as daily_events by user, _time ]
| eval window_start=relative_time(strptime(last_day_of_work,"%Y-%m-%d"), "-14d@d")
| where _time >= window_start AND _time <= strptime(last_day_of_work,"%Y-%m-%d")
| stats sum(daily_events) as window_events by user, last_day_of_work
```
Plausible expected result: the same shape as the KQL output — one row per flagged user with a total event count for the departure window. Interpretation: same read as above.

**[QUERY] AQL** — this is AQL, not standard SQL. AQL has no `JOIN` clause, so the query below is the investigative, single-user search an analyst runs once HR has already provided a specific departure date; a standing, fleet-wide correlated version needs QRadar's Reference Set of active departures plus a Custom Rule testing against it (DEH Part 27 §2–§3's multi-object model), a heavier build than the search shown here.

CONCEPTUAL SAMPLE — single-user investigative search; field names and date window illustrative, and this substitutes for the fleet-wide join no AQL query can express natively.
```sql
SELECT username, COUNT(*) AS fileAccessEvents
FROM events
WHERE username = 'jsmith'
  AND category = 'File Access'
START '2026-08-15 00:00:00' STOP '2026-08-29 00:00:00'
GROUP BY username
```
Plausible expected result: a single row per named user for the manually supplied date window. Interpretation: unchanged — this validates one user at a time rather than screening the whole population automatically.

**[QUERY] YARA-L** — a reference list of departing usernames joined against UDM resource-access events.

CONCEPTUAL SAMPLE — reference-list syntax and threshold illustrative.
```yaral
rule bulk_file_access_ahead_of_departure {
  meta:
    description = "File-access volume spike for a user on the HR departure reference list"
    severity = "Medium"
  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.principal.user.userid = $user
    $user in %hr_departure_watchlist
  match:
    $user over 14d
  outcome:
    $access_count = count($e)
  condition:
    $e and $access_count > 500
}
```
Plausible expected result: one detection instance per flagged user, with `$access_count` well above the illustrative 500-event threshold. Interpretation: same read as above; validate that `%hr_departure_watchlist` is actually populated and current before trusting a zero-result run as clean.

**[QUERY] Elastic (ES\|QL)** — chosen because this pattern's shape is a threshold aggregation over a wide lookback joined against a second data source, per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — `LOOKUP JOIN` syntax and field names illustrative; this construct is recent and version-dependent — validate against your installed Elastic release.
```esql
FROM logs-o365.audit*
| WHERE operation IN ("FileAccessed", "FileDownloaded", "FileCopied")
| STATS window_events = COUNT(*) BY user.name, BUCKET(@timestamp, 14d)
| LOOKUP JOIN hr_departures ON user.name
| WHERE window_events > 500
```
Plausible expected result: the same shape as the other four languages. Interpretation: unchanged.

**[FALSE POSITIVE]** Legitimate offboarding transition work — compiling handoff documentation, downloading personal files an employee is entitled to keep, or a manager pulling reports ahead of a transition meeting — produces the identical volume spike. A voluntary, amicable, pre-announced departure is far more likely to show a benign spike than an abrupt, contested termination; treat the departure's own context as part of the read, not the volume number alone, and route every hit through HR/Legal before any action beyond a documented review, since this pattern's false-positive rate against genuine malicious intent is high by design.

**[PIVOT]** Check whether the accessed files fall outside the departing employee's normal job function or data classification — a marketing employee suddenly pulling customer financial records reads very differently than pulling their own project files. Check for a co-occurring archive-creation event (`QC-21-01`) or removable-media write (`QC-21-03`) in the same window, which is the composite shape `QC-21-05` is built to catch.

> **SOC Management View**
> This pattern cannot run against a named employee without a documented Legal/HR governance sign-off obtained before the query runs, not after a hit — the same review discipline this book's "Why this part exists" section states at the part level, restated here because `QC-21-02` is the one pattern in this part that directly consumes HR data rather than only host telemetry. A SOC that runs this ad hoc against whichever departure HR happens to mention informally, without that sign-off, is building exactly the kind of undocumented profiling activity that turns into a legal liability the moment an employee disputes the finding.

---

### QC-21-03 — Bulk file write to removable/USB mass-storage media

| Field | Value |
|---|---|
| **Pattern ID** | `QC-21-03` |
| **MITRE** | T1052.001 (Exfiltration Over Physical Medium: Exfiltration over USB) |
| **Behavior** | A burst of file-write events lands on a volume flagged as removable storage for one user/host inside a short window, well above the isolated single-file copies typical of routine USB use. |
| **DEH cross-ref** | DEH Part 3 (host telemetry — Windows Advanced Audit Policy's Removable Storage subcategory); DEH Part 42 (Analytic Confidence) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, Elastic (ES\|QL) — YARA-L: `N/A`, see below |

**[HUNTER]** Removable-media write volume is one of the few insider-threat signals with genuinely deterministic host telemetry — but only once the Advanced Audit Policy's "Audit Removable Storage" object-access subcategory is actually enabled, which most environments never turn on. Reach for this hunt first to confirm that audit coverage genuinely exists on the target host or fleet before trusting a zero-result count as clean, since an unaudited host reports as silent by default rather than flagging the gap.

**[QUERY] Sigma** — a correlation over Windows Security Event ID 4663, filtered to write access against a removable-storage-tagged resource.

CONCEPTUAL SAMPLE — the `ResourceAttributes` field and threshold are illustrative; validate against your own Advanced Audit Policy > Object Access > Removable Storage output.
```yaml
title: Bulk File Write Burst to Removable Storage
status: experimental
correlation:
  type: event_count
  rules:
    - removable_storage_write
  group-by:
    - SubjectUserName
    - Computer
  timespan: 15m
  condition:
    gte: 50
---
title: Removable Storage Write
id: removable_storage_write
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    AccessMask: '0x2'
    ResourceAttributes|contains: 'RemovableStorage'
  condition: selection
falsepositives:
  - See [FALSE POSITIVE] below
level: medium
```
Plausible expected result: a hit names a `SubjectUserName`/`Computer` pair with 50 or more qualifying writes inside 15 minutes. Interpretation: consistent with a bulk copy operation to an attached USB mass-storage volume — the threshold is illustrative and should be validated against your own baseline of normal single-file USB use before trusting it as a cutoff.

**[QUERY] KQL (Sentinel/Defender)** — `SecurityEvent`.

CONCEPTUAL SAMPLE — same field caveats as the Sigma block above.
```kql
SecurityEvent
| where EventID == 4663 and AccessMask == "0x2"
| where ResourceAttributes has "RemovableStorage"
| summarize WriteEvents = count() by SubjectUserName, Computer, bin(TimeGenerated, 15m)
| where WriteEvents >= 50
```
Plausible expected result: the same shape as the Sigma rule. Interpretation: unchanged.

**[QUERY] SPL** — `WinEventLog:Security`.

CONCEPTUAL SAMPLE — field names assume the standard Windows TA mapping.
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4663 Access_Mask="0x2" ResourceAttributes="*RemovableStorage*"
| bin _time span=15m
| stats count as write_events by user, ComputerName, _time
| where write_events >= 50
```
Plausible expected result: unchanged from the KQL block, in table form. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL.

CONCEPTUAL SAMPLE — raw payload substring matching is a coarse substitute for a parsed `ResourceAttributes` field; confirm your log source extension exposes it directly if higher precision is needed.
```sql
SELECT username, sourcehostname AS "Host", COUNT(*) AS writeEvents
FROM events
WHERE "EventID" = 4663
  AND UTF8(payload) ILIKE '%RemovableStorage%'
GROUP BY username, sourcehostname
HAVING COUNT(*) >= 50
LAST 15 MINUTES
```
Plausible expected result: a small result set, one row per offending user/host pair. Interpretation: unchanged — this aggregation is fully expressible as a single AQL search, no multi-object build required.

*YARA-L: `N/A` — Missing schema field. UDM's file-write event types carry no confirmed device-class or removable-volume equivalent field distinguishing a write to a USB mass-storage device from any other file write; without a parser-populated marker for this, expressing the filter would mean guessing at an unconfirmed field, per DEH Part 28 §1.1's precedent for a comparable UDM schema gap.*

**[QUERY] Elastic (ES\|QL)** — chosen as the threshold/aggregation surface per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — field paths illustrative for a Winlogbeat/ECS pipeline.
```esql
FROM logs-windows.security*
| WHERE event.code == "4663" AND winlog.event_data.ResourceAttributes LIKE "*RemovableStorage*"
| STATS write_events = COUNT(*) BY user.name, host.name, BUCKET(@timestamp, 15m)
| WHERE write_events >= 50
```
Plausible expected result: unchanged from the other four languages. Interpretation: unchanged.

**[FALSE POSITIVE]** Legitimate bulk operations look identical from this telemetry alone: an employee backing up a personal photo library, an IT technician imaging a drive or deploying software via USB, or a field technician copying diagnostic logs to a USB stick as part of documented troubleshooting all produce the same write-burst shape. Correlate against a device allowlist keyed on USB vendor ID/serial number — not merely "a removable device is present" — and check whether the account holds a role with a legitimate need (IT, forensics, media production) before treating volume alone as a signal.

**[PIVOT]** Pull the device's USB descriptor (vendor ID and serial number, via Event ID 20001/20003 or the equivalent EDR device-inventory event) to determine whether it's a known corporate asset or an unrecognized personal device — an unrecognized device is a materially stronger signal than the write-burst count alone. Cross-reference `QC-21-01` for a co-occurring archive-creation event immediately preceding the write.

> **Blind Spot**
> Every query above keys on a write landing on a volume tagged removable storage in Windows auditing. A phone or tablet mounted in MTP (media transfer protocol) mode, and most personal cloud-sync clients writing to a local sync folder that later uploads on its own schedule, produce neither a removable-storage-tagged write nor a drive-letter change — the transfer happens through an entirely different code path this pattern's telemetry source cannot see. Pair this pattern with a host-based process inventory check for known sync-client binaries (per DEH Part 11) as a second, independent detection layer.

---

### QC-21-04 — Staging directory: high-volume file creation in an atypical local directory

| Field | Value |
|---|---|
| **Pattern ID** | `QC-21-04` |
| **MITRE** | T1074.001 (Data Staged: Local Data Staging) |
| **Behavior** | Many file-create events land inside one local directory that isn't a known application, package-manager, or Windows-owned path, within a short window — an ad hoc collection point assembled ahead of compression or transfer. |
| **DEH cross-ref** | DEH Part 3 (host telemetry — file-creation events); DEH Part 11 (Endpoint Detection Engineering) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (ES\|QL) |

**[HUNTER]** A staging directory rarely announces itself — nothing about a folder full of copied files looks different from a folder full of installer output unless you already know which paths are supposed to generate that volume. This hunt reaches for a directory-level file-create count, filtered against a known-good allowlist, because the interesting signal is the *destination path*, not any single file's origin, and that filter needs constant iteration against real IT behavior in your own environment before it's usable unattended.

**[QUERY] Sigma** — a correlation over Sysmon Event ID 11 (FileCreate), grouped by a derived parent-directory field.

CONCEPTUAL SAMPLE — `TargetDirectory` assumes a parent-folder field derived at ingestion from Sysmon's `TargetFilename`; not every backend exposes this natively, and the allowlist is illustrative, not exhaustive.
```yaml
title: High-Volume File Creation in a Non-Standard Directory
status: experimental
correlation:
  type: event_count
  rules:
    - file_create_outside_allowlist
  group-by:
    - Computer
    - TargetDirectory
  timespan: 10m
  condition:
    gte: 75
---
title: File Create Outside Known Allowlist
id: file_create_outside_allowlist
logsource:
  category: file_event
  product: windows
detection:
  selection:
    EventID: 11
  filter_allowlist:
    TargetFilename|contains:
      - '\AppData\Local\Packages\'
      - '\AppData\Local\Google\Chrome\'
      - '\Windows\'
      - '\Program Files\'
  condition: selection and not filter_allowlist
falsepositives:
  - See [FALSE POSITIVE] below
level: medium
```
Plausible expected result: a hit names a `Computer`/`TargetDirectory` pair with 75 or more file creates inside 10 minutes, sitting outside the allowlist. Interpretation: consistent with files being aggregated into one collection point ahead of compression or transfer — the threshold and allowlist are both illustrative starting points, not validated cutoffs.

**[QUERY] KQL (Sentinel/Defender)** — `DeviceFileEvents`.

CONCEPTUAL SAMPLE — the regex-derived `ParentDir` field is illustrative; validate the extraction against real paths in your tenant.
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where not(FolderPath has_any ("\\AppData\\Local\\Packages\\", "\\AppData\\Local\\Google\\Chrome\\", "\\Windows\\", "\\Program Files\\"))
| summarize CreateEvents = count() by DeviceName, FolderPath, bin(Timestamp, 10m)
| where CreateEvents >= 75
```
Plausible expected result: the same shape as the Sigma rule, keyed on `FolderPath` directly. Interpretation: unchanged.

**[QUERY] SPL** — Sysmon FileCreate events.

CONCEPTUAL SAMPLE — the `rex`-derived `parent_dir` field is illustrative.
```spl
index=sysmon EventCode=11
NOT (TargetFilename="*\\AppData\\Local\\Packages\\*" OR TargetFilename="*\\Program Files\\*" OR TargetFilename="*\\Windows\\*")
| rex field=TargetFilename "(?<parent_dir>.*)\\\\[^\\\\]+$"
| bin _time span=10m
| stats count as create_events by host, parent_dir, _time
| where create_events >= 75
```
Plausible expected result: unchanged from the KQL block. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL. AQL has no string-parsing function to cleanly derive a parent directory from a full file path, so this variant groups on the full path itself rather than the directory — coarser than the other languages here, and best used as a first pass that an analyst then clusters manually by eye, or against a log source extension that already exposes a separate directory field.

CONCEPTUAL SAMPLE — field names and threshold illustrative; grouping on full path rather than directory is a deliberate coarsening, not a validated cutoff.
```sql
SELECT sourcehostname AS "Host", "File Path" AS filePath, COUNT(*) AS createEvents
FROM events
WHERE "EventID" = 11
  AND "File Path" NOT ILIKE '%\Program Files\%'
  AND "File Path" NOT ILIKE '%\Windows\%'
GROUP BY sourcehostname, "File Path"
HAVING COUNT(*) >= 75
LAST 10 MINUTES
```
Plausible expected result: a coarser result set than the other languages, since each row keys on a full file path rather than a shared parent directory. Interpretation: manually group the returned rows by common directory prefix before trusting the count.

**[QUERY] YARA-L** — UDM `FILE_CREATION` events.

CONCEPTUAL SAMPLE — UDM field paths and the negative-match syntax are illustrative.
```yaral
rule staging_directory_high_volume_create {
  meta:
    description = "High-volume file creation in a directory outside the known-good allowlist"
    severity = "Medium"
  events:
    $e.metadata.event_type = "FILE_CREATION"
    $e.target.file.full_path = $path
    not $path = /(AppData\\Local\\Packages|Program Files|\\Windows\\)/i
    $e.target.asset.hostname = $host
  match:
    $host, $path over 10m
  outcome:
    $create_count = count($e)
  condition:
    $e and $create_count >= 75
}
```
Plausible expected result: one detection instance per host/path combination crossing the threshold. Interpretation: unchanged from the other languages above.

**[QUERY] Elastic (ES\|QL)** — chosen as the threshold/aggregation surface; ECS's own `file.directory` field makes this the cleanest implementation of the five.

CONCEPTUAL SAMPLE — allowlist illustrative; extend it against your own environment's real installer and update paths.
```esql
FROM logs-endpoint.events.file*
| WHERE event.action == "creation" AND NOT file.path LIKE "*\\Program Files\\*" AND NOT file.path LIKE "*\\Windows\\*"
| STATS create_events = COUNT(*) BY host.name, file.directory, BUCKET(@timestamp, 10m)
| WHERE create_events >= 75
```
Plausible expected result: unchanged from the other languages above, keyed cleanly on `file.directory`. Interpretation: unchanged.

**[FALSE POSITIVE]** Software installers, application and browser updates, and a user extracting a large vendor-provided archive all produce a comparable burst of file creates in one new directory — this is one of the noisiest patterns in the part before tuning. The allowlist shown above only excludes a handful of well-known paths; expect to iterate it against your own environment's actual installer and update behavior for at least several weeks before this is usable as anything beyond a manually reviewed hunt. Forensic imaging and e-discovery tools intentionally recreate large directory trees too, another common benign trigger specifically among IT and security staff.

**[PIVOT]** Identify the process that created the batch of files — a compression utility, a browser download process, and an unrecognized or renamed binary all read very differently. Check whether the same directory is later referenced as the source path in a `QC-21-01` archive-creation command line, or written to removable media in `QC-21-03` — either link is the composite shape `QC-21-05` targets directly.

> **Detection Autopsy — "any directory with 100+ new files in an hour is staging"**
>
> **The rule:** Alert whenever any single directory on an endpoint receives 100 or more file-create events within one hour.
>
> **Why it shipped:** It's a simple, backend-agnostic threshold with an intuitive story — a real collection point should look like a burst of file activity somewhere it doesn't usually happen.
>
> **How it failed:** Windows Update, most browser cache directories, and nearly every third-party software installer clear 100 file creates in well under an hour as a matter of routine. The rule paged on almost every patch Tuesday and was disabled within a day.
>
> **The fix:** An allowlist of known-noisy paths, exactly the one shown in the queries above, plus treating any hit as a hunt lead requiring the [PIVOT] step's process-identity check — not a standalone page.

---

### QC-21-05 — Composite: staging, archiving, and removable-media write co-occurring in one session

| Field | Value |
|---|---|
| **Pattern ID** | `QC-21-05` |
| **MITRE** | No clean single-technique mapping — see [HUNTER] framing (chains T1074.001, T1560.001, and T1052.001 as an ordered sequence) |
| **Behavior** | Within a single user/host session, a staging-directory file-create burst (`QC-21-04` shape), an archive-utility invocation against that directory (`QC-21-01` shape), and a bulk write to removable media (`QC-21-03` shape) all occur in order inside a short overall window. |
| **DEH cross-ref** | DEH Part 42 (Analytic Confidence — composite/co-occurrence framing); DEH Part 3 (host telemetry underlying all three stages); this book's `QC-21-01`, `QC-21-03`, `QC-21-04` |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL, YARA-L, Elastic (EQL) — Sigma: `N/A`, see below |

**[HUNTER]** Any one of the three stages alone is common and mostly benign; DEH Part 42's Analytic Confidence framing is explicit that stacking several independently low-confidence signals into a required, ordered co-occurrence is often the only honest way to raise this behavior class's confidence without overstating what a single event actually proves. Run this after any one of `QC-21-01`, `QC-21-03`, or `QC-21-04` fires individually to see whether it was part of a chain, or run it directly across a full user population once a departure or investigation opens and a higher bar is warranted.

*Sigma: `N/A` — Structurally poor fit, not impossible. Sigma's `temporal_ordered` correlation type can technically express a three-stage ordered sequence, but it has narrow, inconsistent backend support and no widely implemented reference translation across this book's target SIEMs — forcing this pattern through it would produce a rule that fights the language rather than one a reader could actually deploy, the same friction this book's own `N/A` convention exists to name rather than paper over.*

**[QUERY] KQL (Sentinel/Defender)** — three staged aggregations joined on host, account, and elapsed time.

CONCEPTUAL SAMPLE — window widths and thresholds illustrative; tune against your own environment before use.
```kql
let stage1 = DeviceFileEvents
    | where ActionType == "FileCreated"
    | summarize CreateEvents = count() by DeviceName, AccountName, bin(Timestamp, 10m)
    | where CreateEvents >= 75;
let stage2 = DeviceProcessEvents
    | where FileName in~ ("7z.exe", "rar.exe", "WinRAR.exe")
    | project DeviceName, AccountName, ArchiveTime = Timestamp;
let stage3 = SecurityEvent
    | where EventID == 4663 and ResourceAttributes has "RemovableStorage"
    | summarize WriteEvents = count() by Computer, SubjectUserName, bin(TimeGenerated, 10m)
    | where WriteEvents >= 20;
stage1
| join kind=inner stage2 on DeviceName, AccountName
| where ArchiveTime between (Timestamp .. Timestamp + 30m)
| join kind=inner stage3 on $left.DeviceName == $right.Computer, $left.AccountName == $right.SubjectUserName
| where TimeGenerated between (ArchiveTime .. ArchiveTime + 30m)
```
Plausible expected result: on most fleets, an empty result set most weeks; a genuine hit names one user/host pair with all three timestamps falling inside a two-hour span in the expected order. Interpretation: consistent with a staged collect-compress-transfer sequence — this is the highest-confidence output this part produces, and still not proof of intent on its own, per DEH Part 42.

**[QUERY] SPL** — successive joins chaining the same three stages.

CONCEPTUAL SAMPLE — window widths illustrative.
```spl
index=sysmon EventCode=11
| bin _time span=10m
| stats count as create_events by host, user, _time
| where create_events >= 75
| rename _time as stage1_time
| join type=inner host user
    [ search index=sysmon EventCode=1 (Image="*\\7z.exe" OR Image="*\\rar.exe" OR Image="*\\WinRAR.exe")
      | rename _time as stage2_time ]
| where stage2_time >= stage1_time AND stage2_time <= stage1_time + 1800
| join type=inner host user
    [ search index=wineventlog EventCode=4663 ResourceAttributes="*RemovableStorage*"
      | bin _time span=10m
      | stats count as write_events by host, user, _time
      | where write_events >= 20
      | rename _time as stage3_time ]
| where stage3_time >= stage2_time AND stage3_time <= stage2_time + 1800
| table host, user, stage1_time, stage2_time, stage3_time
```
Plausible expected result: unchanged from the KQL block above. Interpretation: unchanged.

**[QUERY] AQL** — this is AQL, not standard SQL. AQL has no `JOIN` clause, so the three stages below are run as separate searches for the same named user and correlated by an analyst rather than by the query itself; a standing, automated version needs QRadar's Reference Set plus Building Block plus Custom Rule chain (DEH Part 27 §2–§3) to hold state across the three stages, a materially heavier build than anything shown elsewhere in this part.

CONCEPTUAL SAMPLE — single-stage, single-user investigative search shown for stage one only; field names and window illustrative, and the cross-stage correlation shown for the other languages is performed by the analyst here, not the query.
```sql
SELECT username, sourcehostname, COUNT(*) AS createEvents
FROM events
WHERE "EventID" = 11 AND username = 'jsmith'
GROUP BY username, sourcehostname
LAST 2 HOURS
```
Plausible expected result: a per-stage count for one named user; the analyst re-runs the equivalent search for the archive-utility process event and the 4663 removable-storage write event, then checks by hand whether all three cluster inside the same two-hour window. Interpretation: unchanged from the joined languages above — the correlation logic lives with the analyst here, not inside the query.

**[QUERY] YARA-L** — a single multi-event rule with time-ordered placeholders across all three stages.

CONCEPTUAL SAMPLE — multi-event syntax, field paths, and thresholds illustrative.
```yaral
rule staging_archive_removable_media_chain {
  meta:
    description = "Staging burst, archive-utility invocation, and removable-media write chained within one session"
    severity = "High"
  events:
    $stage.metadata.event_type = "FILE_CREATION"
    $stage.target.asset.hostname = $host
    $stage.principal.user.userid = $user

    $archive.metadata.event_type = "PROCESS_LAUNCH"
    $archive.target.process.file.full_path = /(7z\.exe|rar\.exe|WinRAR\.exe)$/i
    $archive.target.asset.hostname = $host
    $archive.principal.user.userid = $user

    $write.metadata.event_type = "FILE_MODIFICATION"
    $write.target.asset.hostname = $host
    $write.principal.user.userid = $user
  match:
    $host, $user over 2h
  outcome:
    $stage_count = count($stage)
    $write_count = count($write)
  condition:
    $stage_count >= 75 and $archive and $write_count >= 20
    and $archive.metadata.event_timestamp.seconds >= $stage.metadata.event_timestamp.seconds
    and $write.metadata.event_timestamp.seconds >= $archive.metadata.event_timestamp.seconds
}
```
Plausible expected result: one detection instance per host/user pair where all three conditions and the ordering constraint hold inside the 2-hour match window. Interpretation: unchanged from the KQL/SPL forms above.

**[QUERY] Elastic (EQL)** — chosen as this pattern's shape is an ordered, joined multi-event sequence per DEH Appendix A5 §8's decision table. EQL's `sequence` stage matches individual events rather than a count threshold, so the create-burst stage below assumes `QC-21-04` has already flagged the directory — the burst-detection logic itself lives upstream in that pattern, not inside this query, per DEH Appendix A5 §4's note that EQL has no native aggregation stage.

CONCEPTUAL SAMPLE — field values and the flagged-directory assumption are illustrative.
```eql
sequence by user.name, host.name with maxspan=2h
  [file where event.action == "creation" and file.path : "*\\stage\\*"]
  [process where process.name in ("7z.exe", "rar.exe", "WinRAR.exe")]
  [file where event.action == "creation" and file.path : "*RemovableStorage*"]
```
Plausible expected result: the same three-stage correlation as the other languages, surfaced as one EQL sequence match per qualifying user/host pair. Interpretation: unchanged — the ordering constraint, not any single stage, is what makes this composite pattern's output more trustworthy than any of its three inputs alone.

**[FALSE POSITIVE]** Each stage's own false-positive driver (named under `QC-21-01`, `QC-21-03`, and `QC-21-04` above) still applies individually, but requiring all three in order inside one session meaningfully narrows them — a nightly backup job, for instance, is far less likely to also trigger a same-session removable-media write than any one stage alone. The composite pattern's main remaining driver is a genuinely busy IT or support session: a technician imaging a machine, compressing logs, and writing them to a USB drive as part of one documented ticket produces this exact three-stage shape legitimately. Check the ticket queue for the specific host and time window before escalating.

**[PIVOT]** Treat a hit here as this part's highest-confidence output and route it directly into the SOC Playbook Handbook's escalation procedure rather than continuing to hunt further inside this book's scope — pull the staging directory's full file inventory and the archive's contents list first, since that's the evidence an escalation needs and this pattern's own queries don't retrieve it.

> **What Would Change My Mind**
> This pattern assumes a 2-hour `maxspan` reasonably captures a genuine collect-compress-transfer session while excluding unrelated same-day activity. If real IT-ticket data showed that legitimate three-stage sessions (imaging, log compression, USB write) routinely span longer than 2 hours — or that genuinely malicious staging in your environment tends to happen across multiple separate sessions over several days specifically to avoid a tight-window correlation like this one — the window width above would need to widen substantially, and this pattern's confidence advantage over its three individual inputs would need to be re-argued, not assumed.

---

## Cross-references

- DEH Part 3 (Telemetry Engineering I: Host and Identity Sources) for the process-creation, file-event, and object-access telemetry mechanics underlying every pattern in this part.
- DEH Part 31 (Baselining) for constructing the per-user access-volume baseline `QC-21-02` depends on.
- DEH Part 42 (Analytic Confidence) for the scoring framework this part's own low-confidence-by-design framing and `QC-21-05`'s composite/co-occurrence logic both build on directly.
- DEH Part 11 (Endpoint Detection Engineering) for the dual-use tooling framing behind `QC-21-01` and `QC-21-04`.
- DEH Part 27 §2–§3 (QRadar's Building Block/Reference Set/Rule model) for the multi-object build every AQL block in this part cites in place of a native `JOIN`.
- DEH Parts 24–29 and Appendix A5 for the Sigma/KQL/SPL/AQL/YARA-L/EQL syntax fundamentals this part assumes rather than teaches.
- DEH Parts 41–43 and this book's own Part 28 for how these five patterns would be scored on the Detection Coverage/Quality/Debt scales rather than this part inventing its own scoring.
- This book's Part 20 (Exfiltration) and Part 15 (Host & Directory Discovery) for the explicit scope boundaries stated in "Why this part exists" above.
- This book's Part 27 (Multi-Behavior Hunt Chains) as the likely destination for a chain that cites `QC-21-01` through `QC-21-05` alongside a Part 20 network-transfer hit or a Part 3/Part 15 pre-departure enumeration signal.
