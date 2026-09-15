---
title: "Registry, Startup & Alternate Persistence"
part: 13
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 13 — Registry, Startup & Alternate Persistence

## Why this part exists

**[CONCEPT]** Persistence exists to answer one question for an attacker: how do I run again without redoing the initial access? DEH Part 11 §5.1 groups every mechanism, Windows or Linux, into three categories — autostart on logon, scheduled/time-triggered execution, and service/daemon survival — and that three-category map is the boundary this part and Part 12 split along. Part 12 owns the scheduled-task, Windows-service, and cron/systemd corner of that map: the mechanisms that get their own dedicated creation event (Event ID 4698, Event ID 7045) or their own daemon-managed unit file. This part owns what's left of the autostart corner — Registry Run/RunOnce keys and the Startup folder, the two classic logon-triggered mechanisms DEH Part 11 §5.2 names under T1547.001 — plus two mechanisms that don't fit either of Part 12's buckets at all: WMI event subscription persistence, which survives reboot without a task, service, or unit entry anywhere, and a small set of execution-hijack techniques (Image File Execution Options Debugger keys, the "sticky keys" accessibility-feature swap) that trigger off something else launching a target binary rather than off a boot, logon, or schedule event in their own right.

This part explicitly does not cover: scheduled tasks, Windows services, or cron/systemd units (Part 12); the general malware-presence heuristics — unsigned-binary scoring, hash/YARA artifact matching — that apply to whatever binary a persistence mechanism ends up pointing at (Part 22); or the lineage-classification model itself, which DEH Part 11 §2 already builds and this part's patterns cite rather than re-derive. Four patterns, split into two groupings below: registry/filesystem autostart (§1) and WMI subscriptions plus execution hijacks (§2).

---

## 1. Registry and startup-folder autostart patterns

### QC-13-01 — Registry Run/RunOnce key autostart persistence

| Field | Value |
|---|---|
| **Pattern ID** | `QC-13-01` |
| **MITRE** | T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) |
| **Behavior** | A new or modified value under an `HKLM`/`HKCU` Run or RunOnce key, planted to survive reboot without a scheduled task or service entry. |
| **DEH cross-ref** | DEH Part 11 §5.2 (Windows: services, scheduled tasks, and Registry Run keys) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) |

**[HUNTER]** Run and RunOnce keys are the oldest Windows autostart mechanism, and commodity malware still reaches for them because planting one is a single registry write with no reboot needed to prove out. A standing detection here inherits whatever installer exceptions someone baked in months ago; running the same logic as a hunt re-checks the current value population against a fresher baseline instead of trusting a rule that hasn't been revisited. Reach for this hunt specifically after a phishing or LOLBin-download finding elsewhere on a host, to check whether the same intrusion also planted a low-effort autostart fallback.

**[QUERY]** Targets Sysmon Event ID 13 (Registry value set) normalized into Sigma's `registry_event` category on a Windows, Sysmon-instrumented endpoint.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use
```yaml
title: Registry Run or RunOnce Key Value Set by Non-Baseline Process
id: 8f3d6a2e-13c1-4e77-9b0e-conceptual0001
status: experimental
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    EventType: 'SetValue'
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
  filter_known_installers:
    Image|endswith:
      - '\msiexec.exe'
      - '\TrustedInstaller.exe'
  condition: selection and not filter_known_installers
falsepositives:
  - Software installers and update agents writing autostart entries during a legitimate install
level: medium
```

A match plausibly names a `TargetObject` such as `HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterAgent`, with `Details` pointing at an executable under `%AppData%` rather than `Program Files`. Once the known-installer filter above is tuned in, a well-instrumented fleet might see this settle to a handful of hits a week, spiking around patch windows and new-software rollouts. A hit naming a path outside `Program Files`/`System32` — especially `%AppData%\Local\Temp` or a randomly-named folder — is consistent with a dropped implant registering for autostart; a hit naming a recognized vendor path more plausibly reflects routine software behavior and should be checked against the baseline below before treating it as a lead.

**[QUERY]** Targets a Microsoft Sentinel workspace ingesting Microsoft Defender for Endpoint's `DeviceRegistryEvents` table.

CONCEPTUAL SAMPLE — table and field names assume a Defender-for-Endpoint-via-Sentinel schema; validate against your own workspace before use
```kql
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where InitiatingProcessFileName !in~ ("msiexec.exe", "TrustedInstaller.exe")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

A row here plausibly carries `InitiatingProcessFileName` = `powershell.exe` or a recently-dropped binary, with `InitiatingProcessFolderPath` outside the usual installer paths. Treat the same field-population caveat as above: `InitiatingProcessAccountName` matching an interactive user rather than `SYSTEM` narrows toward a user-context implant rather than an elevated installer.

**[QUERY]** Targets Splunk ingesting Sysmon via the standard Sysmon TA, `index=sysmon` with `sourcetype=XmlWinEventLog:Sysmon`.

CONCEPTUAL SAMPLE — index and sourcetype names illustrative; adjust to your own TA's field extraction
```spl
index=sysmon EventCode=13
| search TargetObject="*\\CurrentVersion\\Run\\*" OR TargetObject="*\\CurrentVersion\\RunOnce\\*"
| where NOT match(Image, "(?i)msiexec\.exe$|TrustedInstaller\.exe$")
| table _time, Computer, User, Image, TargetObject, Details
| sort - _time
```

Expect a low but nonzero daily row count on a fleet with Sysmon Event ID 13 collection enabled fleet-wide; a burst of hits from one `Computer` in a short window, rather than the usual one-off installer pattern, is the shape worth chasing first.

**[QUERY]** This is AQL, QRadar's own query language, not standard SQL. Targets Sysmon registry events forwarded via WinCollect, matched against the raw payload since not every DSM extension normalizes `TargetObject` into its own custom property.

CONCEPTUAL SAMPLE — the `qid` value and reliance on raw-payload matching are illustrative; confirm your own DSM's QID mapping and whether it exposes a normalized registry-path custom property before use
```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
       sourceip, username, UTF8(payload) AS RawPayload
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Sysmon%'
  AND qid = 13
  AND (UTF8(payload) ILIKE '%CurrentVersion\Run\%' OR UTF8(payload) ILIKE '%CurrentVersion\RunOnce\%')
  AND UTF8(payload) NOT ILIKE '%msiexec.exe%'
LAST 24 HOURS
```

A returned row's `RawPayload` plausibly contains the full Sysmon XML/LEEF fragment with `TargetObject` and `Details` embedded as text rather than as separate normalized fields — expect to grep the payload string itself for the value name and target path rather than projecting them as columns, unless your DSM extension has added that mapping.

**[QUERY]** Targets Google SecOps (Chronicle) with Sysmon registry events mapped into UDM.

CONCEPTUAL SAMPLE — UDM field mapping illustrative; confirm your own parser populates `target.registry.registry_key` for Sysmon Event ID 13 before use
```yaral
rule registry_run_key_autostart_persistence {
  meta:
    description = "Registry Run/RunOnce key value set outside known installer processes"
    severity = "MEDIUM"
  events:
    $reg.metadata.event_type = "REGISTRY_MODIFICATION"
    $reg.target.registry.registry_key = /CurrentVersion\\Run/ nocase
  condition:
    $reg
}
```

A firing detection plausibly surfaces `target.registry.registry_key` alongside `principal.process.file.full_path` for the writing process; treat any hit as a starting point, since this rule doesn't yet exclude known installers the way the Sigma and KQL versions above do — add that filter before running it standing.

**[QUERY]** Targets Elastic Agent/Winlogbeat's Sysmon module data in `logs-windows.sysmon_operational-*`. Run and RunOnce writes are frequent enough that a raw single-event match, unlike the boolean form shown in the five languages above, is better paired with a first-seen aggregation over a wide lookback — the ES\|QL shape per §4.2's decision rule.

CONCEPTUAL SAMPLE — index pattern and field names illustrative; validate against your own Elastic Agent Sysmon-module mapping
```esql
FROM logs-windows.sysmon_operational-*
| WHERE event.code == "13" AND registry.path RLIKE ".*CurrentVersion\\\\Run.*"
| STATS first_seen = MIN(@timestamp), hit_count = COUNT(*) BY host.name, registry.path, registry.value
| WHERE first_seen >= NOW() - 30 days
| SORT first_seen DESC
```

A row where `first_seen` falls inside the last 30 days on a host with months of prior uptime is a stronger signal than the same path appearing on a host imaged within that window; the count column helps separate a one-off write from a script hammering the same key repeatedly.

**[FALSE POSITIVE]** Legitimate software writes to Run/RunOnce constantly — browser and Java/Adobe updaters, cloud-sync clients (OneDrive, Dropbox), conferencing tools, and printer-driver installers all register autostart entries, and RunOnce specifically gets used by Windows Update and driver installers for post-reboot cleanup tasks. DEH Part 11 §5.2 names this directly as "one of the noisier persistence-detection surfaces in this section, needing a baseline of known-legitimate registry writers more than most" — build that baseline from your own environment's observed writers rather than a generic vendor list, since the exact population of installers varies by fleet.

**[PIVOT]** Resolve the target path the Run value points at and check it against Part 9's LOLBin patterns or Part 22's unsigned-binary/rarity signals; separately, check the writing process's own lineage tier against DEH Part 11 §2.2 — a Run-key write from a process that itself has no baseline history raises the whole chain's confidence together.

---

### QC-13-02 — Startup-folder shortcut and script persistence

| Field | Value |
|---|---|
| **Pattern ID** | `QC-13-02` |
| **MITRE** | T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) |
| **Behavior** | A shortcut, script, or executable dropped directly into a user or all-users Startup folder, launched automatically at the next interactive logon. |
| **DEH cross-ref** | DEH Part 11 §5.2 (T1547.001's registry-key half is DEH's own worked detail; the Startup-folder filesystem half of the same sub-technique is this book's own extension) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) |

**[HUNTER]** The Startup folder does the same job as a Run key — anything placed there launches at the next interactive logon — but it's a filesystem write, not a registry write, so it lands in an entirely different telemetry stream and gets missed by a team that only built the Run-key detection above. Hunt this specifically when a Run-key sweep comes back clean but you still suspect logon-triggered persistence; an attacker who assumes the registry side is watched has an easy, well-documented fallback sitting right here.

**[QUERY]** Targets Sysmon Event ID 11 (FileCreate) on a Windows endpoint.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own Sysmon configuration
```yaml
title: File Dropped Into User or Common Startup Folder
id: 2b6f9e10-4a1c-4b7f-9d3e-conceptual0002
status: experimental
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|contains:
      - '\Start Menu\Programs\Startup\'
      - '\Start Menu\Programs\StartUp\'
  filter_setup:
    Image|contains: '\Windows\Installer\'
  condition: selection and not filter_setup
falsepositives:
  - Installers dropping a launch-on-login shortcut for the software they just installed
level: medium
```

A match plausibly names a `.lnk` file or a script (`.vbs`, `.bat`, `.ps1`) written into `...\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`, with `Image` showing whatever process performed the write — a browser process, an archive-extraction tool, or an Office application are all plausible in an intrusion context. A `.lnk` file's *target* isn't captured by this event at all, only its creation — see the pivot below.

**[QUERY]** Targets a Microsoft Sentinel workspace ingesting Defender's `DeviceFileEvents` table.

CONCEPTUAL SAMPLE — table and field names assume a Defender-for-Endpoint-via-Sentinel schema; validate before use
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any (@"Start Menu\Programs\Startup", @"Start Menu\Programs\StartUp")
| where InitiatingProcessFileName !~ "msiexec.exe"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

A row plausibly shows `InitiatingProcessFileName` = `winword.exe`, `chrome.exe`, or an archive utility rather than a recognized installer — that mismatch between the writing process and "software you'd expect to add itself to Startup" is the signal worth chasing.

**[QUERY]** Targets Splunk ingesting Sysmon via the standard TA.

CONCEPTUAL SAMPLE — index and sourcetype illustrative
```spl
index=sysmon EventCode=11
| search TargetFilename="*\\Startup\\*"
| where NOT match(Image, "(?i)\\\\Windows\\\\Installer\\\\")
| table _time, Computer, User, Image, TargetFilename
| sort - _time
```

Expect this to run quieter than the Run-key query above on most fleets — the Startup folder is a less common installer default than a Run key — so a hit here carries somewhat more weight per occurrence, though not enough on its own to skip the false-positive check below.

**[QUERY]** This is AQL, not standard SQL. Targets Sysmon FileCreate events forwarded via WinCollect.

CONCEPTUAL SAMPLE — `qid` value illustrative; confirm your own DSM's mapping
```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
       sourceip, username, UTF8(payload) AS RawPayload
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Sysmon%'
  AND qid = 11
  AND UTF8(payload) ILIKE '%\Startup\%'
LAST 24 HOURS
```

The returned payload text plausibly embeds both `TargetFilename` and the writing `Image` path as substrings; expect to parse them out of the raw field rather than getting separate columns unless your DSM extension normalizes FileCreate events specifically.

**[QUERY]** Targets Google SecOps (Chronicle) with Sysmon file-creation events mapped into UDM.

CONCEPTUAL SAMPLE — UDM field mapping illustrative
```yaral
rule startup_folder_drop {
  meta:
    description = "File created in a user or common Startup folder"
    severity = "MEDIUM"
  events:
    $file.metadata.event_type = "FILE_CREATION"
    $file.target.file.full_path = /\\Startup\\/ nocase
  condition:
    $file
}
```

A hit plausibly names `target.file.full_path` alongside `principal.process.file.full_path` for the creating process — cross-check that process against a known-installer allowlist before treating a hit as actionable.

**[QUERY]** Targets Elastic Agent/Winlogbeat Sysmon-module data. This is a single-event boolean match, so Elastic KQL is the appropriate surface per §4.2.

CONCEPTUAL SAMPLE — field names illustrative
```kql
file.path : "*\\Startup\\*" and event.action : "creation" and not process.name : "msiexec.exe"
```

A match returns the creating `process.name`, `process.executable`, and the new `file.path` in the same document; a creating process with no code-signing metadata attached (where your Elastic Agent policy captures that) is worth escalating ahead of a signed one.

**[FALSE POSITIVE]** Installers for software the user expects to run at logon — VPN clients, cloud-storage sync agents, Steam, printer utilities — deliberately drop a Startup-folder shortcut as part of a normal install, and IT-deployed logon scripts sometimes use this folder instead of a GPO script path. Baseline by the *signer or publisher of the shortcut's target executable*, not the folder path alone, since the folder path is exactly what every legitimate entry and every malicious one share.

**[PIVOT]** Resolve the `.lnk` file's actual target — Sysmon's FileCreate event captures only the shortcut's own creation, not what it points at — and check that target path for a LOLBin, an unsigned binary, or a location under `%TEMP%`/`%AppData%`; also check the creating process's own lineage per DEH Part 11 §2, the same pivot used for QC-13-01.

> **Hunter's Note**
> Don't stop at "a `.lnk` was created in Startup." Pull the shortcut's target path and arguments — most EDR agents resolve this for you; if yours doesn't, parsing the `.lnk` binary format's `LinkTargetIDList` is the fallback — before deciding whether the hit matters. A shortcut pointing at `C:\Program Files\Zoom\bin\Zoom.exe` and one pointing at `%AppData%\Roaming\update.exe` create an identical Sysmon Event ID 11 entry and look identical until you check the target.

---

## 2. WMI event subscriptions and execution-hijack persistence

### QC-13-03 — WMI event subscription persistence

| Field | Value |
|---|---|
| **Pattern ID** | `QC-13-03` |
| **MITRE** | T1546.003 (Event Triggered Execution: Windows Management Instrumentation Event Subscription) |
| **Behavior** | A WMI permanent event subscription — an `__EventFilter`, an event consumer, and a `__FilterToConsumerBinding` tying them together — registered to re-trigger a payload on a system event, with no scheduled task, service, or unit entry anywhere. |
| **DEH cross-ref** | DEH Part 11 §5.1 (Figure 11.2, cross-OS persistence mechanism map — WMI event subscription named as item W5 under the service/daemon category) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar) — investigative single-stage search only; the full three-stage correlation needs a QRadar Rule chaining Building Blocks, not one AQL query, YARA-L: `N/A` — missing schema field, Elastic (EQL sequence) |

**[HUNTER]** WMI subscription persistence survives a reboot, needs no scheduled task or service entry for Part 12's detections to catch, and — because the payload runs inside `WmiPrvSE.exe` rather than as its own freestanding process — produces a process tree that looks nothing like the `cmd.exe`/`powershell.exe` chains most lineage-based hunting expects. Hunt this specifically on a host where lineage-based checks (DEH Part 11 §2) keep coming back clean but something else — a beacon, a discovery burst — suggests persistence is still active.

**[QUERY]** Targets Sysmon Event IDs 19 (WmiEventFilter activity detected), 20 (WmiEventConsumer activity detected), and 21 (WmiEventConsumerToFilter activity detected) on a Windows endpoint with the WMI-focused Sysmon config sections enabled.

CONCEPTUAL SAMPLE — field names illustrative; Sysmon's WMI event IDs are configuration-gated and disabled in several common baseline configs — confirm they're actually collecting before trusting an empty result as clean
```yaml
title: WMI Permanent Event Consumer Registered
id: 6c1e4a80-7f22-4e19-9a4d-conceptual0003
status: experimental
logsource:
  product: windows
  category: wmi_event
  service: wmi
detection:
  selection:
    EventID: 20
  condition: selection
falsepositives:
  - Configuration management and monitoring tools (SCCM, PowerShell DSC) that register their own permanent WMI consumers
level: medium
```

A match plausibly shows `Type: CommandLineEventConsumer` with a `Destination` field naming the actual command line the consumer will run — the single highest-value field in this whole pattern, since it's where the payload itself is visible. A well-tuned environment might see single-digit monthly hits once known management-tool consumers are excluded.

**[QUERY]** Targets a Microsoft Sentinel workspace ingesting Defender's advanced-hunting WMI activity events.

CONCEPTUAL SAMPLE — table and column names illustrative; Defender's exact WMI-activity table/column naming should be confirmed against your own workspace schema before use
```kql
DeviceEvents
| where ActionType in ("WmiCreateEventConsumer", "WmiCreateEventFilter", "WmiBindFilterToConsumer")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName
| order by Timestamp desc
```

A returned row's `AdditionalFields` plausibly carries the consumer's command-line template or the filter's WQL query as a nested JSON value; expect to parse that field explicitly rather than getting it as a top-level column.

**[QUERY]** Targets Splunk ingesting Sysmon's WMI event IDs via the standard TA.

CONCEPTUAL SAMPLE — index/sourcetype illustrative
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time, Computer, EventCode, Operation, EventNamespace, Name, Type, Destination, Consumer, Filter
| sort - _time
```

Expect three related rows per real subscription registration, close together in time, one per Sysmon WMI event ID — a single isolated row without its pair (a filter with no matching consumer, or vice versa) is either a partial/failed registration or a query window that split the sequence.

**[QUERY]** This is AQL, not standard SQL. Targets the raw Microsoft-Windows-WMI-Activity/Operational channel forwarded via WinCollect. QRadar's Building Block/Reference Set/Rule model can't express the ordered three-event correlation (filter, consumer, binding) as a single query — per DEH Part 27 §2–3's own precedent for this exact limitation — so what follows is the investigative single-stage search you'd run before building that correlation as a standing QRadar Rule, not the correlation itself.

CONCEPTUAL SAMPLE — `qid` value illustrative; confirm your own DSM's mapping for this channel
```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
       sourceip, username, UTF8(payload) AS RawPayload
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%WMI-Activity%'
  AND UTF8(payload) ILIKE '%CommandLineEventConsumer%'
LAST 24 HOURS
```

A returned row surfaces one half of the registration — typically the consumer creation, since that's where `CommandLineEventConsumer` appears in the raw payload — leaving the matching filter and binding events to be checked manually against the same host and a nearby timestamp.

**YARA-L (Google SecOps): N/A — missing schema field.** Chronicle's UDM has no confirmed field set for WMI filter/consumer/binding-specific metadata (namespace, WQL query text, consumer type, `CommandLineTemplate`) comparable to what it has for generic process or registry events, the same category of gap the style guide's own worked example flags for `GrantedAccess` (DEH Part 28 §1.1). Forcing this pattern into generic `PROCESS_LAUNCH`/`REGISTRY_MODIFICATION` UDM event types would drop exactly the fields — the WQL trigger condition and the consumer's command line — that make this pattern worth running at all, so this book doesn't publish a YARA-L block for it here.

**[QUERY]** Targets Winlogbeat/Elastic Agent's Sysmon module ingesting Sysmon Event IDs 19–21. This is an ordered, joined multi-event pattern, so EQL's `sequence` stage is the right surface per §4.2's decision rule.

CONCEPTUAL SAMPLE — index pattern, `event.code` mapping, and field names illustrative; validate against your own Elastic Agent Sysmon-module output
```eql
sequence by host.id with maxspan=5m
  [any where event.code == "19"]
  [any where event.code == "20"]
  [any where event.code == "21"]
```

A completed sequence plausibly returns all three events, in order, on one host within the five-minute window — the complete WMI persistence registration correlated into a single hit, rather than three events an analyst would otherwise have to stitch together by hand. A partial match (filter and consumer, no binding) is consistent with an incomplete or failed registration attempt, or a management tool's own transient WMI usage that never got bound.

**[FALSE POSITIVE]** Legitimate management tooling registers permanent WMI event subscriptions as its normal operating mode — SCCM/Configuration Manager, PowerShell Desired State Configuration, and several monitoring agents all create `__EventFilter`/consumer/binding triples for hardware or power-state change detection. Baseline the consumer's `CommandLineTemplate`/`Destination` value against known management-tool binaries and namespaces, not against the mere existence of a subscription — excluding "any WMI subscription" to cut this noise would blind the whole pattern.

**[PIVOT]** Pull the consumer's command-line template (`Destination` in Sysmon's Event ID 20, or the equivalent field in your telemetry source) and run it through the same LOLBin/obfuscation checks Part 8 and Part 9 apply to any other command line; separately, check the WQL query inside the `__EventFilter` for its trigger condition (process start, logon, a specific timer interval) to understand when the payload is designed to fire again.

> **Blind Spot**
> Every query above depends on WMI's own COM API and on Sysmon's ETW-based instrumentation of it — both can be bypassed by editing the CIM repository's backing files (`OBJECTS.DATA` and related files under `%SystemRoot%\System32\wbem\Repository`) directly while the WMI service is stopped, which registers the same subscription with no `__EventFilter`/consumer/binding COM call ever made and therefore no Sysmon Event ID 19–21 at all. This technique is far less common than the COM-API path because it's riskier to get right, but a rule built only around Sysmon's WMI events is blind to it by construction; periodic offline CIM-repository integrity checking is the only mitigation this part is aware of, and it sits outside the scope of any query shown here.

---

### QC-13-04 — Image File Execution Options and accessibility-feature hijack persistence

| Field | Value |
|---|---|
| **Pattern ID** | `QC-13-04` |
| **MITRE** | T1546.012 (Event Triggered Execution: Image File Execution Options Injection); T1546.008 (Event Triggered Execution: Accessibility Features) |
| **Behavior** | A registry `Debugger` value written under Image File Execution Options for a target binary, or a swapped accessibility-feature binary, that hijacks the target's launch to run attacker code in its place. |
| **DEH cross-ref** | DEH Part 11 §5.1 (the autostart/scheduled/service-daemon persistence framework); this pattern's hijack-on-launch shape is this book's own extension beyond DEH's own named mechanism list |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (KQL) |

**[HUNTER]** Image File Execution Options Debugger hijacks and the "sticky keys" accessibility swap both give an attacker code execution triggered by something else launching a target binary — most notoriously, an unauthenticated SYSTEM-level command prompt at the Windows logon or RDP pre-auth screen, via `sethc.exe` or `utilman.exe`. The population of legitimate writers to this specific registry path against this specific set of binaries is close to zero, which makes it one of the few hunts in this part worth running as a scheduled sweep with no prior lead.

**[QUERY]** Targets Sysmon Event ID 13 (Registry value set) on a Windows endpoint.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own Sysmon configuration
```yaml
title: IFEO Debugger Value Set on Accessibility or Console Binary
id: 4d9c2b70-8e31-4f6a-b1d5-conceptual0004
status: experimental
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    EventType: 'SetValue'
    TargetObject|contains: '\Image File Execution Options\'
    TargetObject|endswith: '\Debugger'
    TargetObject|contains|any:
      - 'sethc.exe'
      - 'utilman.exe'
      - 'osk.exe'
      - 'Magnify.exe'
      - 'Narrator.exe'
      - 'DisplaySwitch.exe'
  condition: selection
falsepositives:
  - Rare -- a small number of EDR/AV self-protection agents use IFEO-style hooking against their own monitored binaries
level: high
```

A match plausibly shows `TargetObject` = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger` with `Details` = `C:\Windows\System32\cmd.exe`. This is a low-volume, high-confidence pattern — expect single digits of hits per year fleet-wide, not a noisy baseline like QC-13-01's.

**[QUERY]** Targets a Microsoft Sentinel workspace ingesting Defender's `DeviceRegistryEvents` table.

CONCEPTUAL SAMPLE — table/field names assume a Defender-for-Endpoint-via-Sentinel schema; validate before use
```kql
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has "Image File Execution Options" and RegistryValueName == "Debugger"
| where RegistryKey has_any ("sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe", "DisplaySwitch.exe")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
```

A hit plausibly shows `RegistryValueData` naming `cmd.exe` or `powershell.exe`, with `InitiatingProcessAccountName` carrying elevated (often `SYSTEM` or local-admin) rights, since writing to this `HKLM` path requires them.

**[QUERY]** Targets Splunk ingesting Sysmon via the standard TA.

CONCEPTUAL SAMPLE — index/sourcetype illustrative
```spl
index=sysmon EventCode=13
| search TargetObject="*Image File Execution Options*Debugger"
| search TargetObject="*sethc.exe*" OR TargetObject="*utilman.exe*" OR TargetObject="*osk.exe*" OR TargetObject="*Magnify.exe*" OR TargetObject="*Narrator.exe*" OR TargetObject="*DisplaySwitch.exe*"
| table _time, Computer, User, Image, TargetObject, Details
```

Given the rarity of this pattern, treat any single row as worth a full look rather than tuning for volume — there is essentially no legitimate baseline to build against for this specific binary list.

**[QUERY]** This is AQL, not standard SQL. Targets Sysmon registry events forwarded via WinCollect.

CONCEPTUAL SAMPLE — `qid` value illustrative
```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
       sourceip, username, UTF8(payload) AS RawPayload
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Sysmon%'
  AND qid = 13
  AND UTF8(payload) ILIKE '%Image File Execution Options%'
  AND UTF8(payload) ILIKE '%Debugger%'
LAST 7 DAYS
```

Given the pattern's near-zero legitimate base rate, a wider lookback (7 days rather than 24 hours) is a reasonable default for a periodic hunt run rather than a tight standing-detection window.

**[QUERY]** Targets Google SecOps (Chronicle) with Sysmon registry events mapped into UDM.

CONCEPTUAL SAMPLE — UDM field mapping illustrative
```yaral
rule ifeo_debugger_accessibility_hijack {
  meta:
    description = "IFEO Debugger value set against an accessibility or console binary"
    severity = "HIGH"
  events:
    $reg.metadata.event_type = "REGISTRY_MODIFICATION"
    $reg.target.registry.registry_key = /Image File Execution Options/ nocase
    $reg.target.registry.registry_value_name = "Debugger"
  condition:
    $reg
}
```

A hit surfaces `target.registry.registry_key` and, where the parser populates it, `target.registry.registry_value_data` naming the hijack target — check that value directly rather than treating any IFEO Debugger write as automatically the accessibility-binary variant, since this rule doesn't scope to the specific six binaries the way the Sigma/KQL versions above do.

**[QUERY]** Targets Elastic Agent/Winlogbeat's Sysmon module data. This is a single-event boolean match, so Elastic KQL is the appropriate surface per §4.2.

CONCEPTUAL SAMPLE — field names illustrative
```kql
registry.path : "*Image File Execution Options*Debugger" and registry.path : ("*sethc.exe*" or "*utilman.exe*" or "*osk.exe*" or "*Magnify.exe*" or "*Narrator.exe*" or "*DisplaySwitch.exe*")
```

A match returns the full `registry.path` and, where captured, `registry.data.strings` holding the hijack target binary — `cmd.exe` or `powershell.exe` are the overwhelmingly common values seen in public write-ups of this technique.

**[FALSE POSITIVE]** Against the six accessibility/console binaries named above, legitimate use is close to nonexistent. Against *other* target binaries, IFEO Debugger-style hooking has real legitimate uses — application-compatibility shims, crash-diagnostic tooling, and some EDR/AV products' own self-protection hooks — so a rule scoped broadly to "any IFEO Debugger write" needs identity correlation against the known agent making the write; a rule scoped to the six named binaries needs none.

**[PIVOT]** Check whether the host is RDP- or console-accessible, and pull nearby logon telemetry (4624/4625 with Logon Type 10 for RDP, or a console session) around the same timestamp — the sticky-keys variant of this technique is specifically valuable for unauthenticated pre-login access, so a logon attempt clustered around the registry write is the corroborating signal to chase next; on a jump box or bastion host, escalate straight into Part 16's admin-tool lateral-movement patterns rather than treating this as an isolated host finding.

> **Detection Autopsy — "alert on any IFEO Debugger write, any target binary"**
>
> **The rule:** Fires on every registry write to a `Debugger` value anywhere under Image File Execution Options, regardless of which binary it targets.
>
> **Why it shipped:** T1546.012 is explicitly built around the Debugger-value mechanism, and matching the value name alone reads as complete technique coverage in a design review.
>
> **How it failed:** A handful of EDR/AV agents and crash-diagnostic tools legitimately use IFEO-style hooking for self-protection or silent-exit monitoring against binaries they themselves manage, and every agent install, upgrade, or reconfiguration re-fires this rule — noise that comes from the security stack itself, which trains analysts to dismiss the alert without checking which binary it actually named.
>
> **The fix:** Split the classification in two. The six accessibility/console binaries above get a standing high-confidence classification with no baseline required, since their legitimate population is effectively zero. Every other target binary needs the writing process checked against a known EDR/AV agent identity before escalating — the query blocks above implement only the first half; the second half is a standing exception list your own environment has to build.

**[SOC MANAGEMENT]** Per the zero-tolerance precedent DEH Part 11 §6 sets for shadow-copy deletion and Event ID 1102, a Debugger value written against `sethc.exe`, `utilman.exe`, `osk.exe`, `Magnify.exe`, `Narrator.exe`, or `DisplaySwitch.exe` should escalate to Tier 2 immediately with no tuning window — there is no routine business process that writes to this value against this binary set, and a team suppressing it for volume has a scoping problem, not a tuning problem.

---

## Cross-references

DEH Part 11 §5 (cross-OS persistence mechanism map and the Windows autostart/service worked detail) and DEH Part 11 §2 (lineage classification, cited by every pivot in this part) ground the behavior reasoning this part doesn't re-derive; DEH Parts 23–29 own the Sigma/KQL/SPL/AQL/YARA-L/EQL syntax fundamentals these query blocks assume; DEH Parts 41–43 own the coverage/quality/debt scoring these patterns would be measured against once graduated past hunt stage. Within this book, see Part 12 for the scheduled-task, service, and cron/systemd persistence mechanisms this part deliberately excludes; Part 9 and Part 22 for the LOLBin and malware-presence checks every pivot above hands off to; and Part 16 for the lateral-movement patterns a sticky-keys hijack (QC-13-04) on a jump box or bastion host escalates into. See Appendix A1 for this part's pattern IDs and Appendix A2 for where six-language coverage above is genuinely complete versus deliberately partial.
