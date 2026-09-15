---
title: "The Query Pattern Template & Coverage Notation"
part: 2
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 2 — The Query Pattern Template & Coverage Notation

## Why this part exists

Part 1 covered what this book is, the series map, the six content tags, the honesty standard, and a first pass at reading a pattern header table. This part is the literal specification behind that first pass: the exact header-table schema, the fixed tag order, the fixed language order, and the `N/A — <reason>` convention that every pattern in Parts 3–26 has to satisfy before a reviewer signs off on it (STYLE-GUIDE.md §3–§4). Where Part 1 told a reader what a pattern *is*, this part tells a reader — and every author working in Parts 3–26 — exactly what a pattern has to *contain*, in what order, and why the order is not arbitrary.

This part carries no query-pattern budget, the same "—" BOOK-INDEX.md assigns Part 1 and Part 28. No `QC-NN-SS` pattern originates here, and Appendix A1 tracks none against this part's number. Section 4 below walks through a fully filled-in pattern skeleton to make the mechanics concrete, but that walkthrough is explicitly not a cataloged pattern — it claims no ID, and if the same underlying behavior is ever cataloged as a real hunt pattern in Part 7 or Part 22, it gets its own permanent ID there, independent of anything shown here.

This part's other job — the one with no equivalent in Part 1 — is answering a question a reader asks the first time they try to report a hunt result upward: what does a query copied out of this book actually *mean* on Detection Engineering Handbook V2's (DEH) six-tier Detection Coverage scale (DEH Part 41)? Section 5 answers that directly. It does not invent a parallel scoring system — BOOK-INDEX.md is explicit that this book does not own coverage/quality/debt methodology, and Part 28 is where that methodology gets applied to the pattern catalog as a whole. Section 5's job is narrower: showing where a freshly-copied cookbook pattern sits on DEH's *existing* scale, and what evidence moves it up that same scale, so a reader can tell "still exploratory" from "already graduated" without reinventing DEH Part 41 from scratch.

Part 27's hunt-chain template and Part 28's coverage/quality/debt application are both exempt from the skeleton this part defines (STYLE-GUIDE.md §11) — this part does not restate either of their own templates, and a reader looking for either should go there directly rather than expecting this part to cover them.

**[CONCEPT]** One piece of vocabulary is load-bearing enough to fix before anything else: per DEH's TERMINOLOGY.md, an **Analytic** is the implementation-independent logical statement of what a pattern in telemetry indicates ("a process not on an approved allowlist opens a handle to `lsass.exe` with memory-read-capable access"); a **Detection Rule** is one platform-specific implementation of that analytic, with its own deployed, versioned lifecycle. A query pattern in this book is written at the Analytic layer, with up to six candidate Detection Rule syntaxes shown side by side — the same layer split DEH Part 23 uses for its own canonical DET-23-01 comparison, and the reason `[FALSE POSITIVE]` and `[PIVOT]` are properties of the pattern (the analytic) rather than of any one `[QUERY]` block (a candidate detection rule). Section 2 develops this distinction into the tag-order rule directly.

---

## 1. The header table, field by field

Every pattern in Parts 3–26 opens with the same five-row table, reproduced here from STYLE-GUIDE.md §3.1 exactly as it appears there, using the pattern ID that section already assigned as its own worked example (Part 5 owns the full pattern; this table only demonstrates the schema):

| Field | Value |
|---|---|
| **Pattern ID** | `QC-05-02` |
| **MITRE** | T1110.003 (Password Spraying) |
| **Behavior** | One clause naming the specific shape of activity this pattern targets. |
| **DEH cross-ref** | DEH Part 12 §2 (Identity: Access & Authentication Detection); cf. DEH DET-XX-XX if the pattern adapts a specific DEH detection. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, YARA-L — AQL and EQL: `N/A`, see below |

Five fields, all mandatory, none legitimately blank:

- **Pattern ID** (`QC-NN-SS`) is permanent the moment Appendix A1 assigns it. Deleting a pattern in a later revision leaves a logged gap in Appendix A1, not a renumbered successor — the same position-independence discipline DEH applies to `DET-####`. A pattern ID never moves because the part around it got reorganized.
- **MITRE** is spelled out in full — ID and technique name — every time it appears in a header table, regardless of how many times the same ID was already spelled out earlier in the part (STYLE-GUIDE.md §8). This is deliberate: a reader lands on a header table via Appendix A1 or A3 far more often than by reading the part start to finish, so the table has to stand alone. A pattern with no clean single-technique mapping says so directly — `**MITRE:** No clean single-technique mapping — see [HUNTER] framing` — rather than forcing a guessed ID onto behavior that doesn't cleanly fit one.
- **Behavior** is one clause, not a paragraph. Its job is letting a reader scanning Appendix A1's index tell two similarly-named patterns apart at a glance.
- **DEH cross-ref** points to the specific DEH part and section — and, where the pattern adapts one, the specific DEH detection ID — that explains the telemetry mechanics or the language-semantics reasoning this book is not re-deriving. It is required, not optional, per BOOK-INDEX.md's production model: this book's stated job is citing DEH's reasoning, not rebuilding it. An em dash here is the one field STYLE-GUIDE.md §9 tolerates as genuinely empty, and only where a pattern truly has no DEH antecedent.
- **Languages covered** names all six surfaces explicitly, every time — a language silently dropped with no `N/A` note is a lint failure (STYLE-GUIDE.md §3.1, §12). Section 3 below covers exactly what has to accompany an `N/A` entry.

> **Hunter's Note**
> If you're skimming Appendix A1 under time pressure, the header table is designed to answer "is this the pattern I need" without reading a single line of prose below it — Behavior plus Languages Covered is usually enough to decide. Read the `[HUNTER]` paragraph only after the header table has already told you this is the right pattern; reading it first, on every candidate pattern in a long Appendix A1 search, is the slow way to find what you're looking for.

---

## 2. Tag order inside a pattern, and why two tags are written once

After the header table, STYLE-GUIDE.md §3.2 fixes one order, with no reordering allowed:

1. `[HUNTER]` — once. Hypothesis framing: what you're looking for, and why a hunt beats waiting on a standing detection for this specific shape.
2. `[QUERY]` — once per covered language, in the fixed language order Section 3 defines. The only tag this book allows to repeat within one pattern.
3. `[FALSE POSITIVE]` — once, after every `[QUERY]` block. Covers every language shown, including a per-language nuance as a labeled aside where one exists.
4. `[PIVOT]` — once. The next investigative hop, not a restatement of the query just shown.
5. Up to two callout boxes, opportunistically — most patterns carry zero or one.
6. `[SOC MANAGEMENT]` — at most once, and only where hunt cadence or the graduate-to-detection tradeoff is genuinely specific to this one pattern rather than already covered at the part level.

The reason `[FALSE POSITIVE]` and `[PIVOT]` are written once, not once per language, is the single mechanical decision BOOK-INDEX.md credits with keeping ~140 patterns × up to six languages from becoming an unreadable wall of near-duplicate prose. Both are properties of the Analytic — what the pattern is looking for, and where a hit points next — not properties of any one `[QUERY]` block's syntax. Six backend implementations of one analytic are one line of detection coverage, not six independent things to explain six times; DEH Part 23 establishes exactly this finding for DET-23-01, and this book's tag order is a direct structural application of it to a catalog instead of a single worked example.

**[QUERY]**'s own internal shape is fixed too (STYLE-GUIDE.md §3.3), in this order, every time: one framing sentence naming the platform/version/telemetry source targeted; the fenced, fence-tagged, `CONCEPTUAL SAMPLE`-labeled code block; a plausible expected result stated as field values and a realistic count, not "returns matching events"; and an interpretation sentence hedged to the same honesty register as the rest of the book — "consistent with a spray attempt," never "confirms a spray attack." A `[QUERY]` block missing the expected result or the interpretation is incomplete, the same rejection standard DEH's guide applies at chapter scale, applied here per block.

The confusion authors hit most often in this book is `[HUNTER]` bleeding into `[QUERY]`'s own interpretation sentence. `[HUNTER]` is written before any query appears and stays at the level of "what am I looking for and why" — the moment a `[HUNTER]` paragraph starts naming a specific field value or threshold, it has drifted into `[QUERY]` territory and belongs there instead.

> **Engineering Reality**
> A pattern that puts `[FALSE POSITIVE]` before the last `[QUERY]` block, or repeats `[PIVOT]` once per language "for completeness," reads as more thorough than it is — it's actually redundant, and the redundancy is exactly what the fixed order exists to prevent. A reviewer checking pattern structure against STYLE-GUIDE.md §14's checklist treats an out-of-order or repeated non-`[QUERY]` tag as a structural defect, not a style preference, regardless of how well-written the duplicated content is.

---

## 3. Language order, the Elastic single-slot rule, and the `N/A` convention

`[QUERY]` blocks appear in one fixed order — Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic — matching STYLE-GUIDE.md §3.2 and the same six surfaces DEH Parts 24–29 and DEH Appendix A5 teach in depth. A language marked `N/A` in the header table is skipped entirely at this position; its omission was already recorded in the header table, so no placeholder block appears where it would have gone.

Elastic contributes exactly one query slot per pattern, never three. STYLE-GUIDE.md §4.2 sets the choice: a single-event boolean match uses Elastic KQL (cheapest, per DEH Appendix A5 §7.6); an ordered or joined multi-event pattern uses EQL's `sequence` stage; a threshold or wide-lookback aggregation pattern uses ES\|QL. State the choice in the framing sentence whenever it isn't obvious from the pattern's own shape — a reader should never have to guess why a given pattern shows ES\|QL instead of EQL.

AQL has no dedicated fence tag. Every AQL block uses `` ```sql `` and disambiguates "this is AQL, not standard SQL" in the sentence immediately above the block, every single time (DEH Appendix A5 §2, §6) — never invent an `aql` tag no renderer highlights correctly.

Where a language is genuinely a poor fit, the header table names one of four reason categories (STYLE-GUIDE.md §4.4), and each has a real DEH precedent behind it rather than an invented excuse:

| Reason category | What it means | DEH precedent |
|---|---|---|
| Aggregation ceiling | The query surface has no native construct for the aggregation the pattern's logic depends on. | DEH Appendix A5 §4: Sigma's specification has no native distinct-count correlation type; plain EQL has no aggregation stage at all. |
| Missing schema field | The backend has no confirmed equivalent field for a value the logic depends on. | DEH Part 28 §1.1: YARA-L's Unified Data Model has no confirmed `GrantedAccess`-equivalent field. |
| Multi-object deployment model | The pattern's logic cannot be one deployed artifact on this backend. | DEH Part 27 §2–§3: QRadar's Building Block / Reference Set / Rule chain, not one AQL statement. |
| Structurally poor fit, not impossible | The language can express the logic only by fighting it. | DEH Part 24 §4: Sigma's `temporal_ordered` correlation type has narrow backend support. |

Two things about this table are easy to misapply. First, the multi-object deployment model category is the one most authors reach for too eagerly and use wrong: STYLE-GUIDE.md §4.4 requires showing the investigative AQL search that would validate the pattern before the standing objects get built, in place of marking the whole language `N/A` — the same choice DEH Appendix A5 §7.4 makes for DET-27-01. A true AQL `N/A` is rarer in this book than a first read of the category list suggests, precisely because that exception almost always applies. Second, "ran out of room" or "not commonly used for this" are never acceptable reasons on their own — every `N/A` cites one of the four categories above by name, and an unexplained one is a lint failure. Section 4's walkthrough hits a genuine instance of the first category directly, which is a better demonstration than a second invented example here.

---

## 4. Filling in the skeleton: a full walkthrough

**Not a cataloged pattern.** The example below fills in every field the skeleton requires, adapted from the same LSASS-memory-access analytic DEH Part 23 §1 fixes as DET-23-01 and compares across all six surfaces in DEH Appendix A5 §7. It claims no `QC-NN-SS` ID and is not tracked in Appendix A1. If a hunt pattern for this exact behavior is later cataloged in Part 7 or Part 22, it gets its own permanent ID there, on its own merits, independent of this walkthrough.

| Field | Value |
|---|---|
| **Pattern ID** | *(none — walkthrough example only)* |
| **MITRE** | T1003.001 (OS Credential Dumping: LSASS Memory) |
| **Behavior** | A non-allowlisted process opens a memory-read-capable handle to `lsass.exe` on three or more distinct hosts within 24 hours. |
| **DEH cross-ref** | DEH Part 23 §1 (DET-23-01 analytic definition); DEH Appendix A5 §7 (all-language comparison this walkthrough adapts). |
| **Languages covered** | Sigma (`N/A` — aggregation ceiling), KQL (Sentinel/Defender), SPL, AQL (QRadar, investigative form only — see note below), YARA-L, Elastic ES\|QL |

**[HUNTER]** A scheduled per-host detection for DET-23-01 fires on one suspicious handle at a time; it says nothing about whether the same source process just did this on two other hosts an hour earlier. A hunter with a week's lookback budget instead of a five-minute scheduled window can ask a different question: has this exact source-process shape recurred across enough distinct hosts, in one day, to look like a scripted tool running fleet-wide rather than one analyst's one-off diagnostic. That fleet-wide recurrence signal is worth checking by hand periodically even where the per-host rule from DEH Part 24 §3 is already deployed and healthy, because the two questions catch different failure modes of the same underlying analytic.

**[QUERY] — Sigma.** `N/A` — aggregation ceiling. DEH Appendix A5 §4's own aggregation table marks Sigma's distinct-count row with an em dash: "not a native Sigma correlation type." A Sigma `event_count` correlation can count total matching events per host inside a window, but it cannot count the number of *distinct hosts* a given source process touched — which is the exact signal this pattern's cross-host clause depends on. Nothing below fakes around that gap with a misleading translation.

**[QUERY] — KQL (Sentinel/Defender).** Targets a Microsoft Defender for Endpoint Advanced Hunting workspace, the same native surface DEH Part 25 §7 uses for its own DET-25-01.

CONCEPTUAL SAMPLE — field names and threshold illustrative; validate `ActionType` and the `AdditionalFields.GrantedAccess` nesting against your own live Advanced Hunting schema before use.

```kql
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| extend GrantedAccess = tostring(parse_json(AdditionalFields).GrantedAccess)
| where InitiatingProcessFileName !in~ ("wmiprvse.exe", "svchost.exe", "MsMpEng.exe")
| summarize DistinctHosts = dcount(DeviceName), GrantedAccessValues = make_set(GrantedAccess) by InitiatingProcessFileName
| where DistinctHosts >= 3
```

*Expected result:* a handful of rows at most in a well-instrumented fleet, each naming one source process image, a distinct-host count between 3 and, plausibly, the low double digits if a scripted tool is actually running unattended, and the set of `GrantedAccess` values seen for that process — useful for an eyeball check even though this query, like DEH Appendix A5 §7.2's own KQL form, doesn't filter on that value (see [FALSE POSITIVE] below). *Interpretation:* a row here is consistent with one source-process shape opening handles to `lsass.exe` on several hosts in the same day — worth treating as a stronger signal than any single one of those handles alone, not as confirmed credential theft.

**[QUERY] — SPL.** Built on Sysmon Event ID 10 (ProcessAccess) ingested into Splunk, the same telemetry source DEH Part 26 §5 uses for its own DET-26-01.

CONCEPTUAL SAMPLE — assumes a maintained allowlist lookup; illustrative threshold.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe"
| search GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| lookup lsass_access_allowlist.csv SourceImage OUTPUT is_allowlisted
| where isnull(is_allowlisted)
| stats dc(ComputerName) as distinct_hosts by SourceImage
| where distinct_hosts >= 3
```

*Expected result:* similar shape to the KQL result above — one row per source-process image whose distinct-host count clears the threshold, over the search's 24-hour window, already narrowed to the memory-read-capable `GrantedAccess` values named above. *Interpretation:* the same cross-host recurrence signal, read from Sysmon telemetry instead of Defender's own agent telemetry — running both where both are available is exactly the kind of second, independent source Section 5 treats as meaningful evidence, not a redundant re-check.

**[QUERY] — AQL (QRadar).** Investigative search only. A standing QRadar detection for this exact cross-host logic needs three chained objects — a Building Block, a Reference Set, and a Rule — not one AQL statement (DEH Part 27 §2–§3); the query below is what a hunter runs by hand to validate the pattern before anyone builds those objects.

CONCEPTUAL SAMPLE — this is AQL, not standard SQL; investigative form only, and HAVING/GROUP BY support and the exact aggregate-function name vary by QRadar version — verify against your own AQL reference before running. Custom property names are illustrative and depend on your Sysmon DSM's field extraction (DEH Part 27 §3.1).

```sql
SELECT "Source Process Name", UNIQUECOUNT(sourceip) AS distinct_hosts
FROM events
WHERE QIDNAME(qid) = 'Process accessed'
  AND "Target Process Name" ILIKE '%lsass.exe%'
  AND "Granted Access" IN ('0x1010', '0x1410', '0x1438', '0x143a', '0x1fffff')
LAST 24 HOURS
GROUP BY "Source Process Name"
HAVING UNIQUECOUNT(sourceip) >= 3
```

*Expected result:* a small result set naming a source process and its distinct source-IP count for the window, already narrowed to memory-read-capable `Granted Access` values, or an empty set on a quiet day — an empty set here is a legitimate outcome, not a query failure. *Interpretation:* the same recurrence signal as the two rows above, run as a one-off hunt query rather than a deployed Offense-producing rule; a hit here is a candidate worth promoting to the three-object standing model, not yet evidence that the standing model exists.

**[QUERY] — YARA-L (Google SecOps).** Built against UDM `PROCESS_OPEN` events, the same event type DEH Part 28 §4 uses for its own re-implementation of DET-23-01.

CONCEPTUAL SAMPLE — adapted for a wide hunt window; broader match scope than the Sysmon-native forms above, see [FALSE POSITIVE] below.

```yaral
rule hunt_lsass_access_multi_host {
  events:
    $access.metadata.event_type = "PROCESS_OPEN"
    $access.target.process.file.full_path = /\\lsass\.exe$/ nocase
    $access.principal.process.file.full_path = $source_path
    not $source_path = /\\(wmiprvse|svchost|MsMpEng)\.exe$/ nocase

  match:
    $source_path over 24h

  outcome:
    $distinct_hosts = count_distinct($access.target.hostname)

  condition:
    $access and $distinct_hosts >= 3
}
```

*Expected result:* a match keyed on `$source_path` whenever that source binary's `PROCESS_OPEN` events against `lsass.exe` span three or more distinct target hostnames inside the 24-hour match window. *Interpretation:* consistent with the same cross-host recurrence signal — read the false-positive driver below before trusting a hit here as tightly as the Sysmon-native versions above.

**[QUERY] — Elastic ES\|QL.** This pattern's cross-host threshold is exactly the wide-lookback aggregation shape STYLE-GUIDE.md §4.2 assigns to ES\|QL rather than EQL or Elastic KQL; a plain single-event Elastic KQL filter (DEH Appendix A5 §7.6) could match the boolean condition but has no aggregation stage to count distinct hosts with.

CONCEPTUAL SAMPLE — field availability depends on the specific Sysmon integration version in use; illustrative threshold.

```esql
FROM logs-sysmon-*
| WHERE event.code == "10" AND winlog.event_data.TargetImage LIKE "*\\lsass.exe"
| WHERE NOT process.executable IN ("*\\MsMpEng.exe", "*\\WerFault.exe", "*\\Taskmgr.exe")
| STATS distinct_hosts = COUNT_DISTINCT(host.name) BY process.executable
| WHERE distinct_hosts >= 3
```

*Expected result:* one row per source-process executable whose distinct host count clears 3 over the full retained index queried, not a fixed 24-hour bucket unless the query is further constrained. *Interpretation:* the same recurrence signal again, over whatever lookback the reader's own retention actually supports — a wider lookback than 24 hours here is a legitimate variant, not a deviation from the pattern; see [FALSE POSITIVE] below for why this query, unlike SPL and AQL above, doesn't yet narrow by access level.

**[FALSE POSITIVE]** A fleet-wide EDR agent, backup product, or vulnerability scanner that opens low-level handles to `lsass.exe` from an agent binary running on every host is the most common driver here — it can clear a 3-distinct-host threshold in minutes on a normal day, not just under attack. The SPL and AQL queries above already narrow to the Sysmon/QRadar-native `GrantedAccess` value list consistent with memory-read access (`0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`), because most of that routine handle-opening traffic requests a lower access level than memory-read. The KQL and ES\|QL queries above do *not* filter on that value — they surface it (KQL) or omit it entirely (ES\|QL) rather than filter on it, the same documented gap DEH Appendix A5 §7's own False Positive Trap names for those two surfaces, because the exact field nesting needs live-schema verification before it's safe to filter on — so those two match any qualifying handle-open regardless of access level until a reader adds the equivalent condition. The YARA-L version is noisier still and cannot be tightened the same way: DEH Part 28 §1.1 documents that the UDM has no confirmed `GrantedAccess`-equivalent field at all, so that implementation matches *any* qualifying `PROCESS_OPEN` against `lsass.exe` even after adaptation — treat a YARA-L-only, KQL-only, or ES\|QL-only hit with less confidence than the same result corroborated by the SPL or AQL query.

**[PIVOT]** On a hit, pull the source process's own parent process and full command line first — a generic loader dropped identically across several hosts in the same day looks different from one admin's ad hoc diagnostic session repeated by habit. Second, check whether the source binary is signed and running from its expected path under `\Windows\System32\`; an attacker renaming a credential-dumping tool to match an allowlisted name (T1036.005, Match Legitimate Name or Location) defeats every exclusion list shown above identically, and a path/signature check is the next query that actually distinguishes the two cases the exclusion list itself cannot.

> **Hunter's Note**
> Run the KQL and SPL versions above against the same 24-hour window and diff the two result sets by source-process image before trusting either one alone. A source process that clears the threshold in Defender telemetry but not in Sysmon telemetry (or the reverse) is telling you something about telemetry coverage, not about the attacker — chase that discrepancy before chasing the hit itself.

> **Engineering Reality**
> DEH Part 24 §3's own Sigma implementation of this analytic is a real, reviewed, `status: test` rule — explicitly not labeled conceptual, because DEH's queries are DEH's own tested output. Every block above is labeled `CONCEPTUAL SAMPLE` anyway, per this book's stricter §12 default, because this book's queries are adapted into unknown reader environments this book's authors have never tested against. Same underlying analytic, two honestly different labels, for two structurally different kinds of artifact.

**[SOC MANAGEMENT]** Run this as a weekly wide-lookback hunt rather than a daily one — the cross-host threshold needs enough lookback to be a meaningful signal, and a same-day scheduled run mostly just re-confirms whatever the per-host DEH Part 24 §3 rule already caught. If both the KQL/Defender path and the SPL/Sysmon path stay independently tuned to an acceptable false-positive rate over a stated window, promoting this pair to a standing two-source detection is a reasonable graduation target — see Section 5 for exactly which DEH Part 41 tier that graduation would support a claim to.

---

## 5. Where a cookbook pattern sits on DEH's Detection Coverage scale

**[CONCEPT]** DEH's TERMINOLOGY.md defines Detection Coverage as a distribution across six tiers — `NO VISIBILITY`, `TELEMETRY ONLY`, `PARTIAL DETECTION`, `RELIABLE DETECTION`, `MULTI-SOURCE DETECTION`, and `TESTED / RECENTLY VALIDATED` — each requiring specific, named evidence, never a bare aggregate percentage (DEH Part 41 §2.1). A query pattern in this book is written at the Analytic layer: an implementation-independent statement of what to look for, shown in up to six candidate syntaxes. It is not, on its own, a Detection Rule with disposition history, an owner, or a validation date — the fields DEH Part 41 §3.1 requires a coverage-matrix row to carry. That gap is the entire reason this section exists: a reader who copies a pattern out of this book and reports it upward as "coverage" without doing anything else has made exactly the metadata-count error DEH Part 41 §1.1 opens by naming.

The table below states, for a cookbook pattern at each stage of a reader's own adoption, the highest DEH Part 41 tier the evidence actually available at that stage supports — not the tier the pattern would deserve if it worked as well as this book hopes.

*(CONCEPTUAL SAMPLE — a reasoning aid, not a scored claim about any specific pattern or reader environment.)*

| Stage of adoption | Evidence that actually exists | Highest tier this evidence supports |
|---|---|---|
| Read, not yet run against any telemetry | None | No tier claim at all — `NO VISIBILITY` itself requires "a named, checked absence, not silence" (DEH Part 41 §2.1); never having tried is silence. |
| Run once as a time-boxed Hunt, negative finding documented | A dated finding naming the coverage gap the hunt exposed | The *underlying technique's* honest tier — often `NO VISIBILITY` or `TELEMETRY ONLY` — recorded per DEH's TERMINOLOGY.md § Hunt; the hunt itself is not "coverage." |
| Adapted to your schema, deployed as an owned Detection Rule, no disposition history yet | An analytic plus this pattern's own `[FALSE POSITIVE]` entry as the documented gap | `PARTIAL DETECTION` at best — an analytic exists with a named gap, which is precisely what this tier requires and no more. |
| Disposition history (true/false-positive counts) collected over a stated window at an acceptable rate | Dated disposition data from one telemetry source | `RELIABLE DETECTION`. |
| A second `[QUERY]` block from the same pattern, run against a genuinely different telemetry source, independently validated | Two analytics, two sources, each separately meeting `RELIABLE DETECTION`'s bar | `MULTI-SOURCE DETECTION` — this book's own multi-language format sets a reader up for exactly this tier better than a single-language rule ever could. |
| An Atomic Test or adversary emulation passes, inside the program's recency window | A dated test run, analytic firing as expected | `TESTED / RECENTLY VALIDATED`, subject to DEH Part 41 §6.1's regression discipline — the claim expires, it does not stay true by default. |

Two consequences follow directly from this table. First, this book cannot hand a reader any tier — a tier is always earned by the reader's own evidence, never inherited from the fact that a query appears in a published cookbook. Second, this pattern's own multi-language format is not decoration: DEH Part 41 §2.1 defines `MULTI-SOURCE DETECTION` as "two or more independent sources would each, on their own, catch the technique," and a pattern that already shows a KQL implementation against Defender telemetry and an SPL implementation against Sysmon telemetry side by side — as Section 4's walkthrough does — has done half the design work a reader needs to reach that tier, before they've written a line of their own query logic.

> **SOC Management View**
> Never report "we adopted N patterns from the Cookbook" as a coverage statement to a CISO or a board — it answers a procurement question, not a security one. The tier-earning table above is what turns "we adopted a pattern" into a reportable claim: name the technique at sub-technique granularity, the tier the pattern has actually earned in your environment, and the evidence behind it, exactly as DEH Part 41 §1.2 requires for any coverage sentence — this book's contribution is a starting analytic, not a finished coverage claim.

This section deliberately stops at mapping a single pattern onto DEH's existing scale. Aggregating that mapping across the whole catalog — which patterns are still exploratory, which have graduated, where debt is accumulating — is Part 28's job, applying DEH Parts 41–43's methodology to the catalog as a body of work rather than one pattern at a time. Nothing here anticipates that aggregation or scores a pattern independently of DEH's own six tiers.

---

## Cross-references

DEH Part 1 §"Detection Rule vs. Analytic vs. Use Case vs. Hunt" (the vocabulary this part assumes throughout); DEH Parts 23–29 and DEH Appendix A5 §1–§2, §4, §7 (query-language syntax, the DET-23-01 comparison this part's walkthrough adapts, and the aggregation/deployment gaps behind its `N/A` and multi-object entries); DEH Part 41 (the six-tier Detection Coverage scale Section 5 maps cookbook patterns onto); DEH Parts 42–43 (Detection Quality and Detection Debt, applied to this book's own catalog only in Part 28, not here); this book's Part 1 (the six content tags and honesty standard this part assumes as read); this book's Part 27 (the hunt-chain template, exempt from this part's skeleton); this book's Part 28 (coverage/quality/debt methodology applied to the pattern catalog as a whole); this book's Appendix A1 (Master Pattern Index, tracking every real `QC-NN-SS` ID this part's walkthrough deliberately does not claim) and Appendix A4 (the blank pattern, front-matter, and hunt-chain templates this part's prose explains).
