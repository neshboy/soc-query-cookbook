---
title: "How to Use This Cookbook"
part: 1
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 1 — How to Use This Cookbook

## Why this part exists

This part orients a reader before they hit the first query pattern in Part 3. It covers what this book is and is not, the series map (where to go when this book isn't the right volume), the six content tags that mark every paragraph in the domain parts, the honesty standard that governs every query block in the book, and how to read a pattern's header table at a glance. It carries no query patterns and no pattern budget — the boundary against Part 2 is explicit and load-bearing: Part 2 owns the exact pattern skeleton (the header-table field order, the tag order, the fixed six-language order, the `N/A`-with-reason convention) and the mapping of a pattern onto DEH's six-tier Detection Coverage scale. This part stops at concepts and vocabulary; Part 2 is the mechanical reference a writer or reviewer checks a pattern against.

## 1. What this book is, and what it deliberately is not

**[CONCEPT]** A single attacker behavior — password spraying, a beaconing C2 channel, a scheduled-task persistence mechanism — can be described at several different altitudes, and this book only occupies one of them. Per DEH's TERMINOLOGY.md, an **Analytic** is the implementation-independent logical statement of what pattern in telemetry indicates a behavior; a **Detection Rule** is that analytic written in one specific query language and deployed against one specific backend; a **Use Case** is the business or compliance justification for covering a behavior area at all; and a **Hunt** is a time-boxed, hypothesis-driven human investigation into a behavior with no reliable standing detection. DEH Part 1 (Detection Engineering Foundations) walks through all four with one worked example carried through each layer — this book does not re-derive that ladder, it assumes a reader has climbed it once. What this book adds is a fifth, narrower unit that sits between Analytic and Hunt: the **query pattern** (`QC-NN-SS`), a ready-to-adapt starting query for one specific behavior shape, shown in as many of the six major query surfaces as genuinely fit, framed for a hunter who needs a starting point in the next five minutes rather than a fully-taught language.

This book is organized by **attacker behavior**, not by query language. A reader who needs spray-detection queries opens Part 5 and finds Sigma, KQL, SPL, AQL, YARA-L, and Elastic side by side for that one behavior, rather than learning one language cover to cover and re-deriving every behavior's logic themselves in five other syntaxes afterward. This is a deliberate mirror image of how DEH Parts 24–29 treat the same six surfaces: DEH carries one canonical detection (a suspicious process access to `lsass.exe`, first introduced in DEH Part 23) through all six languages to teach language *semantics* — what a join costs in KQL versus SPL's `transaction`, where Sigma's translation loses meaning, why QRadar's AQL is not the deployed detection at all. This book does not re-teach any of that. It cites it, once, per pattern, and spends its own pages on sheer behavioral breadth instead: roughly 140 named query patterns across 28 parts, each pattern a hunter can adapt without first sitting through a language tutorial.

Four things this book explicitly does not do, so no later part has to repeat the disclaimer:

- **It does not teach query-language syntax fundamentals.** Operators, join semantics, aggregation-window mechanics, and backend feature ceilings belong to DEH Parts 24–29 and DEH Appendix A5. A pattern here that leans on a construct DEH has not already explained cites the DEH section that explains it, rather than re-teaching it inline.
- **It does not re-derive detection-engineering reasoning from first principles.** Why a given field matters, what a telemetry source structurally cannot see, why a naive version of a rule fails — DEH's domain parts (Parts 8–21) and DEH's own recurring Blind Spot, False Positive Trap, and Detection Autopsy callouts already carry that reasoning. This book's own callouts are pattern-specific and additive, never a second pass over ground DEH already covers.
- **It does not own coverage, quality, or debt methodology.** DEH Parts 41–43 define the six-tier Detection Coverage scale, the Detection Quality metric set, and the Detection Debt ledger. Part 28 of this book applies that existing methodology to the pattern catalog; it does not invent a parallel scoring system.
- **It does not own playbook mechanics, triage procedure, or SOC staffing.** The `[SOC MANAGEMENT]` tag defined below stays narrowly scoped to hunt cadence, false-positive cost, and the decision to graduate a hunt into a standing detection — not headcount or shift design.

## 2. The series map: four books, one job each

The NESHBOY SOC Professional Library splits four adjacent jobs across four volumes so that no one book tries to be all of them at once. Before reading further into this cookbook, check this table — it is faster than reading a wrong chapter and discovering the gap three pages in.

| If you're looking for... | Go to... |
|---|---|
| Query-language syntax, semantics, and backend translation loss | *Detection Engineering Handbook V2*, Parts 23–29 and Appendix A5 |
| The telemetry mechanics and blind spots behind a given detection | *Detection Engineering Handbook V2*, Parts 8–21 |
| Detection Coverage / Quality / Debt scoring methodology | *Detection Engineering Handbook V2*, Parts 41–43 |
| Threat-hunting methodology (hypothesis, scoping, hunt-to-detection) | *Detection Engineering Handbook V2*, Parts 34–36 |
| **A ready-to-adapt query for a named attacker behavior, across six languages** | **This book** |
| How to escalate a hunt finding through a playbook | *SIGNAL TO ACTION: The Complete SOC Playbook Handbook* |
| Whether to staff a standing hunt program, and how | *The SOC Manager's Operating Handbook* |

This book cites the other three by name — never re-explains their content at length. Per this series' cross-reference convention, if citing a DEH section seems to need more than one clause of justification, that is a signal to go read the cited section rather than to paraphrase it here.

## 3. How this book is organized: behavior first, language second

Fifteen-plus attacker behavior categories, each needing several query patterns, each pattern needing up to six language implementations, is a combinatorial shape that turns unreadable fast if every pattern repeats every piece of prose six times over. Four mechanical decisions keep the book navigable instead of becoming a wall of near-duplicate query blocks — a reader benefits from knowing all four before hitting the first domain part.

**A fixed pattern budget per part.** Every domain part (Parts 3–26) carries four to six named query patterns, no more. A behavior category that genuinely needs more room — Kerberos and directory credential attacks, cloud abuse, persistence — gets split into an additional part instead of stretched into an oversized one. This is the same discipline DEH names as a direct fix for its own first-version defect: a single breadth-pass that goes thin everywhere rather than deep anywhere.

**Interpretation logic is written once per pattern; only the query block repeats per language.** A pattern's `[FALSE POSITIVE]` and `[PIVOT]` content describes the behavior-level false-positive driver and the next investigative hop exactly once, because both are properties of the *analytic* — what the pattern is looking for — not of any one language's syntax for expressing it. Only `[QUERY]` — the fence-tagged block, its plausible expected result, and its one-line interpretation — repeats, once per language shown. DEH Part 23 established the same finding at a smaller scale: six backend implementations of one analytic are one line of detection coverage to explain, not six independent things.

**A language is omitted with a named reason, never forced.** Where a query surface is a structurally bad fit for a pattern's shape — QRadar's AQL cannot express a stateful multi-event pattern as one query, plain Elastic EQL has no aggregation stage, YARA-L has no confirmed equivalent field for some Windows-native values — the pattern says `N/A` and names the specific reason category rather than publishing an awkward, misleading translation. Section 6 below and Part 2 in full cover the four reason categories this convention uses.

**A navigation layer substitutes for linear reading.** Appendix A1 (Master Pattern Index) and Appendix A2 (Behavior × Language Coverage Matrix) let a reader find a pattern by MITRE ID, by behavior, or by language coverage without reading a part end to end — the same role DEH Appendix A5 plays for its own, much smaller six-implementation comparison set, scaled up here to a catalog roughly 140 patterns deep.

With this budget, 28 parts averaging around five patterns each yield an upper bound near 800 to 850 individual query blocks before any `N/A` omission — deliberately massive, and kept readable by the four rules above rather than by writing less per pattern.

Two parts sit outside this pattern-budget arithmetic entirely, and it is worth knowing which before a reader goes looking for their pattern count. Part 27 (Multi-Behavior Hunt Chains) stitches named patterns from earlier parts into worked end-to-end hunt narratives — a named scenario plus a sequence of cross-referenced pattern IDs in the order a hunter would actually pivot through them — and explicitly does not re-author a query that already exists under a pattern ID elsewhere in the book; a chain step cites `QC-05-02`, it does not restate it. Part 28 (Maintaining the Cookbook) applies DEH's existing coverage, quality, and debt methodology to the pattern catalog using ordinary prose sections, and carries no query patterns at all, the same as this part. Both are named exceptions to the pattern skeleton this section describes, not violations of it.

## 4. The six content tags

Every paragraph or subsection in a domain part opens with one bold, bracketed, all-caps tag naming the job that block of prose is doing. A tag never doubles up on one paragraph, and it is never a heading — it sits at the start of the text it governs. Six tags cover the entire book; this table summarizes each one's job and its boundary against the tag most often confused with it. The authoritative version, including the full do/don't table, is `STYLE-GUIDE.md` §7 — this section is the reader-facing summary, not a second source of truth.

| Tag | Governs | Most often confused with |
|---|---|---|
| `[CONCEPT]` | What a behavior is, why an attacker does it, where it sits in a kill chain — grounding stated before any query appears. Used once or twice per part at most, never once per pattern. | `[HUNTER]`, if a concept explanation starts naming a specific field or threshold — that has drifted into query territory. |
| `[HUNTER]` | The two-to-four-sentence hypothesis framing that opens every pattern: what a hunter is looking for, and when to reach for this hunt instead of trusting a standing detection. | A `[QUERY]` block's own interpretation sentence. If a `[HUNTER]` paragraph starts describing field values or a count, move that text down into the query it belongs to. |
| `[QUERY]` | One language's implementation of a pattern: the framing sentence, the fenced code block, the plausible expected result, and the interpretation. The only tag this book allows to repeat within a single pattern — once per covered language. | Nothing else in the pattern; `[QUERY]` never carries the false-positive driver or the pivot, specifically so neither is repeated six times. |
| `[FALSE POSITIVE]` | The pattern's named, common legitimate-activity driver and the tuning tradeoff that addresses it, written once after every `[QUERY]` block, shared across every language shown. | A per-language nuance — fold that into this same single entry as a labeled aside instead of writing a second `[FALSE POSITIVE]` instance. |
| `[PIVOT]` | The next query or data source to check on a hit — always a genuinely different source than the one the pattern just queried. | A restatement of the pattern's own logic in different words; that is not a pivot. |
| `[SOC MANAGEMENT]` | Hunt cadence, false-positive cost, and the hunt-to-detection graduation call for a behavior category. At most once per pattern, more often once per part. | Headcount, shift design, or budget — that content belongs to *The SOC Manager's Operating Handbook*, cited by name. |

A pattern's minimum tag set is `[HUNTER]` once, `[QUERY]` once per covered language, `[FALSE POSITIVE]` once, and `[PIVOT]` once. `[CONCEPT]` and `[SOC MANAGEMENT]` are additive. Any tag other than `[QUERY]` appearing twice in one pattern is a lint failure a reviewer rejects on sight, not a stylistic preference.

Layered on top of the six tags are the same eight recurring callout boxes DEH uses — Detection Autopsy, Hunter's Note, Engineering Reality, Blind Spot, False Positive Trap, Detection Test, SOC Management View, and What Would Change My Mind — reused verbatim in name and Markdown template for series consistency. This book does not reproduce their templates a second time; `STYLE-GUIDE.md` §6 points directly at `detection-engineering-handbook\release-v2\STYLE-GUIDE.md` §6 for the exact shape of each box, and a reviewer checks a callout's structure against that source rather than against a local copy that could drift from it. Because this book's repeating unit is a pattern rather than a chapter, callout density is capped at two boxes per pattern, and most patterns should carry zero or one — a part where every single pattern carries two callouts is over-boxed at this book's density even if each individual box is well-formed.

## 5. The honesty standard: illustrative by default

**[CONCEPT]** DEH reserves its `CONCEPTUAL SAMPLE` label for teaching snippets, because most of DEH's own query blocks are DEH's reviewed, tested, versioned detection rules — DEH Part 24 §3's Sigma block is explicitly not labeled conceptual, on the grounds that it is a real reviewed rule rather than a sketch. This book's queries are a structurally different artifact. They exist to be copied into an unknown number of reader environments this book's authors have never seen and never tested against, not to be deployed as this book's own output. Treating every query as illustrative by default is simply the honest description of what this book actually is, tightened one notch past DEH's own default rather than layered on top of it as extra caution.

Concretely, every query block in this book carries a one-line label immediately above its fence: `CONCEPTUAL SAMPLE — <one clause on what's illustrative about it>`. A plausible-expected-result sentence reads "a match here is consistent with X" rather than "this returns X," and an interpretation sentence reads "a well-instrumented environment might settle to single-digit daily volume once tuned" rather than inventing a false-precision claim this book has no production telemetry to back. The sole exception is a query block that is a direct, verified quote from official vendor documentation — expected to be rare, since most vendor docs show a generic syntax example rather than a fully worked behavior-specific detection matching this book's own pattern scope. Such a block drops the `CONCEPTUAL SAMPLE` label but must instead carry a citation into `REFERENCES.md` naming the source and retrieval context, and it may never be silently modified once quoted; a modification for fit reverts the block to a cited `CONCEPTUAL SAMPLE` adaptation rather than staying labeled verified. No query in this book, anywhere, under any tag or callout, may claim to be guaranteed to run unmodified against a real product — this is the one rule in the whole book a reviewer rejects a pull request over regardless of how polished the surrounding prose reads.

## 6. How to read a pattern header table

Every named pattern in Parts 3–26 opens with a fixed-field table immediately under its heading, before any prose. Reading one correctly, at a glance, is the single most useful skill for using this book under time pressure, since a reader deciding whether a pattern is worth opening in full should be able to tell from the table alone. The illustrative example below reproduces the same generic worked table `STYLE-GUIDE.md` §3.1 uses to define the skeleton — its field values are illustrative only, not a preview of any specific pattern's actual content. For the real, fully worked patterns this format governs, see Part 5 (Password Spraying), whose own `QC-05-01` through `QC-05-05` header tables carry their own, different Behavior, DEH cross-ref, and language-coverage values.

*(CONCEPTUAL SAMPLE — illustrative header table, reproduced from this book's own style guide to demonstrate the format; its field values are generic and do not match any specific pattern's real header table, including Part 5's own `QC-05-02`.)*

| Field | Value |
|---|---|
| **Pattern ID** | `QC-05-02` |
| **MITRE** | T1110.003 (Password Spraying) |
| **Behavior** | Single-source spray against many accounts. |
| **DEH cross-ref** | DEH Part 12 §2 (Identity: Access & Authentication Detection). |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, YARA-L — AQL and EQL: `N/A`, see below. |

Five fields, read in this order:

- **Pattern ID.** The permanent, position-independent identifier in the form `QC-NN-SS` (part number–sequence), tracked in Appendix A1. It never gets renumbered to close a gap left by a deleted pattern — a gap is recorded in Appendix A1 instead, the same discipline DEH applies to its own `DET-####` IDs. Cite a pattern by this ID, never by its position in the part ("the third pattern in Part 16"), since a later reorganization can move a pattern's position but never its ID.
- **MITRE.** The full technique or sub-technique ID and name, spelled out in this row regardless of how many times the ID was already mentioned earlier in the part — the header table is frequently read in isolation via Appendix A1 or A3, so it never relies on an earlier first-use spell-out to be understood. A pattern with no clean single-technique mapping says so explicitly (`No clean single-technique mapping — see [HUNTER] framing`) rather than forcing an ID that does not fit.
- **Behavior.** One clause naming the specific shape of activity the pattern targets — narrow enough to distinguish this pattern from its neighbors in the same part. "Single-source spray against many accounts" is a behavior; "credential attacks" is not specific enough to be this field.
- **DEH cross-ref.** The DEH part and section — and, where the pattern adapts a specific DEH analytic, the DEH detection ID — this pattern's reasoning is built on. Required, not optional, since this book's stated job is citing DEH's telemetry and detection-engineering reasoning rather than re-deriving it. An em dash here is the header table's one legitimate blank, and only when a pattern genuinely has no specific DEH detection to cite.
- **Languages covered.** Every one of the six surfaces (Sigma, KQL, SPL, AQL, YARA-L, Elastic) named explicitly, including every language marked `N/A`. A pattern that silently drops a language without listing it as `N/A` fails review outright. Where a language is `N/A`, the reason belongs to one of four named categories, expanded on in full in Part 2: an **aggregation ceiling** (the query surface has no native multi-event correlation stage), a **missing schema field** (no confirmed equivalent field exists on that backend for a value the logic depends on), a **multi-object deployment model** (the logic cannot be expressed as one query at all — QRadar's Building Block/Reference Set/Rule model is the recurring example), or a **structurally poor fit** short of impossible (the language could technically express the logic but only by fighting it). "Ran out of room" and "not commonly used for this" are never acceptable reasons on their own.

Elastic's row contributes exactly one query slot per pattern, not three — a pattern chooses EQL, Elastic KQL, or ES\|QL per the pattern's own shape (a single-event boolean match favors Elastic KQL, an ordered multi-event pattern favors EQL's `sequence` stage, a threshold or wide-lookback pattern favors ES\|QL), rather than padding the language count with all three. AQL has no dedicated fence tag anywhere in this book — every AQL block uses ```` ```sql ```` and disambiguates "this is AQL, not standard SQL" in the sentence immediately above the block, every time.

## 7. Finding a pattern without reading the book start to finish

This book is not written to be read cover to cover, and a reader under time pressure should not try. Two appendices exist specifically so a reader can jump straight to what they need:

- **Appendix A1 (Master Pattern Index)** lists every `QC-NN-SS` pattern ID, its title, owning part, MITRE ID or IDs, and which of the six languages are covered versus marked `N/A`. This is the entry point for a reader who knows the behavior or the MITRE ID but not which part owns it.
- **Appendix A2 (Behavior × Language Coverage Matrix)** condenses A1 into one row per part and one column per language, so a reader can see at a glance where six-language coverage is genuinely complete for a behavior category versus deliberately partial, and why.

A reader who wants the exact rules a pattern must follow — rather than the concepts this part introduces — goes to Part 2 next. A reader who already knows both and wants a specific behavior's queries should skip straight to the relevant domain part via Appendix A1, which is the intended, and expected, way most readers will actually use this book after the first sitting.

In practice, the expected reading path is short: read this part and Part 2 once, in full, before ever opening a domain part — together they are under an hour of reading and every later part assumes both. After that first sitting, treat Parts 3 through 26 as a lookup table rather than a narrative: arrive via Appendix A1 or A2, read the one pattern that matches the behavior in front of you, follow its `[PIVOT]` if it hits, and leave. Reading an entire domain part start to finish is occasionally useful for building broader familiarity with a behavior category, but it is never required to use any single pattern correctly, and this book is written on the assumption that most reads are the second kind, not the first.

## Cross-references

DEH Part 1 (Analytic vs. Detection Rule vs. Use Case vs. Hunt) and DEH's TERMINOLOGY.md for the vocabulary ladder this part builds on; DEH Part 23 §6 and DEH Parts 24–29 for the six-language query-surface comparison this book deliberately does not re-teach; DEH Parts 41–43 for the Detection Coverage/Quality/Debt methodology this book's Part 28 applies rather than reinvents; this book's own Part 2 for the exact pattern skeleton, tag order, and `N/A` convention in full; Appendix A1 and Appendix A2 for the pattern-navigation layer described in §7.
