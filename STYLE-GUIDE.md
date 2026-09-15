# The SOC Threat Hunting Query Cookbook — STYLE-GUIDE.md

**Status:** Final, adopted before any part is authored or reviewed.
**Applies to:** every part, pattern, callout, and table in this book.
**Audience:** every writer and technical reviewer working on this book.
**Relationship to the series:** this guide inherits directly from `detection-engineering-handbook\release-v2\STYLE-GUIDE.md` (hereafter "DEH's guide") wherever a rule is language-, formatting-, or honesty-related and this book has no reason to diverge — code block fence tags, Event ID notation, MITRE ID formatting, and the eight callout templates are reused **verbatim**, not reinvented, for series consistency. This guide states those rules again in full rather than only pointing at DEH's copy, because the query-pattern format below is this book's own invention and needs to sit next to the rules it builds on, not force a reader to hold two documents open. Where this guide is silent, DEH's guide governs.

## Why this document exists, and how it differs from DEH's

DEH's STYLE-GUIDE.md exists because 55 independent single-pass agents produced five shapes for one callout box with no shared contract. This book has a narrower but sharper risk: it is organized around one repeating unit — the **query pattern** — that recurs roughly 140 times across 28 parts, each with up to six language variants. A style drift here doesn't produce five shapes for one callout; it produces a book where pattern 47 is unreadable in a different way than pattern 12, at a scale where a reader notices immediately because they are comparing patterns constantly, not reading linearly. This guide's job is to lock the pattern skeleton down so hard that a reader can predict, before reading it, exactly where the false-positive driver and the pivot suggestion will be in any pattern in the book.

**"Must"** means a PR gets rejected if it doesn't comply. **"Should"** means deviate only with a reason recorded in the PR description. **"Avoid"** is a strong default a reviewer can override with justification, recorded as a guide change, not silent drift.

---

## 1. Voice and Tone

### 1.1 The core rule

Write like a senior threat hunter handing a query to a peer who is going to paste it into their own console under time pressure and adapt it in the next five minutes — not like a vendor blog post, and not like a textbook building up to a concept. The reader is not here to learn what a beacon is; DEH's Part 14 already taught that. They are here to get a starting query, know what it plausibly returns, know what will make it lie to them, and know what to check next. Every sentence should survive: **does this get the reader to a working, adapted query faster, or does it just sound like it does?**

Concretely, inheriting DEH's rules directly:

- **State the query's purpose, then the query.** Don't build up to it.
- **Name the false-positive driver; don't gesture at "may generate noise."**
- **Prefer the concrete number.** "Fires on the backup service account nightly at 02:00" beats "may fire on scheduled jobs."
- **Name the field, the operator, the threshold** — not the adjective.
- **Active voice, named actor** ("the attacker," "the query," "the analyst"). Passive only when the actor genuinely doesn't matter.
- **Commit to a claim about what a query plausibly returns**, and say so explicitly when that claim is thin: "this threshold is illustrative — validate the count against your own baseline before trusting it as a cutoff."
- Contractions are fine; this book has a spoken-voice register.

### 1.2 Cookbook-specific tightening: no scene-setting before a query

DEH's parts open sections with grounding prose because a reader is learning a concept for the first time. This book's parts open a *pattern* with one `[HUNTER]` paragraph of hypothesis framing (2–4 sentences) and go straight to the first `[QUERY]` block. A pattern that spends more than one short paragraph before its first query is over-written for this book's density — promote the missing concept to a one-line cross-reference into the relevant DEH part instead of explaining it here.

### 1.3 Banned filler

Identical list to DEH's guide §1.2 — "in today's rapidly evolving threat landscape," "it is crucial/critical/important that," "robust" as an unqualified virtue word, "leveraging," "holistic," "seamlessly," "delve into," "in conclusion" as a section opener, "it is important to note that," standalone "landscape," "unlock/empower/elevate," "at the end of the day," "game-changer/cutting-edge/best-in-class." Same two tests apply: is the word load-bearing and explained, or is it decoration that could be deleted with no loss of meaning? Reuse DEH's guide §1.2 table and worked GOOD/BAD examples rather than re-deriving them — the failure mode is identical across both books.

### 1.4 Sentence and paragraph mechanics

Identical to DEH's guide §1.4: active voice by default; one claim per sentence; sentences under ~30 words; digits for Event IDs, ATT&CK IDs, port numbers, and counts ≥ 10, spelled-out one through nine elsewhere in prose except where paired with an identifier or unit; contractions fine.

**Cookbook-specific addition:** inside a query pattern, prose is allowed to run shorter than DEH's "one idea per paragraph" default — a `[FALSE POSITIVE]` or `[PIVOT]` entry is often correctly one or two sentences total, not a paragraph. Do not pad a pattern's required fields to hit a paragraph-length expectation that belongs to DEH's narrative chapters, not this book's reference entries.

---

## 2. Heading Level Conventions

| Level | Use for | Example |
|---|---|---|
| `#` (H1) | Part title only. One per file, first line. | `# Part 5 — Password Spraying` |
| `##` (H2) | Major numbered sections within a part — almost always just "Why this part exists," one or two grouping sections if the part's patterns cluster (e.g., "Sign-in-log-based patterns" vs. "Application-log-based patterns"), and a closing cross-reference section. | `## 2. Application-log-based spray patterns` |
| `###` (H3) | **One per named query pattern.** This is the standard, load-bearing heading level in this book — almost every `###` in the book is a pattern, not a sub-topic. | `### QC-05-02 — Single-source spray against many accounts` |
| `####` (H4) | Reserved for a pattern that genuinely needs an internal breakdown beyond the standard skeleton (rare — most patterns fit the skeleton in §3 without one). | `#### Variant: cloud IdP sign-in log form` |

Rules:

- Every part opens with an unnumbered `## Why this part exists` section stating scope and the explicit boundary against neighboring parts (see `BOOK-INDEX.md`'s per-part scope column) — mandatory, identical requirement to DEH's guide §2.
- Never skip a level.
- Pattern headings are sentence case after the ID: `### QC-05-02 — Single-source spray against many accounts`, never Title Case, matching DEH's §2 sentence-case rule for section titles.
- A pattern heading's ID (`QC-NN-SS`) is permanent once assigned and tracked in Appendix A1 — do not renumber a pattern to close a gap left by a deleted one; record the gap in Appendix A1 instead, the same position-independence discipline DEH applies to `DET-####`.

---

## 3. The Query Pattern Skeleton

This is this book's own contribution to the series' shared conventions — DEH has no equivalent because DEH's units are chapters teaching a concept, not a repeating catalog entry. Every pattern in every domain part (Parts 3–26) follows this exact skeleton. Part 27's hunt chains and Part 28's synthesis content are explicitly exempt (see §11).

### 3.1 The header table

Every pattern opens with a table immediately under its `###` heading, before any prose:

```
| Field | Value |
|---|---|
| **Pattern ID** | `QC-05-02` |
| **MITRE** | T1110.003 (Password Spraying) |
| **Behavior** | One clause naming the specific shape of activity this pattern targets. |
| **DEH cross-ref** | DEH Part 12 §2 (Identity: Access & Authentication Detection); cf. DEH DET-XX-XX if the pattern adapts a specific DEH detection. |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, YARA-L — AQL and EQL: `N/A`, see below |
```

The **Languages covered** row is mandatory and must name every language explicitly, including every `N/A`. A pattern that silently drops a language without listing it as `N/A` is a lint failure — see §12.

### 3.2 Tag and section order within a pattern

After the header table, in this fixed order:

1. **`[HUNTER]`** — one paragraph (2–4 sentences), the hypothesis framing. What you're looking for and why a hunt beats waiting on a standing detection for this specific shape.
2. **`[QUERY]` blocks, one per covered language, in this fixed order: Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (EQL primary; substitute Elastic KQL or ES\|QL per §4's decision note where the pattern's shape genuinely fits that surface better, per DEH Appendix A5 §8's own decision table).** A language marked `N/A` in the header table is skipped entirely here — do not include an empty or apologetic placeholder block; the header table already recorded the omission and its reason belongs in a one-line note where the block would have gone (see §4.4).
3. **`[FALSE POSITIVE]`** — once, after all `[QUERY]` blocks, covering the pattern's false-positive driver(s) across all languages shown. If one specific language's implementation has an FP driver the others don't share (e.g., a broader match because a field doesn't exist on that backend), name that inside this single section rather than duplicating the whole entry per language.
4. **`[PIVOT]`** — once, after `[FALSE POSITIVE]`. What to check next on a hit.
5. Optional: one or two callout boxes (§6), used opportunistically, never more than two per pattern (§6.9's density rule, tightened further for this book's density).
6. Optional: `[SOC MANAGEMENT]` — at most once per pattern, and only where the pattern's hunt-cadence or graduation-to-detection tradeoff is genuinely pattern-specific rather than already covered at the part level.

### 3.3 Each `[QUERY]` block's required shape

Every `[QUERY]` entry has, in order:

1. One framing sentence: platform/version/telemetry source targeted.
2. The fenced code block, fence-tagged per §5, labeled `CONCEPTUAL SAMPLE` per §12 (the default — see §12 for the rare exception).
3. **Plausible expected result** — one to three sentences describing what a match looks like: field values, a realistic count/rate, not just "returns matching events."
4. **Interpretation** — one to two sentences: what a hit plausibly means, stated with the same honesty discipline as §12 (e.g., "consistent with a spray attempt" rather than "confirms a spray attack").

A `[QUERY]` block missing the expected result or the interpretation is incomplete — this mirrors DEH's guide §3's rule that a bare wall of query syntax with no framing is grounds for reviewer rejection, applied here per-block instead of per-chapter.

---

## 4. Language Coverage and the `N/A` Convention

### 4.1 The six covered surfaces

Same six as DEH Parts 24–29 and DEH Appendix A5, same fence tags (§5):

Sigma · KQL (Sentinel/Defender) · Splunk SPL · QRadar AQL · YARA-L (Google SecOps) · Elastic (EQL / Elastic KQL / ES\|QL, one surface chosen per pattern shape).

### 4.2 Choosing the Elastic surface

Elastic contributes one query slot per pattern, not three — do not pad a pattern with all of EQL, Elastic KQL, and ES\|QL to inflate the language count. Choose per DEH Appendix A5 §8's decision table: a single-event boolean match uses Elastic KQL (cheapest, per DEH Appendix A5 §7.6's own precedent); an ordered/joined multi-event pattern uses EQL `sequence`; a threshold/wide-lookback pattern uses ES\|QL. State which surface was chosen and why in the framing sentence if it isn't obvious from the pattern's shape.

### 4.3 Choosing AQL's fence tag

Per DEH's guide §3 and DEH Appendix A5 §2/§6: AQL has no dedicated fence tag. Use `` ```sql `` and disambiguate "this is AQL, not standard SQL" in the sentence immediately above the block, every time — never invent an `aql` tag.

### 4.4 The `N/A` note

Where the header table marks a language `N/A`, add a one-line note in that language's position in the pattern (a short parenthetical or a one-sentence aside, not a full block) naming the specific reason category:

- **Aggregation ceiling** — the pattern needs multi-event correlation or aggregation the language's query surface doesn't support natively (e.g., plain EQL with no `sequence`/`sample` stage, per DEH Appendix A5 §4).
- **Missing schema field** — the target backend has no confirmed equivalent field for a value the pattern's logic depends on (e.g., YARA-L's unconfirmed `GrantedAccess` equivalent, per DEH Part 28 §1.1).
- **Multi-object deployment model** — the pattern's logic cannot be expressed as one query at all on this backend (QRadar's Building Block/Reference Set/Rule model, per DEH Part 27 §2–§3); where this applies, still show the investigative AQL search that would validate the pattern before building the standing objects, exactly as DEH Appendix A5 §7.4 does for DET-27-01, rather than marking the whole language `N/A`.
- **Structurally poor fit, not impossible** — the language could technically express the logic but only by fighting the language (e.g., forcing a stateful hunt through Sigma's narrow-backend-support `temporal_ordered` correlation type). Name the specific friction rather than using this category as a catch-all for "we didn't get to it."

Never mark a language `N/A` for "ran out of room" or "not commonly used for this" without one of the four reasons above — an unexplained `N/A` is a lint failure (§12).

---

## 5. Code Block Conventions

Identical fence-tag table to DEH's guide §3, reproduced here because it governs the single most frequent element in this book:

| Language / platform | Fence tag | Notes |
|---|---|---|
| Sigma rules | `` ```yaml `` | Sigma is YAML; never invent a `sigma` tag. |
| Splunk SPL | `` ```spl `` | One pipe-clause per line for 3+ pipes; align `\|` at the start of the continuation line. |
| Sentinel/Defender KQL | `` ```kql `` | Disambiguate "Sentinel/Defender KQL" vs. "Elastic KQL" in the sentence above the block, every time — same tag, different platform, per DEH's guide §3 and DEH Appendix A5 §2. |
| Elastic KQL | `` ```kql `` | Same disambiguation requirement, other direction. |
| Elastic EQL | `` ```eql `` | Never merge with `kql`. |
| Google SecOps YARA-L | `` ```yaral `` | Fall back to `` ```yaml `` only if the block is YAML-shaped and the renderer lacks a `yaral` lexer; otherwise `` ```text ``. |
| QRadar AQL | `` ```sql `` | Disambiguate "this is AQL, not standard SQL" above the block every time (§4.3). |
| Elastic ES\|QL | `` ```esql `` | |
| PowerShell (attacker command shown inline) | `` ```powershell `` | Never `ps1`. |
| Bash / shell (attacker command shown inline) | `` ```bash `` | Match the actual shell; never generic `shell`. |
| Raw log excerpt, not meant to be executed | `` ```json ``, `` ```xml ``, or `` ```text `` | `text` for a truncated/annotated excerpt with ellipses. |
| Mermaid (Part 27 hunt-chain diagrams only) | `` ```mermaid `` | See §10. |

Additional rules, identical to DEH's guide §3:

- Every fenced block carries an explicit, correct language tag — untagged or mistagged is a lint failure.
- Inline code (single backtick) for field names, single Event IDs used as identifiers, filenames, command names — never a substitute for a fenced block showing more than one line of logic.
- Comments inside a query explain *why*, not restate syntax: `// excludes the nightly backup account — see [FALSE POSITIVE] below`, not `// this is a NOT clause`.

---

## 6. Callout Boxes

Same eight boxes, same exact Markdown templates as DEH's guide §6, reused verbatim for series consistency: **Detection Autopsy**, **Hunter's Note**, **Engineering Reality**, **Blind Spot**, **False Positive Trap**, **Detection Test**, **SOC Management View**, **What Would Change My Mind**. All eight are a blockquote (`>`) opened with a bold label line; none is ever a heading; none nests inside another. Copy the exact template and worked-example structure from `detection-engineering-handbook\release-v2\STYLE-GUIDE.md` §6.1–§6.8 for each box — this guide does not reproduce all eight templates a second time in full text, to avoid the two copies drifting from each other; a reviewer checks the box shape against DEH's copy directly.

**Cookbook-specific relationship between callouts and the required `[FALSE POSITIVE]`/`[PIVOT]` tags:** the required tags in §3.2 are short, mandatory, once-per-pattern facts. A callout box is for something that needs more than a sentence or two, or that's genuinely a named recurring trap worth a reader's attention mid-skim (a Blind Spot, a Detection Autopsy of a naive version of this exact pattern). Do not promote every `[FALSE POSITIVE]` entry into a False Positive Trap callout — that duplicates the required tag in a heavier box for no reason. Use a callout only when the tag's one-line version genuinely isn't enough.

### 6.9 Callout usage density (tightened for this book)

DEH's guide allows roughly one Detection Autopsy, zero-to-one Blind Spot, zero-to-one False Positive Trap, and one Detection Test per chapter-length unit. This book's unit is a pattern, not a chapter — apply the same "opportunistic, not exhaustive" logic but cap it explicitly: **at most two callout boxes per pattern**, and most patterns should carry zero or one. A part where every pattern carries two callouts is over-boxed at this book's density even if each individual box is well-formed — cut to the pattern's single most important callout, or promote the recurring issue to the part's opening `## Why this part exists` section if it applies to most patterns in the part rather than one.

---

## 7. Content-Level Tags

Format locked to `**[TAG]**` — bold, brackets, all caps, start of the paragraph or subsection it governs. Never a heading, never doubled on one paragraph.

| Tag | Use for | Do not use for |
|---|---|---|
| `[CONCEPT]` | What the behavior is, why an attacker does it, where it sits in a kill chain — grounding before any query in the part. Used at most once or twice per part (in "Why this part exists" and maybe one pattern that introduces a genuinely new sub-shape), not once per pattern. | Anything that gives a specific query, threshold, or field name — that's `[QUERY]` even if conceptually simple. |
| `[HUNTER]` | The hypothesis-driven framing that opens every pattern: what you're looking for, when to reach for this hunt instead of trusting a standing detection. | A named, deployable rule's design rationale — that's DEH's `[DETECTION ENGINEER]` territory and belongs in DEH, cited, not restated here. |
| `[QUERY]` | Introduces one language's implementation of a pattern: the framing sentence, the fenced block, the plausible expected result, the interpretation. Repeats once per covered language within a pattern — the only tag allowed to repeat within one pattern. | The false-positive driver or the next pivot — those are pulled out into their own tags specifically so they aren't repeated per language. |
| `[FALSE POSITIVE]` | The pattern's named, common legitimate-activity driver and the fix or tuning tradeoff. Written once per pattern, after all `[QUERY]` blocks. | A per-language FP nuance that applies to only one backend — fold that into the same single `[FALSE POSITIVE]` entry as a clearly labeled aside, don't create a second tag instance. |
| `[PIVOT]` | What to query or check next if the pattern's query returns a hit — the next investigative hop. Written once per pattern. | A restatement of the query's own logic — a pivot is a *different* query or data source than the one just shown. |
| `[SOC MANAGEMENT]` | Hunt cadence, false-positive cost, and hunt-to-detection graduation framing for the behavior category — at most once per pattern, more often once per part. | Headcount, shift design, or vendor/budget content — that belongs in The SOC Manager's Operating Handbook, cited by name, not restated here. |

Tagging guidance specific to this book:

- A pattern's minimum tag set is `[HUNTER]` once, `[QUERY]` once per covered language, `[FALSE POSITIVE]` once, `[PIVOT]` once. `[CONCEPT]` and `[SOC MANAGEMENT]` are additive, not required per pattern.
- The pair authors most often confuse in this book: `[HUNTER]` (why you're looking, before any query) vs. `[QUERY]`'s own interpretation sentence (what a specific result plausibly means, after the query). If a `[HUNTER]` paragraph starts describing field values or a threshold, it's drifted into `[QUERY]` territory — move it.
- `[QUERY]` is the only tag this guide allows to repeat within a single pattern. Any other tag appearing more than once in one pattern is a lint failure — consolidate.

---

## 8. Windows Event ID and MITRE ATT&CK ID Notation

Identical to DEH's guide §4 and §5, reused verbatim:

- **Event ID 4624 (An account was successfully logged on)** on true first use per chapter; bare `4624` after. Never "Event 4624," "EID 4624," or lowercase "event 4624." Sysmon IDs disambiguate from Windows Security IDs on first use per chapter ("Sysmon Event ID 1 (Process Create)").
- **T1110.003 (Password Spraying)** on first reference per section; bare `T1110.003` after. Uppercase `T`, no space, sub-technique dot-suffix never truncated. A standalone **MITRE** row in a pattern's header table always spells out ID + name in full, regardless of prior mentions — the header table is read in isolation via Appendix A1/A3, exactly the same reasoning DEH's guide §5 gives for its own standalone `**MITRE:**` line.
- Never invent or guess a MITRE ID. A pattern with no clean mapping says so in its header table (`**MITRE:** No clean single-technique mapping — see [HUNTER] framing`) rather than forcing one.

---

## 9. Table Conventions

Identical to DEH's guide §8: lead-in sentence stating what decision a table supports; header row as short capitalized noun phrases; left-align text columns; fragments not full sentences in cells; em dash for "not applicable," never a blank cell; MITRE IDs and Event IDs inside cells follow §8's rules; tables built from invented/illustrative data marked `(CONCEPTUAL SAMPLE)` in the caption.

**Cookbook-specific addition:** the pattern header table (§3.1) is exempt from the "no blank cells, use em dash" table rule only in the sense that every field is mandatory and none is ever legitimately "not applicable" — a header table with an em dash in any field other than **DEH cross-ref** (where a pattern genuinely has none) signals a missing pattern ID, MITRE mapping, or language-coverage statement that must be filled in before review, not a deliberate omission.

---

## 10. Figures and Diagrams

This book is reference-dense and figure-sparse by design — most patterns need no diagram at all. Where a figure does appear (chiefly Part 27's hunt-chain flow diagrams, and occasionally a sequence diagram inside a lateral-movement or C2 pattern), it uses DEH's guide §9 evidence-classification system unchanged: `CONTROLLED LAB EXAMPLE`, `REAL LAB EXAMPLE`, `OFFICIAL REFERENCE`, or `CONCEPTUAL` — almost always `CONCEPTUAL` in this book, since a hunt-chain diagram illustrates a narrative sequence rather than capturing a real incident. Every Mermaid block is rendered to a static image and committed alongside its source per DEH's guide §10; the Mermaid source stays in the file as the editable record.

---

## 11. Part 27 and Part 28: Exemptions from the Pattern Skeleton

Part 27 (Multi-Behavior Hunt Chains) and Part 28 (Maintaining the Cookbook) are synthesis parts, not domain parts, and are exempt from §3's pattern skeleton:

- **Part 27** uses a **hunt-chain template** instead (defined in full in Appendix A4): a named scenario, a sequence of cross-referenced pattern IDs from Parts 3–26 in the order a hunter would actually pivot through them, and a closing note on where the chain would hand off to a playbook (cited into the SOC Playbook Handbook, not restated). Individual steps in a chain are citations to existing pattern IDs (`see QC-05-02`), not new query blocks — Part 27 must not silently re-author a query that already exists under a pattern ID elsewhere in the book.
- **Part 28** contains no query patterns at all. It applies DEH's existing Detection Coverage/Quality/Debt methodology (DEH Parts 41–43) to the pattern catalog and uses ordinary `##`/`###` prose sections, not the pattern skeleton.

---

## 12. The Honesty Standard: Illustrative by Default

This is this book's tightened version of DEH's guide §3 `CONCEPTUAL SAMPLE` convention, and the single most important rule in this document.

**Default rule:** every query block in this book is framed as illustrative and must carry the `CONCEPTUAL SAMPLE` labeling convention — a one-line label immediately above the fence, exactly as DEH's guide §3 specifies: `CONCEPTUAL SAMPLE — <one clause on what's illustrative about it>`, e.g. `CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use`.

**This is stricter than DEH's own default.** DEH reserves the label for teaching snippets because most DEH queries are DEH's own reviewed, tested, versioned detection rules (see DEH Part 24 §3's Sigma block, explicitly *not* labeled conceptual). This book's queries are a structurally different artifact: they exist to be copied into an unknown number of reader environments this book's authors have never seen and never tested against, not to be this book's own deployed output. Treating every query as illustrative by default is the honest description of what this book actually is, not an extra caution layered on top of it.

**The sole exception:** a query block that is a direct, verified quote from official vendor documentation. Such a block:

- Is never labeled `CONCEPTUAL SAMPLE`.
- Must instead carry a citation into `REFERENCES.md` immediately below the block, naming the source and retrieval context — the same sourcing discipline DEH's guide §9.1 requires for an `OFFICIAL REFERENCE` figure.
- Must not be silently modified, extended, or "improved" once quoted — if a modification is needed to fit this book's pattern (e.g., renaming a placeholder field), the block reverts to a `CONCEPTUAL SAMPLE` adaptation of the vendor example, cited as such, rather than staying labeled as a verified quote.
- Is expected to be rare. Most vendor documentation shows a generic syntax example, not a fully worked behavior-specific detection matching this book's own pattern scope — reviewers should default to assuming a query needs the standard `CONCEPTUAL SAMPLE` label and treat the exception as something to justify, not something to reach for to sound more authoritative.

**What this means for the "plausible expected result" and "interpretation" fields (§3.3):** these are also framed as plausible/illustrative, never as guaranteed — "a match here is consistent with X" and "a well-instrumented environment might see this settle to single-digit daily volume once tuned" are the correct register, not "this will return X" or "this proves X." This mirrors DEH's own precedent in Part 23's False Positive Trap box: "this book has not validated a specific per-day count against production telemetry" stated plainly rather than inventing false precision.

**No query in this book, anywhere, under any callout or tag, may claim to be guaranteed to run unmodified against a real product.** This is a hard rule, not a style preference — a reviewer finding this claim anywhere in the book rejects the PR regardless of how well-formed the surrounding prose is.

---

## 13. Cross-Reference Conventions

- **Citing DEH:** "DEH Part 12 §2" (part and section), or "DEH DET-23-01" (a specific detection ID) when citing a specific analytic. Never re-explain what the cited section says beyond the one clause needed to justify the citation — if more explanation seems necessary, that's a signal the cited DEH section should be read, not paraphrased at length here.
- **Citing this book's own patterns:** `QC-NN-SS` (e.g., "see `QC-16-03` for the corresponding admin-tool lateral-movement query"). Pattern IDs are the only stable cross-reference unit in this book — never cite a pattern by its part-relative position ("the third pattern in Part 16") since Appendix A1 tracks IDs, not positions.
- **Citing the other two series volumes:** name the book and, where known, the part ("SOC Playbook Handbook, Escalation Quality" or "SOC Manager's Operating Handbook, Part NN") — following the exact citation style The SOC Manager's Operating Handbook already uses for its own series map, for consistency across all volumes that cite each other.
- **Citing TERMINOLOGY.md concepts:** when this book uses "Analytic," "Detection Rule," "Detection Coverage," or another term DEH's TERMINOLOGY.md defines precisely, use the term exactly as DEH defines it and do not redefine it locally — cite "per DEH's TERMINOLOGY.md" on first substantive use per part if the distinction is load-bearing for that part (most directly relevant in Part 2 and Part 28).

---

## 14. Review Checklist (per pattern, and per part)

Work from this list, not from vibes — this is the enforcement mechanism for everything above.

**Per pattern:**

1. Header table present, complete, every language explicitly listed (covered or `N/A` with a named reason category per §4.4)?
2. Tag order matches §3.2: `[HUNTER]` once, `[QUERY]` per covered language in the fixed §3.2 order, `[FALSE POSITIVE]` once, `[PIVOT]` once, no tag other than `[QUERY]` repeated?
3. Every `[QUERY]` block: correct fence tag (§5), `CONCEPTUAL SAMPLE` label present unless the rare verified-vendor-quote exception applies and is cited into `REFERENCES.md` (§12), plausible expected result present, interpretation present and hedged appropriately?
4. MITRE ID in the header table spelled out in full regardless of prior mentions (§8)?
5. At most two callout boxes, correct template borrowed from DEH's guide §6, no box duplicating a required tag's job (§6)?
6. No unexplained `N/A`, no guaranteed-to-work claim anywhere in the pattern (§12)?
7. Pattern ID permanent and logged in Appendix A1; any DEH cross-reference in the header table points to a real DEH part/section/detection ID, not a guessed one?

**Per part:**

8. Pattern count within the 4–6 budget (or the part is explicitly a synthesis part exempt per §11)?
9. `## Why this part exists` present, stating scope and the explicit boundary against neighboring parts named in `BOOK-INDEX.md`?
10. Depth check: does this part's pattern count and per-pattern depth match sibling parts in the same lettered section, or is it thin/padded relative to them?
