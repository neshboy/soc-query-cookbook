# The SOC Threat Hunting Query Cookbook

**Sigma, KQL, SPL, AQL, YARA-L, and EQL Side by Side — Organized by Attacker Behavior, Not by Query Language**

📄 **[Download the full PDF](./SOC_Threat_Hunting_Query_Cookbook.pdf)** — 486 pages, ~157,000 words across 28 parts.

Volume 4 of the **NESHBOY SOC Professional Library**, alongside [SIGNAL TO ACTION: The Complete SOC Playbook Handbook](https://github.com/neshboy/soc-playbook-handbook), [The Detection Engineering Handbook V2](https://github.com/neshboy/detection-engineering-handbook), and [The SOC Manager's Operating Handbook](https://github.com/neshboy/soc-manager-handbook).

This is a query reference, not a query-language primer. A hunter who needs queries for password spraying, suspicious PowerShell, or C2 beaconing opens one part and finds Sigma, KQL, SPL, AQL, YARA-L, and Elastic (EQL/Elastic KQL/ES|QL) side by side for that behavior — instead of learning one language end to end and re-deriving every behavior's logic themselves in five other syntaxes. This book is a deliberate mirror-image of how [The Detection Engineering Handbook V2](https://github.com/neshboy/detection-engineering-handbook) (DEH) treats the same six query surfaces: **DEH Parts 23–29 already teach the language semantics** — what a `join` costs in KQL versus SPL's `transaction`, where Sigma's translation loses meaning, why QRadar's AQL isn't the deployed detection at all — carrying one canonical detection through all six languages. This book does not re-teach any of that. It cites DEH's syntax and telemetry-mechanics chapters throughout and spends its own page budget on sheer behavioral breadth instead: 28 parts across 15-plus named attacker behaviors, roughly 140 named query patterns, each with up to six ready-to-adapt query implementations.

## Reading the book

- **[SOC_Threat_Hunting_Query_Cookbook.pdf](./SOC_Threat_Hunting_Query_Cookbook.pdf)** — the assembled, print-ready book. Start here.
- **[BOOK-INDEX.md](./BOOK-INDEX.md)** — the full part table with per-part scope, pattern budget, and DEH cross-references, plus a "Key structural decisions and provenance" section recording why the book is 28 parts and organized by behavior rather than by language.
- **[STYLE-GUIDE.md](./STYLE-GUIDE.md)** — the voice, formatting, and honesty-labeling contract every part follows: six content tags (`[CONCEPT]`, `[HUNTER]`, `[QUERY]`, `[FALSE POSITIVE]`, `[PIVOT]`, `[SOC MANAGEMENT]`), the fixed query-pattern skeleton (§3), the `N/A`-with-reason convention for a language that structurally doesn't fit a pattern (§4), and the eight recurring callout boxes reused verbatim from DEH's style guide for series consistency.

## The honesty standard — every query defaults to CONCEPTUAL SAMPLE

DEH reserves its `CONCEPTUAL SAMPLE` label for teaching snippets, because most of DEH's own queries are real, reviewed, tested detection rules with reviewer sign-off. This book's queries are a different kind of artifact: they exist to be copied into an unknown number of reader environments this book's authors have never seen and never tested against, not to be this book's own deployed detections. Per this series' honesty standard, **every query in this book is labeled an illustrative `CONCEPTUAL SAMPLE` by default** — field names, thresholds, and expected-result counts are all illustrative and must be validated against your own schema and baseline before use. This is a deliberate tightening of DEH V2's own default, stated once here rather than repeated at the top of all ~140 patterns: DEH labels a query conceptual only when it's a teaching snippet; this book labels every query conceptual because none of them are this book's own reviewed, deployed output. The sole exception — a direct, verified quote from official vendor documentation — is cited into a references note rather than labeled conceptual, and is never silently modified once quoted. See `STYLE-GUIDE.md` §12 for the full mechanics.

**For the query-language syntax and semantics this book's patterns build on** — join costs, aggregation ceilings, backend translation loss, the reasoning behind why a language is marked `N/A` for a given pattern shape — see [The Detection Engineering Handbook V2](https://github.com/neshboy/detection-engineering-handbook), Parts 23–29 and Appendix A5. This book cites that reasoning throughout rather than re-deriving it.

## What's synthetic vs. real

Every query block in this book is a conceptual/illustrative sample per the honesty standard above, adapted from common attacker-behavior shapes rather than pulled from a live SOC deployment. Diagrams (Part 27's hunt-chain flowcharts) are original Mermaid flowcharts, rendered to SVG and committed alongside their Markdown source, each marked `CONCEPTUAL` per DEH's evidence-classification convention — none is a capture of a real incident. This book contains no fabricated screenshots and no claim that any query is guaranteed to run unmodified against a real product.

## How it was built

- `build/build_book.js` — parses `BOOK-INDEX.md`'s Part Table, assembles all 28 chapter files into one HTML document (stripping YAML front matter, resolving image paths, colorizing the six content tags), and prints it to PDF via headless Chrome. The Appendix Table is skipped automatically: `BOOK-INDEX.md` names 5 planned appendix bundles (Master Pattern Index, Behavior × Language Coverage Matrix, MITRE ATT&CK Cross-Reference, Pattern/Front-Matter/Hunt-Chain Templates, Query-Language Syntax Pointer), but `appendices/` is empty in this release — a future edition, not a build defect.
- `build/add_watermark.py` — applies the diagonal `neshboy` watermark to every page.
- Part 27's five Mermaid hunt-chain diagrams were already rendered to SVG and embedded with image tags in the chapter source before this release's build pass; no `render_mermaid.py` run was needed for this book.

## Rebuilding it yourself

```
cd build
npm install
node build_book.js
"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer ^
  --print-to-pdf="..\_build\SOC_Threat_Hunting_Query_Cookbook.pdf" "..\_build\book.html"
python add_watermark.py
```

## Repository layout

- `chapters/` — the 28 parts, Markdown source of record. `appendices/` is reserved for the 5 appendix bundles named in `BOOK-INDEX.md`'s Appendix Table; none are drafted yet.
- `assets/diagrams/` — rendered Mermaid SVGs (Part 27's five hunt-chain flowcharts).
- `build/` — the build/watermark tooling above.
- `BOOK-INDEX.md`, `STYLE-GUIDE.md` — cross-cutting project documentation.
