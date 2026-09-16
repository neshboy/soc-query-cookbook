# References

Full metadata for every external, real-world source cited inline in `chapters/`. Each source is listed once here; the chapter text cites it inline, in place, using this book's existing parenthetical convention: `(Organization, "Title," Publication/Version: URL)`. This file does not re-derive or re-explain a cited claim — see the chapter text for how each source is used.

Per `STYLE-GUIDE.md` §12, a query block that is a direct, verified quote from official vendor documentation must cite its source here rather than being labeled `CONCEPTUAL SAMPLE`; every other inline citation below supports a specific factual or conceptual claim in the surrounding prose, not a verbatim query quote.

Every URL below was fetched and read directly before citing, per this book's sourcing standard — none is pattern-guessed from a vendor's URL scheme.

## Sources

- **IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5.** https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html — Documents AQL's `HAVING` clause (filters on an aggregate's alias, not the raw aggregate expression) and its one documented limitation: a saved search using `HAVING` is not supported for a scheduled report or a time-series graph. Cited throughout Parts 2–24 wherever a QRadar AQL query block relies on this `HAVING`/alias behavior.

- **MITRE Corporation, "MITRE ATT&CK."** https://attack.mitre.org/ — The official ATT&CK knowledge base of adversary tactics and techniques; the source for every technique/sub-technique ID and name used in this book's pattern header tables (e.g., `T1110.003`, confirmed against the live technique page as "Brute Force: Password Spraying"). Cited in Part 1 §6 and Part 2 §1, where the header table's `MITRE` field convention is defined.

- **SigmaHQ, "Sigma Correlation Rules Specification," v2.1.0.** https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md — The normative specification defining Sigma's correlation rule types. Confirmed to define exactly seven correlation types (`event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`), matching Part 18's claim about why Sigma has no native first-seen/new-term primitive. Cited in Part 18 (`QC-18` "rare/first-seen domain" pattern).

- **Elastic, "EQL syntax reference," Elastic Docs.** https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax — Confirms that an EQL `sequence` matches a fixed number of stages (optionally repeated a fixed count via `with runs`), with no native "N or more" construct for one repeated stage. Supports Part 6's claim that a five-failure EQL `sequence` pattern approximates, rather than exactly expresses, a "5 or more" threshold. Cited in Part 6 (`QC-06-04`, MFA-failure-burst-then-success pattern).

- **Elastic, "LOOKUP JOIN," ES\|QL command reference, Elastic Docs.** https://www.elastic.co/docs/reference/query-languages/esql/commands/lookup-join — Confirms `LOOKUP JOIN` adds columns from a lookup index to query results by matching a shared join-field value. Supports Part 7's claim that ES\|QL's `LOOKUP JOIN` expresses a static-table inventory/issuance check more directly than EQL's `sequence` stage. Cited in Part 7 (`QC-07` DCSync-exclusion-list and ticket-issuance patterns); the same command underlies later, uncited restatements of this pattern shape in Parts 17, 21, 23, 24, and 26.
