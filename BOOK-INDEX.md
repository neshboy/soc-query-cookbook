# The SOC Threat Hunting Query Cookbook

**BOOK-INDEX.md — canonical part list and appendix list.**
**Status:** Draft architecture, Volume 4 of the NESHBOY SOC Professional Library. Companion volumes: *SIGNAL TO ACTION: The Complete SOC Playbook Handbook* (`github.com/neshboy/soc-playbook-handbook`), *The Detection Engineering Handbook V2* (`github.com/neshboy/detection-engineering-handbook`), and *The SOC Manager's Operating Handbook* (this series' Volume 3, local at `C:\Users\User\projects\soc-manager-handbook`).

## What this book is

A massive, ready-to-adapt query reference for threat hunters, organized by **attacker behavior**, not by query language. A hunter who wants queries for password spraying, suspicious PowerShell, or C2 beaconing opens one part and finds Sigma, KQL, SPL, AQL, YARA-L, and Elastic (EQL/KQL/ES\|QL) side by side for that behavior — instead of learning one language end to end and then having to re-derive every behavior's logic themselves in five other syntaxes.

This is a deliberate mirror-image of how The Detection Engineering Handbook V2 (DEH) treats the same six query surfaces. DEH Parts 23–29 carry **one canonical detection** (DET-23-01, suspicious process access to `lsass.exe`) through all six languages to teach language *semantics* — what a `join` costs you in KQL versus SPL's `transaction`, where Sigma's translation loses meaning, why QRadar's AQL isn't the deployed detection at all. This book does not re-teach any of that, and does not re-derive *why* a given piece of detection logic works from telemetry mechanics up — DEH's domain parts (8–21) and Part 23's translation-loss framework already did that work. This book cites it. Its own job is sheer behavioral breadth: dozens of named attacker behaviors, each with several ready-to-adapt query patterns across the same six surfaces, so a hunter under time pressure has a starting point for the behavior in front of them rather than a fully-taught language and a blank page.

**What this book explicitly does not do**, stated once here so no part has to repeat it:

- **Does not teach query-language syntax fundamentals.** Operators, join semantics, aggregation windows, backend feature ceilings — DEH Parts 24–29 and DEH Appendix A5 own this. A pattern in this book that depends on a construct DEH hasn't already explained cites the DEH section that explains it rather than teaching it inline a second time.
- **Does not re-derive detection-engineering reasoning from first principles.** Why a given field matters, what a telemetry source structurally cannot see, why a naive version of a rule fails — DEH's domain parts (8–21) and its recurring Blind Spot / False Positive Trap / Detection Autopsy callouts already carry that reasoning. This book's own Blind Spot and False Positive Trap callouts are pattern-specific and additive, not a second pass over ground DEH already covers.
- **Does not own coverage/quality/debt methodology.** DEH Parts 41–43 define the six-tier Detection Coverage scale, the Detection Quality metric set, and the Detection Debt ledger. Part 28 of this book *applies* that existing methodology to cookbook patterns; it does not invent a parallel scoring system.
- **Does not own playbook mechanics, triage procedure, or SOC staffing.** SIGNAL TO ACTION owns escalation/playbook structure; The SOC Manager's Operating Handbook owns staffing, process, and budget. The `[SOC MANAGEMENT]` tag in this book stays narrowly scoped to hunt cadence, false-positive-cost tradeoffs, and the decision to graduate a hunt pattern into a standing detection — not headcount or shift design.

## Series map

| If you're looking for... | Go to... |
|---|---|
| Query language syntax, semantics, and backend translation loss | Detection Engineering Handbook V2, Parts 23–29 and Appendix A5 |
| The telemetry mechanics and blind spots behind a given detection | Detection Engineering Handbook V2, Parts 8–21 (domain parts) |
| Detection Coverage / Quality / Debt scoring methodology | Detection Engineering Handbook V2, Parts 41–43 |
| Threat hunting methodology (hypothesis, scoping, hunt-to-detection) | Detection Engineering Handbook V2, Parts 34–36 |
| **A ready-to-adapt query for a named attacker behavior, across six languages** | **This book** |
| How to escalate a hunt finding through a playbook | SOC Playbook Handbook |
| Whether to staff a standing hunt program, and how | SOC Manager's Operating Handbook |

## The structural problem this book has to solve, and how it's solved

Fifteen-plus attacker behavior categories, each needing multiple query patterns, each pattern needing up to six language implementations, is a combinatorial shape that gets unreadable fast if every pattern repeats every piece of prose six times. Four mechanical decisions keep the book navigable instead of becoming a wall of near-duplicate query blocks:

1. **A fixed pattern budget per part.** Every domain part carries 4–6 named query patterns, no more. A behavior category that genuinely needs more room (Kerberos/directory credential attacks, cloud abuse, persistence) gets *split into an additional part*, not an oversized one — the same "single breadth-pass, thin depth" trap DEH names as its own V1 defect #4, applied here to pattern count instead of page count.
2. **Interpretation logic is written once per pattern; only the query block repeats per language.** Every pattern's `[FALSE POSITIVE]` and `[PIVOT]` content is written **once**, describing the behavior-level false-positive driver and the next investigative hop — because both are properties of the *analytic* (what the pattern is looking for), not of any one language's syntax for expressing it. Only `[QUERY]` — the fence-tagged code block, its plausible expected result, and its one-line interpretation — repeats, once per language shown. This is a direct structural borrowing from DEH Part 23's own finding: six backend implementations of one analytic are one line of detection coverage, not six independent things to explain six times.
3. **A language is omitted with a one-line reason, never forced.** Where a language is a structurally bad fit for a pattern's shape — QRadar AQL cannot express a stateful multi-event pattern as one query (DEH Part 27 §2–3), EQL has no aggregation stage (DEH Appendix A5 §4), YARA-L has no confirmed access-rights-equivalent field for some Windows-native patterns (DEH Part 28 §1.1) — the pattern says `N/A — <reason>` instead of publishing an awkward, misleading translation. This mirrors DEH's own honesty precedent for DET-23-01 rather than inventing a new excuse to skip a language.
4. **A navigation layer substitutes for linear reading.** Appendix A1 (Master Pattern Index) and Appendix A2 (Behavior × Language Coverage Matrix) let a reader find a pattern by MITRE ID, behavior, or language coverage without reading a part end to end — the same role DEH Appendix A5 plays for its six canonical language implementations, scaled up to this book's much larger pattern count.

With this budget, 28 parts carrying an average of ~5 patterns each yields roughly 140 named query patterns and, before any `N/A` omissions, an upper bound near 800–850 individual query blocks — deliberately "massive," and kept readable by the four rules above rather than by writing less.

## Multi-level content model

Content is marked with one of six **content tags**, placed as a bold bracketed label at the start of the paragraph or subsection it governs (never as a heading, never doubled on one paragraph). Full definitions and a do/don't table are in `STYLE-GUIDE.md` §7; summarized here:

- `[CONCEPT]` — what the behavior is, why an attacker does it, and where it sits in a kill chain, before any query appears.
- `[HUNTER]` — the hypothesis-driven framing for a specific pattern: what you're actually looking for, and when to reach for this hunt instead of trusting a standing detection.
- `[QUERY]` — introduces one specific, ready-to-adapt query: target platform/version, the fenced query block (see honesty standard below), its plausible expected result, and its interpretation. The only tag that repeats per language within one pattern.
- `[FALSE POSITIVE]` — the pattern's named, common false-positive driver and the fix or tuning tradeoff. Written once per pattern, shared across every language variant shown.
- `[PIVOT]` — what to query or check next if this pattern's query returns a hit. Written once per pattern, shared across every language variant shown.
- `[SOC MANAGEMENT]` — hunt cadence, false-positive cost, and hunt-to-detection graduation framing, tied to the behavior category. Used opportunistically, roughly once per part, not per pattern — see the scope boundary above.

Layered on top are the **same eight recurring callout boxes DEH uses**, unchanged in name and Markdown template for series consistency (Detection Autopsy, Hunter's Note, Engineering Reality, Blind Spot, False Positive Trap, Detection Test, SOC Management View, What Would Change My Mind — full templates in `STYLE-GUIDE.md` §6, reused by reference from `detection-engineering-handbook\release-v2\STYLE-GUIDE.md` §6). Given this book's much higher item density (a callout box per query pattern, not per chapter section), density guidance is tightened accordingly — see `STYLE-GUIDE.md` §6.9.

## The honesty standard (why every query defaults to CONCEPTUAL SAMPLE)

DEH reserves the `CONCEPTUAL SAMPLE` label for teaching snippets, because most of DEH's queries are real, reviewed, tested detection rules with their own front matter and reviewer sign-off (see DEH Part 24 §3's Sigma block, explicitly *not* labeled conceptual: "a real reviewed rule, not a conceptual sketch"). This book's queries are a different kind of artifact: they are meant to be copied into an unknown number of unverified reader environments and adapted, not deployed verbatim as this book's own reviewed output. Per this series' existing honesty standard, **every query in this book is framed as an illustrative CONCEPTUAL SAMPLE by default.** The sole exception is a query that is a direct, verified quote from official vendor documentation — rare, must carry a citation into `REFERENCES.md` instead of the `CONCEPTUAL SAMPLE` label, and must not be silently modified from the source once quoted. No pattern in this book may claim a query is guaranteed to run unmodified against a real product. See `STYLE-GUIDE.md` §3 and §12 for the exact labeling mechanics.

## Production model (cross-cutting, applies to every part and pattern)

Every part carries the same mandatory YAML front matter DEH uses (`author`, `reviewer`, `status`, `last_validated`, `depends_on`). Every named query pattern carries a permanent, position-independent global ID in the form `QC-NN-SS` (part number–sequence, e.g. `QC-04-02`), tracked in Appendix A1, so a future reorganization never breaks a cross-reference — the same discipline DEH applies to its `DET-####`/`HUNT-####`/`FIG-####` IDs. Where a pattern is a direct adaptation of a DEH analytic (most commonly a DEH domain-part detection or DEH's DET-23-01 comparison set), the pattern's header table cites the DEH part, section, and detection ID it derives from — required, not optional, since this book's stated job is citing DEH's reasoning rather than re-deriving it.

---

## Part Table

*File path pattern:* `C:\Users\User\projects\soc-query-cookbook\chapters\partNN-slug.md`

### Section A — Cookbook Mechanics

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 1 | How to Use This Cookbook | `chapters\part01-how-to-use-this-cookbook.md` | What this book is and isn't, the series map, the six content tags, the honesty standard, and how to read a pattern header table. No queries in this part. | — | DEH Part 1 (Analytic vs. Detection Rule vs. Use Case vs. Hunt), DEH Part 23 §6 |
| 2 | The Query Pattern Template & Coverage Notation | `chapters\part02-the-query-pattern-template-and-coverage-notation.md` | The exact pattern skeleton (header table, tag order, language order, `N/A`-with-reason convention) and how a pattern maps onto DEH's six-tier Detection Coverage scale for the reader who wants to track which hunts are still exploratory versus already graduated to a standing rule. | — | DEH Part 41 (six-tier Detection Coverage scale), DEH Appendix A5 §1–§2 |

### Section B — Reconnaissance & Scanning Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 3 | Scanning & Enumeration | `chapters\part03-scanning-and-enumeration.md` | Port/service scanning, vulnerability-scan fingerprints, internal host/service enumeration, and directory/share enumeration as a pre-lateral-movement signal. Does not cover the DNS-specific enumeration forms owned by Part 18. | 5 | DEH Part 14 §2 (Network Detection Engineering — scan detection) |

### Section C — Credential Access Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 4 | Brute Force | `chapters\part04-brute-force.md` | Single-account, high-volume failed-authentication patterns across RDP, SSH, VPN, and web-application login endpoints. | 5 | DEH Part 12 (Identity: Access & Authentication Detection) |
| 5 | Password Spraying | `chapters\part05-password-spraying.md` | Low-and-slow, single-attempt-per-account, many-accounts authentication patterns — the distinguishing shape from Part 4's per-account volume. | 5 | DEH Part 12, DEH Part 40 (seeded naive-rule teardown: "five failed logins = brute force") |
| 6 | MFA Abuse & Authentication Anomalies | `chapters\part06-mfa-abuse-and-authentication-anomalies.md` | MFA-fatigue push-bombing, impossible travel, new-device/new-country sign-in, and login-after-a-failure-burst patterns. | 5 | DEH Part 12, DEH Part 31 (Baselining — the "new device/country" pattern requires a baseline to mean anything) |
| 7 | Kerberos & Directory Credential Attacks | `chapters\part07-kerberos-and-directory-credential-attacks.md` | Kerberoasting, AS-REP roasting, DCSync, and pass-the-hash/pass-the-ticket *theft* events — the credential-theft side of the ATT&CK tactic boundary. The *use* of a stolen ticket/hash to move laterally is Part 17's scope, not this one's; stated explicitly so the two parts don't silently duplicate. | 6 | DEH Part 13 (Identity: Directory, Privilege & Kerberos Detection) |

### Section D — Execution & Living-off-the-Land Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 8 | Suspicious PowerShell Execution | `chapters\part08-suspicious-powershell-execution.md` | Encoded/obfuscated command lines, download cradles, AMSI-bypass-shaped invocations, and 4104-driven script-block hunting. | 5 | DEH Part 10 (PowerShell Detection Engineering), DEH Part 40 (seeded teardown: "PowerShell execution = malicious") |
| 9 | LOLBins & Living-off-the-Land Execution | `chapters\part09-lolbins-and-living-off-the-land-execution.md` | LOLBAS/GTFOBins-class binary abuse for execution, download, or defense evasion — `rundll32`, `mshta`, `certutil`, `bitsadmin`, and their Linux analogs. | 6 | DEH Part 11 (Endpoint Detection Engineering) |
| 10 | Suspicious Scripting Hosts & Macro Execution | `chapters\part10-suspicious-scripting-hosts-and-macro-execution.md` | Office macro execution chains (Word/Excel spawning a child process), WSH (`wscript`/`cscript`), and HTA-based execution. | 5 | DEH Part 11, DEH Part 17 (Email — the macro's usual delivery vector) |

### Section E — Persistence & Privilege Escalation Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 11 | Account Creation & Privilege Escalation | `chapters\part11-account-creation-and-privilege-escalation.md` | New local/domain account creation, unexpected group membership changes, and token/privilege-assignment escalation on Windows and Linux (`sudo`/`sudoers` drift). | 6 | DEH Part 13, DEH Part 11 |
| 12 | Scheduled Tasks & Service Manipulation | `chapters\part12-scheduled-tasks-and-service-manipulation.md` | New/modified scheduled tasks, Windows service creation via the Service Control Manager, and `cron`/`systemd` unit creation on Linux. | 5 | DEH Part 11 (persistence across Windows services/tasks/registry *and* Linux cron/systemd) |
| 13 | Registry, Startup & Alternate Persistence | `chapters\part13-registry-startup-and-alternate-persistence.md` | Run-key/startup-folder persistence, WMI event subscriptions, and less common persistence surfaces not already owned by Part 12. | 4 | DEH Part 11 |

### Section F — Defense Evasion & Discovery Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 14 | Log Tampering & Security Tool Interference | `chapters\part14-log-tampering-and-security-tool-interference.md` | Audit-log clearing, EDR/AV tampering or uninstall attempts, and Sysmon/agent-service-stop patterns — the "someone is trying to go dark" behavior class. | 4 | DEH Part 11 (security-tool tampering), DEH Part 8 §Event ID 1102 SOC Management View precedent |
| 15 | Host & Directory Discovery | `chapters\part15-host-and-directory-discovery.md` | `net`/`nltest`/`whoami`/BloodHound-shaped enumeration commands and their Linux equivalents, as the pre-lateral-movement recon signal distinct from Part 3's network-level scanning. | 5 | DEH Part 11, DEH Part 13 (LDAP enumeration) |

### Section G — Lateral Movement Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 16 | Lateral Movement via Admin Tools & Remote Services | `chapters\part16-lateral-movement-via-admin-tools-and-remote-services.md` | PsExec-style service-based lateral movement, WMI-based remote execution, WinRM/PowerShell remoting, and RDP-based movement. | 6 | DEH Part 11 §Endpoint (process-tree view), DEH Part 8 (4624 Type 3/10) |
| 17 | Lateral Movement via Stolen Tokens & Ticket Reuse | `chapters\part17-lateral-movement-via-stolen-tokens-and-ticket-reuse.md` | The *use* of a pass-the-hash or pass-the-ticket credential obtained via Part 7's theft patterns to authenticate to a new host. Explicit scope boundary against Part 7, mirroring DEH's own theft-vs-use tactic split. | 5 | DEH Part 13, this book's Part 7 |

### Section H — Network & Command-and-Control Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 18 | Suspicious DNS | `chapters\part18-suspicious-dns.md` | DNS tunnelling, DGA-shaped queries, rare/first-seen domains, and NXDOMAIN-burst patterns. Owns all DNS-tunnelling logic exclusively, mirroring DEH Part 15's exclusive ownership. | 5 | DEH Part 15 (DNS Detection Engineering), DEH Part 40 (seeded teardown: "long DNS label = tunnel") |
| 19 | C2 & Beaconing Detection | `chapters\part19-c2-and-beaconing-detection.md` | Regular-interval beacon detection, rare/first-seen destination hunting, JA3/TLS-fingerprint pivoting, and domain-fronting/CDN-abuse shaped traffic. Explicitly excludes DNS-tunnelling logic, owned by Part 18. | 6 | DEH Part 14 (Network Detection Engineering) |

### Section I — Collection, Exfiltration & Data-Staging Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 20 | Exfiltration | `chapters\part20-exfiltration.md` | Large/anomalous outbound transfer volume, exfiltration over an alternate protocol (DNS/ICMP), and exfiltration to unsanctioned cloud-storage destinations. | 5 | DEH Part 14, DEH Part 19 (Cloud Infrastructure — storage egress) |
| 21 | Insider Threat & Data Staging | `chapters\part21-insider-threat-and-data-staging.md` | Mass archive creation, unusual bulk file access ahead of departure, removable-media write events, and staging-directory hunting — deliberately framed around intent-ambiguous behavior rather than assumed-malicious tooling. | 5 | DEH Part 3 (host telemetry), DEH Part 42 (Analytic Confidence — this behavior class runs unusually low-confidence by design) |

### Section J — Malware & Ransomware Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 22 | Malware Indicators | `chapters\part22-malware-indicators.md` | Unsigned/rare-binary execution, process-injection-shaped parent/child anomalies, and hash/YARA-based artifact hunting — general-purpose malware presence signals not already covered by a named behavior elsewhere in the book. | 6 | DEH Part 11, DEH Part 40 (seeded teardown: "unsigned process = malware") |
| 23 | Ransomware Precursors | `chapters\part23-ransomware-precursors.md` | Discovery-stage, credential-access-stage, and backup/shadow-copy-tampering signals that precede encryption — deliberately weighted toward the pre-encryption stage, mirroring DEH Part 45's own framing that encryption-stage detection is the already-failed, last-resort case. | 5 | DEH Part 45 (Ransomware Detection Model) |

### Section K — Cloud & Identity Abuse Behaviors

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 24 | Cloud Identity & SaaS Abuse | `chapters\part24-cloud-identity-and-saas-abuse.md` | OAuth/app-consent-grant abuse, conditional-access bypass, and cross-tenant/guest-account risk in Entra ID, Okta, Google Workspace, and M365. | 5 | DEH Part 18 (Cloud Identity & SaaS Detection Engineering) |
| 25 | Cloud Infrastructure Abuse | `chapters\part25-cloud-infrastructure-abuse.md` | IAM policy abuse, storage/network exposure, and mass control-plane API activity across AWS/Azure/GCP. | 5 | DEH Part 19 (Cloud Infrastructure Detection Engineering) |
| 26 | Cloud-Native Lateral Movement & Privilege Escalation | `chapters\part26-cloud-native-lateral-movement-and-privilege-escalation.md` | Assumed-role chaining, instance-metadata-service credential theft, and cross-account pivoting — split from Part 25 because the query shape (CloudTrail Lake/Sentinel ASIM/Cloud Audit Logs joins across an assumed-role chain) is materially different from a single-account IAM-abuse query. | 5 | DEH Part 19, DEH Part 23 §3 (the CloudTrail `userIdentity.arn` assumed-role-chain example) |

### Section L — Synthesis, Maturity & Maintenance

| Part | Title | File Path | Scope | Pattern Budget | Primary DEH Cross-Refs |
|---|---|---|---|---|---|
| 27 | Multi-Behavior Hunt Chains | `chapters\part27-multi-behavior-hunt-chains.md` | Stitches named patterns from earlier parts into 4–6 worked end-to-end hunt narratives (e.g., spray → Part 5, successful logon → Part 6, discovery → Part 15, lateral move → Part 16, exfil → Part 20), demonstrating pivot chains across parts rather than introducing new single-behavior patterns. | 5 (chains, not single patterns) | DEH Part 44 (Adversary Behaviour for Defenders), DEH Parts 34–36 (Threat Hunting) |
| 28 | Maintaining the Cookbook: Coverage, Freshness & Debt | `chapters\part28-maintaining-the-cookbook-coverage-freshness-and-debt.md` | Applies DEH's existing Detection Coverage six-tier scale, Detection Quality metrics, and Detection Debt ledger to cookbook patterns specifically: which patterns are exploratory-only versus graduated to a standing rule, which are stale against schema drift, and how a team tracks that without inventing a parallel scoring system. | — (synthesis, no new query patterns) | DEH Part 41 (Detection Coverage), DEH Part 42 (Detection Quality), DEH Part 43 (Detection Debt) |

**Total: 28 parts.**

---

## Appendix Table

*File path pattern:* `C:\Users\User\projects\soc-query-cookbook\appendices\aN-slug.md`

| Appendix | Title | File Path | Contents |
|---|---|---|---|
| A1 | Master Pattern Index | `appendices\a1-master-pattern-index.md` | Every `QC-NN-SS` pattern ID, its title, owning part, MITRE ID(s), and which of the six languages are covered versus marked `N/A`. The primary navigation entry point for a reader who knows the behavior or MITRE ID but not the part number. |
| A2 | Behavior × Language Coverage Matrix | `appendices\a2-behavior-by-language-coverage-matrix.md` | One row per part, one column per language, cell = pattern count covered / `N/A` count / reason category — the book-level view of where six-language coverage is genuinely complete versus deliberately partial, condensed from A1. |
| A3 | MITRE ATT&CK Cross-Reference | `appendices\a3-mitre-attack-cross-reference.md` | Technique/sub-technique index mapped to every `QC-NN-SS` pattern ID that addresses it — this book's equivalent of DEH Appendix A4, scoped to cookbook patterns rather than DEH's own detections. |
| A4 | Pattern, Front-Matter & Hunt-Chain Templates | `appendices\a4-pattern-front-matter-and-hunt-chain-templates.md` | The blank skeleton for a query pattern (header table, tag order, language order), the per-file YAML front matter fields, and the multi-behavior hunt-chain template used in Part 27. |
| A5 | Query-Language Syntax Pointer | `appendices\a5-query-language-syntax-pointer.md` | Deliberately thin: does not duplicate DEH Appendix A5's cross-language syntax cheat sheet. Maps this book's recurring query shapes (threshold/rate, sequence, wide-lookback hunt) onto DEH Appendix A5 §4/§5/§8's existing decision tables, and flags the small number of syntax constructs this book relies on that DEH's A5 doesn't already cover (if any arise during drafting), so a gap gets logged against DEH's appendix rather than silently re-taught here. |

**Total: 5 appendix bundles.**

---

## Key structural decisions and provenance

1. **Behavior-organization instead of language-organization** (the book's core design choice). DEH Parts 23–29 already own the "one analytic, six languages, taught for semantics" job; repeating that structure at a larger scale would just be a bigger DEH, not a different book. Organizing by attacker behavior is the one axis DEH's language-first structure doesn't optimize for, and it's the axis a hunter under time pressure actually searches by ("I need spray queries," not "I need KQL queries").
2. **A fixed 4–6 pattern budget per part**, enforced by splitting an oversized behavior into an additional part rather than inflating one part's pattern count. Applied concretely at Kerberos/directory attacks (Part 7, 6 patterns — already at the ceiling), persistence (split across Parts 12–13), and cloud abuse (split across Parts 24–26) — each split is a named depth decision, not a rebalancing for its own sake, matching DEH's own justification style for its Telemetry and Cloud splits.
3. **`[FALSE POSITIVE]` and `[PIVOT]` written once per pattern; only `[QUERY]` repeats per language.** This is the single mechanical decision that keeps 6-languages-times-~140-patterns from becoming an unreadable wall of near-duplicate prose — it treats false-positive drivers and pivot logic as properties of the analytic (shared), and treats the query syntax alone as the thing that legitimately differs by backend (repeated), which is exactly the analytic/detection-rule distinction DEH's own TERMINOLOGY.md and Part 23 already establish.
4. **Explicit `N/A — <reason>` instead of a forced six-for-six template.** Every pattern still *states* whether all six languages apply; where one doesn't fit a pattern's shape, the reason is named (aggregation ceiling, missing schema field, multi-object deployment model) rather than silently omitted or forced into a misleading translation — directly continuing DEH's own precedent for DET-23-01 (QRadar's three-object CRE, EQL's no-aggregation limit, YARA-L's missing `GrantedAccess` equivalent).
5. **Appendix A1 (Master Pattern Index) and A2 (Coverage Matrix) as the navigation layer**, scaling up the role DEH Appendix A5 plays for its much smaller six-implementation comparison set. A reader is never expected to read all 28 parts start to finish to find one pattern.
6. **Illustrative-by-default, stricter than DEH's own default.** DEH's `CONCEPTUAL SAMPLE` label is reserved for teaching snippets because most DEH queries are this book's own reviewed, tested output. This book's queries are adapted into unknown reader environments rather than deployed as this book's own detections, so every query defaults to `CONCEPTUAL SAMPLE` — a deliberate, stated tightening of the series' honesty standard for this book's specific use case, not a contradiction of DEH's convention.
7. **Theft-vs-use scope split (Part 7 vs. Part 17)**, mirroring the ATT&CK Credential Access / Lateral Movement tactic boundary and DEH's own telemetry-layer/analytic-layer scope-boundary discipline (e.g., DEH Part 8 vs. Part 9 vs. Part 10). Prevents Kerberos-ticket-theft logic and stolen-ticket-reuse logic from silently duplicating each other under two different part titles.
8. **Cloud split into three parts (24–26), one more than DEH's own Identity/Infrastructure split (DEH Parts 18–19).** Cloud-native lateral movement and privilege escalation (assumed-role chaining, instance-metadata theft) has a genuinely different query shape — cross-account joins over control-plane logs — than either single-account IAM abuse or SaaS identity abuse, and forcing it into one of those two parts would blow the pattern budget in decision #2 above.
9. **Two closing parts (27–28) instead of one.** Stitching patterns into worked hunt narratives (Part 27, hunter-facing) and applying DEH's coverage/quality/debt methodology to the pattern catalog (Part 28, lead/manager-facing) are different jobs for different readers, the same split logic behind DEH's own Parts 41/42/43 separation.
10. **28 total parts.** Fifteen-plus named behaviors, several requiring a second part to stay inside the pattern budget (decision #2), plus two mechanics parts and two closing synthesis parts, converges on 28 — inside the 24–32 range this architecture targeted, and chosen over a flatter ~15-part structure (one part per literally-named behavior) because a flat structure would either force several behaviors over the pattern-budget ceiling or force silently thinner coverage per behavior, the exact "single breadth-pass, thin depth" failure DEH names as its own V1 defect #4.
