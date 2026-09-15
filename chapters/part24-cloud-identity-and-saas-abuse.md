---
title: "Cloud Identity & SaaS Abuse"
part: 24
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 24 — Cloud Identity & SaaS Abuse

## Why this part exists

**[CONCEPT]** Part 6 generalized authentication abuse — spray, push-bombing, impossible travel — across any identity provider's sign-in log, because that shape of abuse doesn't care whether the IdP sits on-prem or in the cloud. This part covers what genuinely is cloud- and SaaS-specific: an OAuth app registration that hands a third party standing API access without IT ever provisioning an account for it, a guest or federated identity that gets a directory role your own tenant never issued a password for, and a conditional-access policy satisfied by something other than the login it was built to gate. None of the five patterns below has a clean on-prem AD/Kerberos equivalent, which is the actual dividing line this part draws, not the specific vendor named in a query's framing sentence.

**Explicit boundary against neighboring parts.** Part 6 owns generic brute-force/spray/MFA-fatigue/impossible-travel logic against any sign-in log and is not re-derived here for Okta or Google Workspace specifically. Part 17 owns the *use* of a stolen token or session to move laterally once an attacker already holds it; this part stops at the moment a grant, role assignment, or bypass is discovered. Part 25 and Part 26 own AWS/Azure/GCP control-plane IAM — role chaining, storage exposure, instance-metadata theft — while this part stays at the identity-provider and SaaS-consent layer even where the platform (Entra ID) doubles as Azure's directory. This part's five patterns adapt DEH Part 18's four canonical detections and one hunt into hunt-first form, the same way Part 5 and Part 6 adapt DEH Part 12.

**Primary DEH cross-ref:** DEH Part 18 (Cloud Identity & SaaS Detection Engineering), whose §§2–5 carry DET-18-01 through DET-18-04 and HUNT-18-01 — the canonical analytics QC-24-01 through QC-24-05 below adapt into ad hoc hunt form, and whose §1 telemetry-layer table (sign-in log versus audit log, and the licensing gates behind both) this part assumes as read rather than re-deriving.

**[SOC MANAGEMENT]** QC-24-01 and QC-24-03 tune cleanly into standing near-real-time rules once a publisher/exception allowlist exists — graduation candidates, not permanent hunts, the same posture Part 5 takes toward its own single-source spray pattern. QC-24-02 should stay a low-volume, near-real-time rule rather than a scheduled hunt, since it fires rarely and a delay between assignment and alert defeats the point. QC-24-04 carries real telemetry-availability risk (see its Blind Spot below) and is better run as a periodic validated hunt until that availability is confirmed. QC-24-05 is a hygiene sweep by design — run it monthly or quarterly, never as a fired alert, per DEH Part 43's framing of scheduled low-urgency checks as distinct from real-time detection.

## Query patterns

### QC-24-01 — Self-service consent to a high-privilege OAuth scope

| Field | Value |
|---|---|
| **Pattern ID** | `QC-24-01` |
| **MITRE** | T1528 (Steal Application Access Token); T1550.001 (Use Alternate Authentication Material: Application Access Token) |
| **Behavior** | A user completes self-service consent for an application requesting a high-privilege delegated scope (mail, files, or directory read/write, or `offline_access`), with no corresponding admin-consent marker on the event. |
| **DEH cross-ref** | DEH Part 18 §2 (DET-18-01 — suspicious OAuth app consent grant) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** An illicit consent grant survives a password reset because the attacker never needed the password a second time — the refresh token issued at the moment of consent keeps working until someone explicitly revokes it. A hunter working a tip (a user reporting an odd consent prompt, a helpdesk ticket about an app nobody recognizes) needs the ad hoc version of this query before the standing rule's own scheduled publisher-verification enrichment pass runs. Start here whenever the tip names a specific user or app rather than waiting for a wider sweep.

**[QUERY]** Sigma, a single-event selection rule against Entra ID `AuditLogs` — no correlation stage needed, since this pattern is a boolean filter on one event, not a threshold.

CONCEPTUAL SAMPLE — field names and the scope list illustrative; `ModifiedProperties` and `AdditionalDetails` shapes vary by tenant schema version, validate before deploying.
```yaml
title: Self-Service Consent to High-Privilege OAuth Scope
id: 7c4e9a21-3f6b-4d82-9e15-6a2c8f4b91d0
status: experimental
logsource:
  product: azure
  service: AuditLogs
detection:
  selection:
    OperationName: 'Consent to application'
  highprivscope:
    ModifiedProperties|contains:
      - 'Mail.Read'
      - 'Files.ReadWrite.All'
      - 'Directory.ReadWrite.All'
      - 'offline_access'
  notadminconsent:
    AdditionalDetails|contains: '"key":"AdminConsent","value":"False"'
  condition: selection and highprivscope and notadminconsent
level: medium
tags:
  - attack.t1528
  - attack.t1550.001
```
Plausible expected result: one alert per qualifying event, naming the consenting user and the raw modified-properties payload the scope match fired on. Interpretation: consistent with a self-consented high-privilege grant; this is a first-stage filter, not a verdict — pair it with the publisher-verification pivot below before treating a hit as confirmed abuse.

**[QUERY]** Sentinel/Defender KQL against Entra ID `AuditLogs`, adapted from DEH DET-18-01.

CONCEPTUAL SAMPLE — validate the exact `OperationName` string and `TargetResources`/`AdditionalDetails` nesting against your own tenant's current schema before trusting a zero-row run as clean.
```kql
AuditLogs
| where OperationName == "Consent to application"
| where isnotempty(TargetResources)
| extend RequestedScope = tostring(TargetResources[0].modifiedProperties)
| mv-expand AdminDetail = AdditionalDetails
| where tostring(AdminDetail.key) == "AdminConsent"
| extend IsAdminConsent = tobool(tostring(AdminDetail.value))
| where RequestedScope has_any ("Mail.Read", "Files.ReadWrite.All", "Directory.ReadWrite.All", "offline_access")
| where IsAdminConsent == false
| project TimeGenerated, ConsentedBy = tostring(InitiatedBy.user.userPrincipalName), RequestedScope, Result
```
Plausible expected result: a handful to a few dozen rows a month in a tenant with self-service consent enabled, each naming a consenting UPN and the scope string it matched on. Interpretation: unchanged from the Sigma form above — a tenant that instead sees zero rows every month either has self-service consent already restricted (worth confirming, not assuming) or the query's field names have drifted from the live schema.

**[QUERY]** Splunk SPL against an Okta System Log index, covering the same behavior on a tenant whose OAuth authorization surface is Okta's own rather than Entra ID's.

CONCEPTUAL SAMPLE — Okta has revised its System Log `eventType` taxonomy across API versions before (DEH Part 18 §1); confirm the current value for a consent-grant event against your own tenant's live log before trusting this filter.
```spl
index=okta sourcetype="OktaIM2:log" eventType="app.oauth2.as.consent.grant"
| spath input=debugContext.debugData path=grantedScopes output=granted_scopes
| where match(granted_scopes, "(?i)mail\.read|files\.readwrite\.all|directory\.readwrite\.all|offline_access")
| table _time, actor.alternateId, target{}.displayName, granted_scopes
```
Plausible expected result: rows naming the consenting actor, target application, and granted-scope string, at a volume tracking how actively users self-onboard OIN-catalog integrations. Interpretation: the same claim as the KQL form, read from Okta's authorization-server log — run both where both exist rather than assuming one IdP covers every SaaS app in use.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. Investigative form against an M365 Unified Audit Log feed ingested through a custom DSM extension.

CONCEPTUAL SAMPLE — assumes a DSM extension already maps the M365 consent operation to a queryable QID and payload field; without that extension the operation name and scope list are unparsed payload text, not columns.
```sql
SELECT username, UTF8(payload) AS scope_detail, starttime
FROM events
WHERE QIDNAME(qid) = 'Consent to application'
  AND (UTF8(payload) ILIKE '%Mail.Read%'
       OR UTF8(payload) ILIKE '%Files.ReadWrite.All%'
       OR UTF8(payload) ILIKE '%Directory.ReadWrite.All%'
       OR UTF8(payload) ILIKE '%offline_access%')
LAST 24 HOURS
```
Plausible expected result: one row per qualifying event, or an empty set as likely to mean "the DSM mapping is stale" as "no consent activity occurred." Interpretation: unchanged from the other surfaces — a hit is a lead for the pivot below, not a scored offense.

**[QUERY]** Google SecOps YARA-L against Google Workspace Token audit events, covering the same behavior where the SaaS-consent surface is Workspace rather than Microsoft's.

CONCEPTUAL SAMPLE — UDM event-type and field-path mapping for Workspace Token `authorize` events illustrative; confirm against a live Chronicle parser output before relying on it.
```yaral
rule qc_24_01_self_consent_highpriv_scope {
  meta:
    description = "Self-service OAuth token authorization for a high-privilege Workspace scope"
    mitre_technique_id = "T1528"

  events:
    $e.metadata.product_event_type = "authorize"
    $e.target.application.name = $app
    $e.principal.user.userid = $user
    $e.security_result.description = $scope
    $scope = /(?i)(drive|gmail)\.(readonly|modify)|mail\.google\.com/

  match:
    $user, $app over 24h

  condition:
    $e
}
```
Plausible expected result: a match per user/app pair authorizing a matching scope inside the window. Interpretation: the same claim as the other surfaces, gated on whether your Workspace-to-Chronicle parser populates `security_result.description` with the scope text — confirm against a known test authorization first.

**[QUERY]** Elastic KQL (not Sentinel/Defender KQL) — a single-event boolean match, the cheapest fit per DEH Appendix A5 §7.6, over an Azure AD audit-log index.

CONCEPTUAL SAMPLE — index and field paths depend on your specific Azure/O365 integration mapping.
```kql
event.dataset : "azure.auditlogs" and azure.auditlogs.operation_name : "Consent to application"
  and azure.auditlogs.properties.target_resources : ("Mail.Read" or "Files.ReadWrite.All" or "Directory.ReadWrite.All" or "offline_access")
  and azure.auditlogs.properties.additional_details : "*AdminConsent*False*"
```
Plausible expected result and interpretation: unchanged from the KQL/Sigma forms above — this is the same analytic on Elastic's own audit-log ingest path.

**[FALSE POSITIVE]** Low-code and RPA platforms (Power Automate flows a business user builds unassisted, e-signature tools, meeting-scheduling add-ins, backup and eDiscovery platforms) routinely request exactly these scopes under self-consent, because letting a non-admin wire up an integration without an IT ticket is the entire point of the tool. Maintain an allowlist of already-vetted publisher app IDs and exclude them at the query level, then treat every new, previously-unseen app ID requesting the same scope class as the item worth an analyst's time — the fix is delta-based novelty, not a permanent scope exclusion, which would just recreate the same blind spot the naive scope-only version of this query has.

**[PIVOT]** Pull the app registration's publisher-verification status, multi-tenant flag, and creation date directly from the directory — an unverified, multi-tenant, days-old app is a materially different claim than a verified app your own platform team registered last year. Check whether the grant has actually been used yet (QC-24-05's own join logic answers this directly); a grant with zero subsequent API activity is lower urgency than one already pulling mail or files.

> **Blind Spot**
> Every query above filters on `IsAdminConsent == false` (or its Okta/Workspace equivalent) specifically to cut the routine-SaaS-onboarding noise named above. That same filter means admin-consent phishing — social-engineering a Global Administrator into approving the same broad scope tenant-wide — is filtered out entirely, even though it's the higher-impact variant of the same attack. A grant created programmatically against Graph or the Workspace Admin SDK by an already-compromised privileged token may not emit a `Consent to application`-shaped event at all. Cover the admin-consent path with a separate query flagging `IsAdminConsent == true` grants outside a defined admin-approved-apps baseline.

---

### QC-24-02 — Guest or external identity granted a privileged role directly

| Field | Value |
|---|---|
| **Pattern ID** | `QC-24-02` |
| **MITRE** | T1199 (Trusted Relationship); T1078.004 (Valid Accounts: Cloud Accounts) |
| **Behavior** | An external guest, B2B-invited, or federated identity receives a built-in privileged directory or admin role directly, not through group membership. |
| **DEH cross-ref** | DEH Part 18 §3 (DET-18-02 — guest account granted a privileged directory role) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** B2B guest access lets an external identity authenticate with credentials your own directory never issued, and directly assigning that identity a built-in privileged role — rather than nesting it into an already-scoped group — is a deliberate, uncommon action in a well-governed tenant. A hunter chasing a tip about an unusual admin action or a compromised partner organization can scan for this shape immediately, since it should already be rare enough that a hit is itself worth escalating rather than a background rate to tune down.

**[QUERY]** Sigma, a single-event selection against Entra ID `AuditLogs`.

CONCEPTUAL SAMPLE — the `#EXT#` guest UPN suffix is Entra ID's default and may be customized per tenant; confirm before deploying.
```yaml
title: Privileged Role Assigned Directly to a Guest Identity
id: 2a9f6d13-8b4c-4e71-a3f2-1d7c9b5e6a48
status: experimental
logsource:
  product: azure
  service: AuditLogs
detection:
  selection:
    OperationName:
      - 'Add member to role'
      - 'Add eligible member to role'
  guestmarker:
    TargetResources|contains: '#EXT#'
  condition: selection and guestmarker
level: high
tags:
  - attack.t1199
  - attack.t1078.004
```
Plausible expected result: an alert instance per qualifying role-assignment event naming the guest UPN and role. Interpretation: consistent with a direct privileged-role assignment to an external identity — rare enough in a well-governed tenant that a hit is a lead worth same-day triage, not routine noise.

**[QUERY]** Sentinel/Defender KQL against Entra ID `AuditLogs`, adapted from DEH DET-18-02.

CONCEPTUAL SAMPLE — `TargetResources` element order and the `Role.DisplayName` modified-property name are not a documented stable contract; validate against a real event from your tenant before trusting either.
```kql
AuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| mv-expand Target = TargetResources
| where tostring(Target.type) == "User" and tostring(Target.userPrincipalName) has "#EXT#"
| project TimeGenerated, InitiatedBy, TargetUPN = tostring(Target.userPrincipalName), Result
```
Plausible expected result: honestly close to zero most weeks in a well-governed tenant, since this is a deliberate action rather than routine administration — a short burst of several hits is itself the finding, not noise to filter further. Interpretation: unchanged from the Sigma form; a sudden cluster here is worth treating as a signal on volume alone, unlike QC-24-01 where routine SaaS onboarding guarantees a steady background rate.

**[QUERY]** Splunk SPL against an Okta System Log index, covering the same behavior for a federated (non-Okta-native) user profile receiving a direct admin-role grant.

CONCEPTUAL SAMPLE — Okta's federated-user profile-source field and its admin-role-grant `eventType` value are illustrative; confirm both against your tenant.
```spl
index=okta sourcetype="OktaIM2:log" eventType="user.account.privilege.grant"
| where target{}.detail.profile_source!="OKTA"
| table _time, actor.alternateId, target{}.alternateId, target{}.detail.profile_source, outcome.result
```
Plausible expected result and interpretation: the same rare, deliberate-action shape as the KQL result, read from Okta's own admin-role-grant event instead of Entra ID's directory audit log.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. A single filter query is sufficient here; no chained Building Block/Reference Set model is needed since this is a boolean match, not a multi-stage aggregation.

CONCEPTUAL SAMPLE — confirm your identity DSM extracts a queryable username field before trusting the `LIKE` match.
```sql
SELECT username, QIDNAME(qid) AS event_type, starttime
FROM events
WHERE QIDNAME(qid) IN ('Add member to role', 'Add eligible member to role')
  AND UTF8(username) ILIKE '%#EXT#%'
LAST 24 HOURS
```
Plausible expected result: zero or one row on most days, per the same rarity argument above. Interpretation: unchanged — an empty result here is a legitimate, expected outcome, not a query failure.

**[QUERY]** Google SecOps YARA-L, covering the Google Workspace analog: a user whose primary email domain differs from the Workspace's own verified domains receiving an admin-role change.

CONCEPTUAL SAMPLE — the UDM field path for a Workspace admin-role-change event and its domain-comparison logic are illustrative; confirm against a live parser output.
```yaral
rule qc_24_02_external_domain_admin_role {
  meta:
    description = "Admin role change targeting a user outside the Workspace's verified domains"
    mitre_technique_id = "T1199"

  events:
    $e.metadata.product_event_type = "ADMIN_SERVICE_ROLE_CHANGE"
    $e.target.user.userid = $user
    not $user = /@(your-verified-domain\.com|your-secondary-domain\.com)$/

  condition:
    $e
}
```
Plausible expected result and interpretation: the same rare-and-deliberate shape as the other surfaces; the domain allowlist inside the rule is the one piece every deployment must edit before use, not a generic default.

**[QUERY]** Elastic KQL (not Sentinel/Defender KQL) over an Azure AD audit-log index — a single-event boolean match.

CONCEPTUAL SAMPLE — field paths depend on your specific integration mapping.
```kql
event.dataset : "azure.auditlogs" and azure.auditlogs.operation_name : ("Add member to role" or "Add eligible member to role")
  and azure.auditlogs.properties.target_resources : "*#EXT#*"
```
Plausible expected result and interpretation: unchanged from the other five surfaces.

**[FALSE POSITIVE]** A genuine merger, acquisition, or large contractor-onboarding wave produces a real burst of new guest invitations and, often, deliberate privileged-role assignments to specific external consultants — a legitimate business event that looks identical, at the query level, to an attacker methodically escalating a foothold guest account. Cross-reference against a change calendar or a named business sponsor for the invitation batch before escalating; the fix here is a documented, dated approval record attached to the exception, not a query threshold.

**[PIVOT]** Confirm the assignment against a change record or business sponsor before escalating. Separately, check whether the same external identity reaches equivalent effective access through nested group membership rather than a direct role — a query that only reads direct role-assignment events, including every one above, cannot see that path at all.

> **Blind Spot**
> Every query above reasons only about *direct* role assignment, and only about *outbound* trust — guests or federated identities your own tenant explicitly invited or assigned. An identity that reaches the same privileged access through inherited group membership never appears in these results, because none of them walk the group-membership graph; that gap is large and mostly benign, since nested-group membership is the standard mechanism most enterprises use to grant access at scale, but it means a real escalation routed through a group is invisible here. Separately, cross-tenant access settings govern whether an already-compromised partner tenant that holds a *standing* trust relationship with yours can pivot in without ever generating an invitation event in the first place — from your tenant's own audit trail, nothing was invited, because nothing needed to be.

---

### QC-24-03 — Legacy-protocol or second-factor-bypass sign-in against an intended-block policy

| Field | Value |
|---|---|
| **Pattern ID** | `QC-24-03` |
| **MITRE** | T1078.004 (Valid Accounts: Cloud Accounts) — no clean single-technique mapping for the underlying policy-scope gap itself; see `[HUNTER]` |
| **Behavior** | A successful authentication via a legacy, non-interactive protocol (IMAP4, POP3, older ActiveSync, basic-auth SMTP) or an app-password path that bypasses second-factor enforcement, against a tenant whose documented policy intends to block or challenge it. |
| **DEH cross-ref** | DEH Part 18 §4.1 (DET-18-03 — legacy authentication protocol usage against an intended-block policy) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** A tenant-wide "legacy authentication blocked" or "second-factor required" policy is a name in a policy summary, not a guarantee — per-app and per-user exceptions accumulate for years, usually for a device or integration nobody remembers approving, and none of them surface in a dashboard that only reports the policy as enabled. Reach for this hunt whenever you need to know actual legacy-auth or bypass-path volume in the sign-in logs, rather than trusting the policy's own name as ground truth.

**[QUERY]** Sigma, a single-event selection against Entra ID `SigninLogs`.

CONCEPTUAL SAMPLE — the `ClientAppUsed` value list is illustrative; confirm which legacy-protocol labels your tenant actually emits before deploying.
```yaml
title: Successful Legacy Authentication Sign-In
id: 5e1c8a94-4d2f-4b6a-9c8e-7a3f2d1b9e60
status: experimental
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    ResultType: '0'
    ClientAppUsed:
      - 'IMAP4'
      - 'POP3'
      - 'Exchange ActiveSync'
      - 'Other clients'
  condition: selection
level: medium
tags:
  - attack.t1078.004
```
Plausible expected result: an alert per successful sign-in tagged with a legacy `ClientAppUsed` value. Interpretation: a policy-enforcement gap worth investigating on its own, independent of whether the account itself is compromised — it means the intended block has a scoping hole.

**[QUERY]** Sentinel/Defender KQL against `SigninLogs`, adapted from DEH DET-18-03.

CONCEPTUAL SAMPLE — Microsoft has added and renamed `ClientAppUsed` values before; re-verify the list against your tenant's current sign-in logs periodically rather than treating it as fixed.
```kql
SigninLogs
| where ClientAppUsed in ("Other clients","IMAP4","POP3","Exchange ActiveSync","Authenticated SMTP")
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, ConditionalAccessStatus
```
Plausible expected result: in a tenant that has actually enforced the block, hits cluster almost entirely on a small, named exception list — the same few identities week over week — rather than spreading across the user population. Interpretation: any hit from an account not already on that exception list is the rare, high-value case this query exists to surface, and should be triaged as a scoping gap or possible compromise immediately, not batched in with routine exception traffic.

**[QUERY]** Splunk SPL against an Exchange Online / M365 Unified Audit Log index, targeting basic-auth SMTP/IMAP sign-ins.

CONCEPTUAL SAMPLE — field names assume a standard Microsoft 365 audit-log add-on mapping.
```spl
index=m365_unified_audit Operation="MailboxLogin" AuthenticationType="Basic" ResultStatus="Succeeded"
| table _time, UserId, ClientInfoString, ClientIPAddress
```
Plausible expected result and interpretation: the same policy-scoping-gap claim as the KQL form, read from the mailbox-access side of the audit log rather than the sign-in log.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. Single filter query against an ingested Entra ID `SigninLogs` feed.

CONCEPTUAL SAMPLE — assumes an Azure AD DSM extension already maps `clientappused` and `resulttype` as queryable fields.
```sql
SELECT username, sourceip, UTF8(clientappused) AS client_app
FROM events
WHERE resulttype = '0'
  AND UTF8(clientappused) IN ('IMAP4','POP3','Exchange ActiveSync','Other clients')
LAST 24 HOURS
```
Plausible expected result: identical shape to the other surfaces, gated on whether the DSM mapping is current. Interpretation: a zero-result run is as likely to mean "the field mapping is stale" as "the block actually holds" — verify the mapping before trusting an empty result as clean.

**[QUERY]** Google SecOps YARA-L, covering the Google Workspace analog: an IMAP or POP login using an app password that bypasses 2-Step Verification entirely.

CONCEPTUAL SAMPLE — the UDM field path for a Workspace login event's second-factor and app-password indicators is illustrative; confirm against a live parser output.
```yaral
rule qc_24_03_workspace_app_password_bypass {
  meta:
    description = "Workspace login via app password, bypassing 2-Step Verification"
    mitre_technique_id = "T1078.004"

  events:
    $e.metadata.product_event_type = "login_success"
    $e.extensions.auth.mechanism = "APPLICATION_SPECIFIC_PASSWORD"
    $e.target.user.userid = $user

  condition:
    $e
}
```
Plausible expected result and interpretation: the same policy-scoping-gap claim as the other surfaces — Google Workspace's app-password feature is a structurally identical bypass to Entra ID's legacy protocols, since both were built before, and sit outside, second-factor enforcement.

**[QUERY]** Elastic KQL (not Sentinel/Defender KQL) over an Azure AD sign-in-log index — a single-event boolean match.

CONCEPTUAL SAMPLE — field path for `ClientAppUsed` depends on your ECS integration mapping version.
```kql
event.dataset : "azure.signinlogs" and azure.signinlogs.properties.client_app_used : ("IMAP4" or "POP3" or "Exchange ActiveSync" or "Other clients")
  and azure.signinlogs.properties.status.error_code : 0
```
Plausible expected result and interpretation: unchanged from the KQL/Sigma forms above.

**[FALSE POSITIVE]** Multifunction printers, scan-to-email appliances, and a handful of legacy line-of-business applications with hardcoded SMTP or IMAP integration are the most common source of legitimate legacy-auth traffic, and Google Workspace's own app-password feature exists specifically so users can keep an old mail client or script working — which is exactly why many tenants carve out narrow, named exceptions rather than a clean universal block. Maintain those exceptions as dated, reviewed entries and alert on any success from an account not on that list, rather than tuning the query to ignore legacy auth broadly — a broad exclusion silently recreates the exact bypass path this pattern exists to close.

**[PIVOT]** Confirm whether the flagged account or app password is on the documented exception list; if it isn't, treat this as a policy-scoping gap independent of whether the account is compromised. Check for other protocols or applications sharing the same gap, since a scoping hole rarely affects just one account.

> **Engineering Reality**
> A conditional access policy summary that reads "legacy authentication blocked" or a Workspace admin console that reads "less secure app access disabled" is a policy *name*, not a measurement. Per-app and per-user exceptions accumulate silently over years — a fax-to-email gateway approved by someone who left the company, a CRM integration nobody re-audits — and none of them change what the policy summary reports. The only way to know the actual enforcement boundary is the sign-in-log volume these queries surface directly; treat the policy's displayed status as a claim to verify, not a fact to build on.

---

### QC-24-04 — Session or refresh token reused from an inconsistent device or network fingerprint

| Field | Value |
|---|---|
| **Pattern ID** | `QC-24-04` |
| **MITRE** | T1550.004 (Use Alternate Authentication Material: Web Session Cookie) |
| **Behavior** | The same session or refresh-token identifier is used from two or more materially different device fingerprints or network locations within one active session lifetime. |
| **DEH cross-ref** | DEH Part 18 §4.2 (DET-18-04 — session or refresh token used from an inconsistent device or network fingerprint) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L: `N/A`, see below; Elastic (ES\|QL) |

**[HUNTER]** An adversary-in-the-middle phishing proxy captures a session token after the legitimate user has already cleared MFA, so the conditional-access evaluation itself reads success — the policy genuinely was satisfied, just not by whoever is using the token now. This hunt sidesteps the conditional-access result field entirely and instead asks whether one session identifier's own usage history is internally consistent, which is the one thing a stolen-but-valid token cannot fake if the platform captures it at all.

**[QUERY]** Sigma, a distinct-count correlation over a base session-usage rule — the same `value_count` shape Part 5's QC-05-01 uses, grouped by session identifier instead of source IP.

CONCEPTUAL SAMPLE — correlation type and threshold illustrative; validate `value_count` support against your Sigma backend, and confirm your platform emits a session-usage event with a stable session identifier at all before deploying.
```yaml
title: Session Identifier Used From Multiple Device Fingerprints
correlation:
  type: value_count
  rules:
    - session_usage_event
  group-by:
    - SessionId
  timespan: 8h
  condition:
    field: DeviceFingerprint
    gte: 2
---
title: Session Usage Event
id: session_usage_event
logsource:
  category: authentication
detection:
  selection:
    EventType: 'session_token_used'
  condition: selection
```
Plausible expected result: a correlation alert per `SessionId` whose distinct `DeviceFingerprint` count reaches two or more inside eight hours. Interpretation: consistent with the same session being presented from more than one device — plausible evidence of token replay, not yet distinguished from the false-positive drivers below.

**[QUERY]** Sentinel/Defender KQL against a generic session-usage telemetry table — field names here are illustrative, since a stable session identifier paired with a per-use device fingerprint is not uniformly exposed across every Entra ID licensing tier.

CONCEPTUAL SAMPLE — this schema is invented to illustrate the join logic; confirm what your specific Continuous Access Evaluation or token-protection feature actually logs before treating this as a drop-in query.
```kql
SessionUsageEvents
| where TimeGenerated > ago(8h)
| summarize DistinctIPs = dcount(UsedIP), DistinctDevices = dcount(UsedDeviceFingerprint) by SessionId
| where DistinctIPs > 1 or DistinctDevices > 1
```
Plausible expected result: a small number of `SessionId` rows whose distinct-IP or distinct-device count exceeds one inside the lookback window. Interpretation: unchanged from the Sigma form — the mobile-network driver named below produces this exact shape constantly on an ordinary day.

**[QUERY]** Splunk SPL, the same aggregation shape against an equivalent session-usage index.

CONCEPTUAL SAMPLE — sourcetype and field names illustrative, same schema caveat as the KQL form above.
```spl
index=identity sourcetype=session_usage earliest=-8h
| stats dc(used_ip) as distinct_ips, dc(used_device_fp) as distinct_devices by session_id
| where distinct_ips>1 OR distinct_devices>1
```
Plausible expected result and interpretation: unchanged from the KQL form.

**[QUERY]** QRadar AQL — this is AQL, not standard SQL. Single grouped-aggregation query; whether this returns anything meaningful depends entirely on whether the ingested identity feed carries a session identifier at all.

CONCEPTUAL SAMPLE — assumes a custom identity-platform log source extension exposes `session_id` and a device-fingerprint field as queryable columns, which most default DSMs do not. `HAVING` filters on the `distinct_ips`/`distinct_devices` aliases rather than the raw `UNIQUECOUNT(...)` expressions, per IBM's only documented AQL `HAVING` pattern (IBM Documentation, "AQL data aggregation functions," QRadar SIEM 7.4/7.5: https://www.ibm.com/docs/en/qsip/7.5?topic=SS42VS_7.5/com.ibm.qradar.doc/r_aql_aggregate_functions.html).
```sql
SELECT session_id, UNIQUECOUNT(sourceip) AS distinct_ips, UNIQUECOUNT(devicefingerprint) AS distinct_devices
FROM events
WHERE QIDNAME(qid) = 'Session token used'
GROUP BY session_id
HAVING distinct_ips > 1 OR distinct_devices > 1
LAST 8 HOURS
```
Plausible expected result: an empty set on most deployments, since the underlying fields are rarely present without a custom extension. Interpretation: a persistently empty result is more likely "not ingested" than "no replay occurred" — confirm the field mapping exists before trusting a clean run.

*YARA-L — N/A, missing schema field: there is no confirmed UDM field carrying a stable session or refresh-token identifier alongside a device fingerprint captured at each point of use, the same class of gap DEH Part 28 §1.1 documents for `GrantedAccess`. If your deployment ingests a custom label carrying this pairing, substitute it and validate a known multi-device test session before trusting a zero-hit run as clean.*

**[QUERY]** Elastic ES\|QL, chosen because this is a threshold/wide-lookback aggregation shape rather than an ordered sequence, per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — index and field names illustrative, same schema-availability caveat as the KQL/SPL forms above.
```esql
FROM logs-identity.session-usage*
| WHERE @timestamp > NOW() - 8 hours
| STATS distinct_ips = COUNT_DISTINCT(used_ip), distinct_devices = COUNT_DISTINCT(used_device_fp) BY session.id
| WHERE distinct_ips > 1 OR distinct_devices > 1
```
Plausible expected result and interpretation: unchanged from the other covered surfaces.

**[FALSE POSITIVE]** A single session legitimately crossing multiple IPs and even device-fingerprint readings within one workday is common, not exceptional — a mobile user's visible IP changes every time a carrier hands the device between towers or it switches from cellular to Wi-Fi, and a double-NAT'd home or corporate network can present a different egress IP on consecutive requests with no device change at all. This is the single largest driver of hits across every language above. Score IP changes by network distance (an IP change within the same ASN or metro minutes apart is a different claim than a cross-country jump) and require the device fingerprint to shift too, rather than alerting on either signal alone — widening the threshold to "fix" this just makes the query blind to a faster real replay too.

**[PIVOT]** Before trusting any result from this pattern, confirm your specific identity platform and license tier actually populates a stable session identifier paired with a per-use device fingerprint — a silent schema gap and a genuinely clean tenant produce an identical empty result. Where a real hit surfaces, revoke the specific session or refresh token and force re-authentication; a password reset alone does not close this access path, since the token was never password-dependent.

> **Blind Spot**
> This pattern's usability is gated behind telemetry most tenants lack by default. Microsoft's Continuous Access Evaluation and token-protection features target exactly this problem, but their logged fields vary by license tier; Okta's and Workspace's equivalents are similarly inconsistent. Where that telemetry doesn't exist, every query above returns a clean-looking empty result indistinguishable from "no replay happened" — confirm the fields are populating, with a deliberate multi-device test session, before trusting a quiet production run.

---

### QC-24-05 — Dormant high-privilege OAuth app with no post-consent API usage

| Field | Value |
|---|---|
| **Pattern ID** | `QC-24-05` |
| **MITRE** | T1528 (Steal Application Access Token) |
| **Behavior** | An OAuth app registration holds a consented high-privilege delegated scope older than a stated age threshold, with no corresponding API-usage activity recorded since consent. |
| **DEH cross-ref** | DEH Part 18 §5.1 (HUNT-18-01 — dormant high-privilege OAuth apps) |
| **Languages covered** | Sigma: `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar): `N/A`, see below; YARA-L: `N/A`, see below; Elastic (ES\|QL) |

**[HUNTER]** A standing consent-grant rule like QC-24-01 only sees the moment of consent — it says nothing about what happens to the grant afterward. An OAuth app that was handed a high-privilege scope but has made little or no use of that grant since is either a forgotten, never-deployed integration or a backdoor an attacker registered, phished consent for, and hasn't activated yet, and either finding is worth surfacing: a standing high-privilege grant with zero usage history has no legitimate reason to keep existing regardless of which case it turns out to be.

*Sigma — N/A, aggregation ceiling: this pattern needs the set difference between two independently-matched event categories — apps with a qualifying consent event, minus apps with any usage event in the following N days — which none of Sigma's correlation types (`event_count`, `value_count`, `temporal`, `temporal_ordered`) can express; each counts or orders matches within one rule's own event stream, none supports an anti-join across two separately-matched rule types.*

**[QUERY]** Sentinel/Defender KQL, joining Entra ID app-registration consent history against service-principal sign-in activity, adapted from DEH HUNT-18-01.

CONCEPTUAL SAMPLE — the 30-day age threshold is illustrative; service-principal sign-in activity requires Identity Protection-tier logging in many tenants (DEH Part 18 §1's licensing note) — confirm it's enabled before trusting a zero-usage result as real.
```kql
let HighPrivGrants = AuditLogs
| where OperationName == "Consent to application" and TimeGenerated < ago(30d)
| extend AppId = tostring(TargetResources[0].id), RequestedScope = tostring(TargetResources[0].modifiedProperties)
| where RequestedScope has_any ("Mail.Read", "Files.ReadWrite.All", "Directory.ReadWrite.All", "offline_access");
let RecentUsage = AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| distinct AppId = ServicePrincipalId;
HighPrivGrants
| join kind=leftanti RecentUsage on AppId
```
Plausible expected result: a small number of app IDs with a qualifying grant older than 30 days and no matching row in `RecentUsage`. Interpretation: consistent with either an abandoned integration or an unused backdoor grant — a dated, negative usage finding worth pursuing, not itself a confirmed compromise.

**[QUERY]** Splunk SPL, the same anti-join shape against equivalent consent-history and usage-history indexes.

CONCEPTUAL SAMPLE — assumes both indexes carry a common app-identifier field; validate the join key before trusting an empty result.
```spl
| inputlookup highpriv_grants_30d.csv
| join type=outer app_id
    [ search index=identity sourcetype=app_signin_activity earliest=-30d
      | stats count by app_id ]
| where isnull(count)
```
Plausible expected result and interpretation: unchanged from the KQL form above — same claim, read from a maintained lookup rather than a native Entra ID table.

*AQL — N/A, aggregation ceiling: the same structural gap named for Sigma applies for a different reason. AQL's `SELECT` has no subquery or common-table-expression stage to feed one category's matched app-ID set into an anti-join against a second category's usage events (per DEH Appendix A5 §4's precedent, and the reasoning this book's own QC-05-04 applies to a different two-stage rollup). Approximate this by exporting both result sets and reconciling them outside AQL, not by forcing a misleading single-query translation.*

*YARA-L — N/A, aggregation ceiling: the same cross-category anti-join Sigma and AQL lack applies here too; YARA-L's `condition` section can negate a field's *value* within one matched event, but has no construct for asserting a second, independently-defined event type never occurred for a given entity across an open-ended window.*

**[QUERY]** Elastic ES\|QL, the same anti-join shape, chosen as the wide-lookback aggregation fit per DEH Appendix A5 §8's decision table.

CONCEPTUAL SAMPLE — assumes a consent-history data view and a usage-history data view share a common app-identifier field.
```esql
FROM logs-azure.auditlogs-consent-30d
| LOOKUP JOIN logs-azure.serviceprincipal-signins-30d ON app_id
| WHERE usage_count IS NULL OR usage_count == 0
```
Plausible expected result and interpretation: unchanged from the KQL/SPL forms above.

**[FALSE POSITIVE]** A legitimate integration that runs infrequently by design — an annual compliance-attestation tool, a disaster-recovery failover script, a backup-verification job scheduled quarterly — will show 30-plus days of zero usage between runs and look identical, on this query alone, to a genuinely abandoned or backdoored grant; expect a real tenant to surface a non-trivial background rate of these legitimate-but-quiet apps every sweep, not a rare exception. Separately, because the usage-side telemetry this pattern joins against is itself gated behind licensing in some tenants, a broken or unlicensed usage feed makes every high-privilege grant in the tenant look dormant at once — a mass positive spike, not a mass negative, is the tell that the join broke rather than that every app went quiet simultaneously.

**[PIVOT]** Cross-check the app's registration description and business owner before escalating a dormant hit — most legitimate-but-quiet apps resolve in one lookup. Where a grant is genuinely unexplained, feed it directly into QC-24-01's revoke-consent action rather than opening a separate workflow.

> **Hunter's Note**
> Before trusting a production run, seed one deliberately-unused test app and one lightly-used test app with the same scope, and confirm the sweep tells them apart. If the usage-telemetry join is broken by a licensing gap or schema change, both test apps — and every real app in the tenant — show up dormant at once, and that mass-positive spike is the signal the join failed, not a hygiene finding worth escalating.

## Cross-references

This part's queries adapt DEH Part 18 §§2–5 (DET-18-01 through DET-18-04, and HUNT-18-01) into hunt-first form, and assume DEH Part 18 §1's sign-in-log/audit-log telemetry split and its per-platform licensing-gate table as read rather than re-deriving either. DEH Appendix A5 §4 and §8 are cited throughout for the aggregation-ceiling reasoning behind QC-24-04's and QC-24-05's `N/A` entries and for the Elastic-surface-selection decision table. Within this book: Part 5 (Password Spraying) for the `value_count` Sigma correlation shape QC-24-04 borrows; Part 6 (MFA Abuse & Authentication Anomalies) for the generic authentication-abuse patterns this part does not re-derive and for QC-06-05's MFA re-enrollment pattern, adjacent to but distinct from this part's consent-grant and role-assignment patterns; Part 17 (Lateral Movement via Stolen Tokens & Ticket Reuse) for what an attacker does with a token or session once QC-24-01 or QC-24-04 surfaces it; Part 25 (Cloud Infrastructure Abuse) and Part 26 (Cloud-Native Lateral Movement & Privilege Escalation) for AWS/Azure/GCP control-plane IAM abuse, kept out of this part's identity-and-SaaS-consent scope; Part 28 (Maintaining the Cookbook) for applying DEH's Detection Coverage/Quality/Debt methodology to this part's patterns as adoption evidence accumulates.
