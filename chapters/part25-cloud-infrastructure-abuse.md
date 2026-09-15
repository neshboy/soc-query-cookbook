---
title: "Cloud Infrastructure Abuse"
part: 25
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 25 — Cloud Infrastructure Abuse

## Why this part exists

**[CONCEPT]** This part covers the cloud provider's own control plane — the management APIs behind AWS, Azure, and GCP — rather than the identity-provider/SaaS layer sitting on top of it. Three named shapes make up its scope: **IAM policy abuse** (a principal granting itself or another wildcard or administrator-equivalent access through ordinary policy APIs), **storage and network exposure** (a bucket, security group, or firewall rule opened to the world through an ordinary configuration change), and **mass control-plane API activity** (a burst of calls — discovery-shaped or resource-creation-shaped — that looks nothing like routine usage). DEH Part 19 (Cloud Infrastructure Detection Engineering) owns the telemetry mechanics and worked detections this part adapts; this part cites that reasoning rather than re-deriving it.

Four explicit boundaries keep this part from silently duplicating a neighbor. **Part 24** owns the identity-provider/SaaS layer — Entra ID, Okta, Google Workspace, M365, OAuth/app-consent abuse, conditional-access bypass, cross-tenant and guest risk — the same Part 18/Part 19 seam DEH itself draws: Part 24 tells you who authenticated and how; this part tells you what that identity then did to the infrastructure. **Part 26** owns credential usage, assumed-role chaining, and instance-metadata-service credential theft — DEH Part 19 §6's territory — because that query shape earns its own part per `BOOK-INDEX.md`'s stated reasoning for the 24–26 split. **Part 20** owns mass object-level access and exfiltration from cloud data stores — DEH Part 19 §7's cross-account snapshot-sharing and GetObject-volume material — an outbound-transfer-volume question, not an infrastructure-configuration one, even where both parts cite T1530 from different angles (see QC-25-02's note below). **Part 14** owns Windows/EDR-style log and security-tool tampering; DEH Part 19 §5's `StopLogging`/`DeleteTrail`/`PutEventSelectors` material (T1562.008) has no cookbook home as of this writing — named here as an honest gap, not silently implied coverage.

Like DEH Part 19 itself, this part is provider-agnostic in structure and unevenly worked in practice: AWS CloudTrail has the deepest public detection literature, so several `[QUERY]` blocks default to it, while Azure and GCP get their own worked implementations wherever the mechanism changes the logic, not just the field names — the same discipline DEH Part 19's own "Why this part exists" section commits to.

**[SOC MANAGEMENT]** QC-25-01 through QC-25-03 tune into standing near-real-time rules cleanly once a CI/CD and IaC allowlist is current, the same "roughly one to five alerts a week" trajectory DEH Part 19 §2.1 documents for DET-19-01. QC-25-04 and QC-25-05 carry heavier aggregation cost and a larger legitimate-automation false-positive population — a weekly or biweekly hunt is the more sustainable cadence for either, per DEH Part 43's compute-cost framing of detection debt, until each has a tuned allowlist and a stable hit rate.

## Query patterns

### QC-25-01 — IAM privilege escalation via policy attachment or role-assignment grant

| Field | Value |
|---|---|
| **Pattern ID** | `QC-25-01` |
| **MITRE** | T1098.003 (Account Manipulation: Additional Cloud Roles) |
| **Behavior** | A principal attaches, creates, or is granted a policy/role assignment carrying wildcard or administrator-equivalent permissions, outside a maintained automation allowlist. |
| **DEH cross-ref** | DEH Part 19 §2, §2.1 (DET-19-01) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** DEH Part 19 §2.1 already builds this into a tuned standing detection once a CI/CD allowlist exists. Before that allowlist is current — a freshly onboarded account, or an incident already underway where you don't yet trust the allowlist isn't stale — running the same logic by hand catches the identical behavior without waiting on maintenance. It's also the first query to run manually the moment a compromised credential is suspected.

**[QUERY]** AWS CloudTrail, Sigma rule matching an `Attach*Policy` call naming an administrator-equivalent AWS-managed policy.

```yaml
title: IAM Principal Attaches Administrator-Equivalent Managed Policy
id: 6f2a19d4-8b3e-4c71-9a05-2e7c4f1b8a33
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - AttachUserPolicy
      - AttachRolePolicy
      - AttachGroupPolicy
    requestParameters.policyArn|endswith:
      - '/AdministratorAccess'
      - '/PowerUserAccess'
      - '/IAMFullAccess'
  filter:
    userIdentity.arn|contains: '%known_cicd_principals%'
  condition: selection and not filter
```

CONCEPTUAL SAMPLE — covers only the managed-policy-attach branch, not the inline-wildcard-document branch DEH Part 19 §2.1 also scores; validate `%known_cicd_principals%` against a real, maintained placeholder list before use.

Plausible expected result: a single event naming the attaching principal's ARN, the target user/role/group, and one of the three listed managed-policy ARNs. Interpretation: consistent with reaching administrator-equivalent access through a documented AWS policy rather than a custom document — narrower than the full pattern below, worth pairing with it.

**[QUERY]** Azure Activity Log via Sentinel/Defender KQL, an RBAC role-assignment write granting a built-in Owner or Contributor role.

```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Success"
| extend RequestBody = parse_json(tostring(Properties)).requestbody
| extend RoleDefinitionId = tostring(parse_json(RequestBody).properties.roleDefinitionId)
| where RoleDefinitionId has_any (
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", // Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c")  // Contributor
| where Caller !in (known_cicd_principals)
| project TimeGenerated, Caller, CallerIpAddress, RoleDefinitionId, ResourceId
```

CONCEPTUAL SAMPLE — the `Properties`/`requestbody` nesting path is illustrative; validate against your own AzureActivity schema version, and extend the role-GUID list to cover any custom role with equivalent wildcard permissions.

Plausible expected result: a row per successful role-assignment write naming the built-in role GUID, the assigning Caller, and a `ResourceId` scoped to a subscription or resource group — the widest, most consequential targets. Interpretation: the same escalation shape as the AWS form, expressed through Azure's RBAC model instead of a document-based IAM policy — a genuinely different detection shape, not a renamed field.

**[QUERY]** AWS CloudTrail SPL, condensed from DEH Part 19 §2.1's own DET-19-01.

```spl
sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com
    (eventName=AttachUserPolicy OR eventName=AttachRolePolicy OR eventName=AttachGroupPolicy
     OR eventName=PutUserPolicy OR eventName=PutRolePolicy OR eventName=PutGroupPolicy
     OR eventName=CreatePolicyVersion)
| spath input=requestParameters.policyDocument output=policy_doc
| eval grants_wildcard=if(match(policy_doc, "\"Action\"\s*:\s*(\"\*\"|\[\s*\"\*\"\s*\])") OR
    match(requestParameters.policyArn, "(AdministratorAccess|PowerUserAccess|IAMFullAccess)$"), 1, 0)
| where grants_wildcard=1
| lookup known_cicd_principals_lookup arn as userIdentity.arn OUTPUT is_known_cicd
| where isnull(is_known_cicd)
| table _time, userIdentity.arn, eventName, requestParameters.policyName, requestParameters.policyArn, sourceIPAddress
```

CONCEPTUAL SAMPLE — condensed; DEH Part 19 §2.1's full version also covers the `Resource`-wildcard case and group-scoped grants — read it directly rather than treating this as a complete substitute.

Plausible expected result: roughly one to five hits a week in a mid-sized environment with active IaC pipelines once the allowlist is current, per DEH Part 19 §2.1's documented baseline. Interpretation: unchanged from the Sigma/KQL forms — consistent with an escalation attempt, not confirmed, until the pivot below rules out routine access management.

**[QUERY]** GCP Cloud Audit Logs via QRadar AQL (not standard SQL), a `SetIamPolicy` call binding an owner/editor-equivalent role.

```sql
-- AQL, not standard SQL. Assumes a GCP Cloud Audit Logs DSM extension mapping
-- protoPayload fields into the custom properties referenced below.
SELECT "Principal Email", "Method Name", "Resource Name", "Bound Role"
FROM events
WHERE "Method Name" = 'SetIamPolicy'
  AND "Bound Role" IN ('roles/owner', 'roles/editor')
  AND "Principal Email" NOT IN ('cicd-deploy@my-project.iam.gserviceaccount.com')
LAST 1 DAYS
```

CONCEPTUAL SAMPLE — the DSM extension and its field mapping are illustrative; without a confirmed extension, `protoPayload.policyDelta.bindingDeltas` arrives as unparsed payload text, not queryable columns.

Plausible expected result: zero to a few rows a day naming the principal and the binding added; an empty result is legitimate, not a query failure. Interpretation: the same escalation shape as the AWS/Azure forms, read from GCP's IAM binding-delta record — extend the role list to cover custom roles granting equivalent permissions under a different name.

**[QUERY]** AWS via Google SecOps YARA-L over a UDM permission-update event.

```yaral
rule iam_privilege_escalation_wildcard_or_admin_policy {
  meta:
    description = "Principal attaches or creates a wildcard or admin-equivalent IAM policy"
  events:
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
    $e.metadata.product_event_type = $api_call
    $api_call in %dangerous_iam_calls
    $e.principal.user.userid = $principal
  match:
    $principal over 5m
  outcome:
    $matching_calls = count($e)
  condition:
    $e
}
```

CONCEPTUAL SAMPLE — `%dangerous_iam_calls` assumes a reference list defined elsewhere; parsing the inline `policyDocument` needs a UDM field path this book has not verified, so this rule leans on the event-name list alone, not the document check the other forms carry.

Plausible expected result: a match bound to `$principal` for each qualifying call inside the window. Interpretation: broader and less precise than the KQL/SPL/AQL forms — treat a YARA-L-only hit as a lead to confirm, not escalate on directly.

**[QUERY]** AWS via Elastic KQL, chosen because this is a single-event boolean match rather than an aggregation (per DEH Appendix A5 §8's decision table).

```kql
event.dataset: "aws.cloudtrail" and event.provider: "iam.amazonaws.com"
  and event.action: ("AttachUserPolicy" or "AttachRolePolicy" or "AttachGroupPolicy")
  and aws.cloudtrail.request_parameters: (*AdministratorAccess* or *PowerUserAccess* or *IAMFullAccess*)
```

CONCEPTUAL SAMPLE — field paths depend on your AWS integration version; the wildcard match against `request_parameters` as raw text is fragile against reformatting the same way the QRadar form above is.

Plausible expected result and interpretation: same managed-policy-attach branch as the Sigma form, on a different backend, filterable further by `user.id` in Kibana.

**[FALSE POSITIVE]** Terraform, CloudFormation, and any GitOps-driven IAM pipeline call exactly these APIs as their entire purpose — an allowlist keyed on the exact principal ARN of the deployment role, never a blanket "automation" exclusion an attacker who compromises that same CI/CD credential would also match, per DEH Part 19 §2.1's own False Positive Trap. Azure adds its own version of the gap: a custom RBAC role carrying wildcard `"*"` actions produces no `roleAssignments/write` event at creation time and won't match the built-in-role-GUID check above until it's actually assigned — extend the check to custom role definitions, not just the two GUIDs shown. GCP's `roles/editor` is broader than most teams expect; treat a hit on it with nearly `roles/owner`'s urgency, not as a lesser finding.

**[PIVOT]** Check whether the granting principal already held `iam:PassRole` combined with a resource-launch permission — the Blind Spot below names this as a route invisible to every query above. Check `AddUserToGroup` changes against groups that already carry a wildcard attachment predating this pattern's deployment. If the principal is a federated identity, pull its authentication context from Part 24 first.

> **Blind Spot**
> Every form above sees the grant, never the `iam:PassRole`-plus-launch path DEH Part 19 §2.1 documents as a structurally separate escalation route with no `Attach*Policy` call in it. A rule scoped to attachment and role assignment alone is blind to that path by construction — closing it needs a separate correlation between a `PassRole` call and a compute- or function-launch call from the same principal, not a variant of any query above.

---

### QC-25-02 — Storage bucket or container exposed to public or anonymous access

| Field | Value |
|---|---|
| **Pattern ID** | `QC-25-02` |
| **MITRE** | T1530 (Data from Cloud Storage) — mapped to the consequence this configuration change enables, not the change itself; ATT&CK carries no dedicated technique for the exposure state, per DEH Part 19 §3's own scope note. |
| **Behavior** | A policy, ACL, or IAM-binding change grants public or anonymous read/write access to a storage bucket, blob container, or GCS bucket. |
| **DEH cross-ref** | DEH Part 19 §3, §3.1 (DET-19-02) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** A public bucket rarely gets created by an attacker from nothing — far more often it's a legitimate bucket an attacker with existing access re-opens for staged exfiltration, or an old misconfiguration nobody noticed. Hunt this on a schedule independent of any standing rule: DEH Part 19 §3's own Blind Spot names a gap a policy/ACL-scoped rule can't see — a dormant wildcard grant made live by a later `PublicAccessBlock` change with no `PutBucketPolicy`/`PutBucketAcl` event near it.

**[QUERY]** AWS S3, Sigma rule on an ACL grant to the `AllUsers` predefined group.

```yaml
title: S3 Bucket ACL Grants Public Read or Write Access
id: 3d8c71a2-4f9e-4b06-8a1c-6e2f9d3b7a44
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: PutBucketAcl
    requestParameters.AccessControlPolicy|contains: 'groups/global/AllUsers'
  filter:
    requestParameters.bucketName|in: '%known_public_hosting_buckets%'
  condition: selection and not filter
```

CONCEPTUAL SAMPLE — covers only the ACL-grant branch; a `PutBucketPolicy` granting `"Principal": "*"` needs the document-parsing branch DEH Part 19 §3.1 builds separately, since the two event types encode "public" in structurally different fields.

Plausible expected result: an event naming the bucket and granting principal whenever an ACL adds the `AllUsers` or `AuthenticatedUsers` predefined-group URI. Interpretation: consistent with a bucket becoming reachable by anyone with an AWS account, or literally anyone — read which group matched before treating the two as equally severe.

**[QUERY]** Azure Storage via Sentinel/Defender KQL, an account- or container-level public-access setting change.

```kql
AzureActivity
| where OperationNameValue in (
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE")
| where ActivityStatusValue == "Success"
| extend RequestBody = parse_json(tostring(Properties)).requestbody
| extend PublicAccessLevel = tostring(parse_json(RequestBody).properties.publicAccess),
         AllowsBlobPublic = tobool(parse_json(RequestBody).properties.allowBlobPublicAccess)
| where PublicAccessLevel in ("Container", "Blob") or AllowsBlobPublic == true
| where Caller !in (known_public_hosting_accounts)
| project TimeGenerated, Caller, ResourceId, PublicAccessLevel, AllowsBlobPublic
```

CONCEPTUAL SAMPLE — the nested `requestbody` path is illustrative. Note the two-precondition shape already checked: an account-level `allowBlobPublicAccess=true` is necessary but not sufficient — a container still set to `Private` beneath it isn't yet exposed, which is why the container-level event is checked too.

Plausible expected result: a row whenever either the account-level toggle or a container's public-access level moves to `Container` or `Blob`. Interpretation: same exposure shape as the AWS forms, through Azure's two-layer (account, then container) model — a different precondition structure than S3's single-object ACL or policy.

**[QUERY]** AWS S3 SPL, condensed from DEH Part 19 §3.1's own DET-19-02.

```spl
sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com
    (eventName=PutBucketPolicy OR eventName=PutBucketAcl)
| spath input=requestParameters.bucketPolicy output=policy_doc
| spath input=requestParameters.AccessControlPolicy output=acl_doc
| eval principal_wildcard=if(match(policy_doc, "\"Principal\"\s*:\s*\"\*\"") OR
    match(policy_doc, "\"Principal\"\s*:\s*\{\s*\"AWS\"\s*:\s*(\"\*\"|\[\s*\"\*\"\s*\])"), 1, 0)
| eval grants_public=case(
    eventName="PutBucketPolicy", principal_wildcard=1,
    eventName="PutBucketAcl", if(match(acl_doc, "groups/global/(AllUsers|AuthenticatedUsers)"), 1, 0),
    true(), 0)
| where grants_public=1
| table _time, userIdentity.arn, requestParameters.bucketName, eventName, sourceIPAddress
```

CONCEPTUAL SAMPLE — drops DEH Part 19 §3.1's `Condition`-narrowing check; without it, a policy adding a genuine `aws:SourceIp` restriction alongside `Principal: "*"` still matches here as if fully public.

Plausible expected result and interpretation: unchanged from the Sigma form, covering both the ACL and policy branches this time.

**[QUERY]** GCP Cloud Storage via QRadar AQL (not standard SQL), an IAM-binding change adding `allUsers` or `allAuthenticatedUsers`.

```sql
SELECT "Principal Email", "Resource Name", "Bound Member", "Bound Role"
FROM events
WHERE "Method Name" = 'storage.setIamPermissions'
  AND "Bound Member" IN ('allUsers', 'allAuthenticatedUsers')
LAST 1 DAYS
```

CONCEPTUAL SAMPLE — assumes the same GCP DSM extension as QC-25-01's AQL form.

Plausible expected result: one row per qualifying binding change, `"Bound Member"` distinguishing `allUsers` (anyone, unauthenticated) from `allAuthenticatedUsers` (anyone with a Google account) — a real severity difference, not a formatting detail. Interpretation: the same exposure shape, through GCP's IAM-binding model rather than an ACL or storage-account setting.

**[QUERY]** AWS S3 via Google SecOps YARA-L over a UDM resource-permission-update event.

```yaral
rule s3_bucket_public_exposure {
  meta:
    description = "S3 bucket policy or ACL change grants public/anonymous access"
  events:
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
    $e.metadata.product_event_type = $api_call
    $api_call in %s3_public_exposure_calls
    $e.target.resource.name = $bucket
  match:
    $bucket over 5m
  outcome:
    $matching_calls = count($e)
  condition:
    $e
}
```

CONCEPTUAL SAMPLE — leans on the event-name list rather than parsing the policy/ACL document content, the same simplification QC-25-01's YARA-L form makes; confirm a match against one of the document-parsing forms above before escalating.

Plausible expected result and interpretation: unchanged from the other forms — a bucket-keyed match flagging the exposure event.

**[QUERY]** GCP Cloud Storage via Elastic KQL.

```kql
event.dataset: "gcp.audit" and event.action: "storage.setIamPermissions"
  and gcp.audit.policy_delta.binding_deltas.member: ("allUsers" or "allAuthenticatedUsers")
```

CONCEPTUAL SAMPLE — field path depends on your Elastic GCP integration version.

Plausible expected result and interpretation: same as the AQL form above, on a different backend.

**[FALSE POSITIVE]** A bucket deliberately hosting a static website, a public open dataset, or public release artifacts carries the identical grant this pattern targets — documented and supported, not an edge case, per DEH Part 19 §3.1's own False Positive Trap. The fix is a bucket-name/ARN allowlist for approved public hosting, reviewed on the same cadence as QC-25-01's CI/CD allowlist, never a blanket exclusion for "buckets with a website configuration." Part 20 and this pattern touch T1530-adjacent activity from different angles without duplicating each other: Part 20 covers an object-read-volume spike once data-event logging is enabled (DEH Part 19 §7); this pattern covers the exposure event that makes the bucket reachable at all (DEH Part 19 §3).

**[PIVOT]** Check whether the bucket or container is on the approved public-hosting allowlist before escalating. If not, check for a `GetObject`/blob-read spike immediately following the exposure change — that volume-based query is Part 20's territory, not repeated here, but a hit there sharply raises the stakes. Check the IAM/RBAC history for who currently holds write access to the bucket's own policy.

> **Blind Spot**
> This pattern only sees the moment a policy or ACL adds a public grant. DEH Part 19 §3's own Blind Spot names the gap directly: removing S3 Block Public Access (or its Azure/GCP equivalents) from a resource already carrying a dormant wildcard grant makes it public immediately, with no `PutBucketPolicy`/`PutBucketAcl`-shaped event near the moment it happened. Closing that gap needs a separate check on the public-access-block setting itself, not a variant of any query above.

---

### QC-25-03 — Security group, NSG, or firewall rule opened to the internet on a sensitive port

| Field | Value |
|---|---|
| **Pattern ID** | `QC-25-03` |
| **MITRE** | T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall) |
| **Behavior** | A security group ingress rule, NSG rule, or firewall rule is created or modified to permit `0.0.0.0/0` (or `::/0`) on an administrative, database, or management port. |
| **DEH cross-ref** | DEH Part 19 §4 |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** This catches only the moment of exposure, never a rule already misconfigured before logging began — DEH Part 19 §4 names that limit and points to configuration-snapshot comparison, not an event-stream query, as the way to close it. Run this against a suspect group's full modification history, not just its latest change: a rule opened briefly and never closed is far more common than a single obviously malicious event.

**[QUERY]** AWS EC2, Sigma rule on an ingress rule granting `0.0.0.0/0` on a sensitive port.

```yaml
title: Security Group Ingress Opened to the Internet on a Sensitive Port
id: 9c2a7e14-5b3f-4a1d-8e2c-7f4b1a9d3c56
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_event:
    eventSource: ec2.amazonaws.com
    eventName: AuthorizeSecurityGroupIngress
  selection_world:
    requestParameters.cidrIp: '0.0.0.0/0'
  selection_port:
    requestParameters.fromPort:
      - 22
      - 3389
      - 3306
      - 5432
      - 6379
      - 27017
  condition: selection_event and selection_world and selection_port
```

CONCEPTUAL SAMPLE — sensitive-port list is a starting point; DEH Part 19 §4 also names `ModifySecurityGroupRules` and a wide-range/all-protocol rule as gaps this exact-port-match form doesn't cover — read that section before treating this as complete.

Plausible expected result: an event naming the security group ID, granting principal, and opened port whenever a new rule matches both conditions. Interpretation: consistent with an internet-facing exposure on a port with no legitimate reason to face the internet in most environments — cross-check the allowlist below before escalating.

**[QUERY]** Azure NSG via Sentinel/Defender KQL, a security-rule write permitting a wildcard source.

```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
| where ActivityStatusValue == "Success"
| extend RequestBody = parse_json(tostring(Properties)).requestbody
| extend SourcePrefix = tostring(parse_json(RequestBody).properties.sourceAddressPrefix),
         DestPortRange = tostring(parse_json(RequestBody).properties.destinationPortRange),
         Access = tostring(parse_json(RequestBody).properties.access)
| where Access == "Allow" and SourcePrefix in ("*", "0.0.0.0/0", "Internet")
| where DestPortRange in ("22", "3389", "3306", "5432", "6379", "27017") or DestPortRange == "*"
| project TimeGenerated, Caller, ResourceId, SourcePrefix, DestPortRange
```

CONCEPTUAL SAMPLE — nested path illustrative; validate against your schema. See the Engineering Reality box below before trusting a hit here as necessarily live traffic.

Plausible expected result and interpretation: the same exposure shape as the AWS form, through Azure's separately-prioritized rule-evaluation model, naming the caller, NSG resource ID, and opened port range.

**[QUERY]** AWS EC2 SPL, condensed from DEH Part 19 §4.

```spl
sourcetype=aws:cloudtrail eventSource=ec2.amazonaws.com
    (eventName=AuthorizeSecurityGroupIngress OR eventName=ModifySecurityGroupRules)
| eval rule_json=case(
    eventName="AuthorizeSecurityGroupIngress", spath(_raw, "requestParameters.ipPermissions{}"),
    eventName="ModifySecurityGroupRules", spath(_raw, "requestParameters.SecurityGroupRules{}.SecurityGroupRule"))
| mvexpand rule_json
| eval opened_to_world=if(match(rule_json, "0\.0\.0\.0/0") OR match(rule_json, "::/0"), 1, 0)
| rex field=rule_json "(?i)\"fromPort\"\s*:\s*(?<from_port>-?\d+)"
| rex field=rule_json "(?i)\"toPort\"\s*:\s*(?<to_port>-?\d+)"
| eval sensitive_port=if((from_port<=22 AND to_port>=22) OR (from_port<=3389 AND to_port>=3389) OR
    (from_port<=3306 AND to_port>=3306) OR (from_port<=5432 AND to_port>=5432), 1, 0)
| where opened_to_world=1 AND sensitive_port=1
| table _time, userIdentity.arn, requestParameters.groupId, eventName, from_port, to_port, sourceIPAddress
```

CONCEPTUAL SAMPLE — field paths and nested shapes differ between the two event types, exactly as DEH Part 19 §4 documents; validate both branches against your own ingested schema.

Plausible expected result and interpretation: same shape as the Sigma/KQL forms, covering both the legacy `Authorize*` call and the bulk-edit API DEH Part 19 §4 flags as a common silent gap.

**[QUERY]** GCP firewall rules via QRadar AQL (not standard SQL).

```sql
SELECT "Principal Email", "Firewall Name", "Source Ranges", "Allowed Ports"
FROM events
WHERE "Method Name" IN ('v1.compute.firewalls.insert', 'v1.compute.firewalls.patch')
  AND "Source Ranges" ILIKE '%0.0.0.0/0%'
  AND ("Allowed Ports" ILIKE '%22%' OR "Allowed Ports" ILIKE '%3389%' OR "Allowed Ports" ILIKE '%3306%')
LAST 1 DAYS
```

CONCEPTUAL SAMPLE — assumes the same GCP DSM extension as QC-25-01/QC-25-02's AQL forms; the `ILIKE` substring match on `"Allowed Ports"` is a coarse stand-in for a properly parsed port-range comparison.

Plausible expected result and interpretation: one row per qualifying insert/patch naming the principal and opened range — the same exposure shape, through GCP's VPC firewall model; see the Engineering Reality box for why its confidence level differs from Azure's.

**[QUERY]** AWS via Google SecOps YARA-L over a UDM setting-change event.

```yaral
rule security_group_opened_to_internet {
  meta:
    description = "Security group ingress rule opened to 0.0.0.0/0 on a sensitive port"
  events:
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
    $e.metadata.product_event_type = $api_call
    $api_call in %sg_ingress_calls
    $e.target.resource.name = $group_id
  match:
    $group_id over 5m
  outcome:
    $matching_calls = count($e)
  condition:
    $e
}
```

CONCEPTUAL SAMPLE — UDM's firewall-rule field modeling is not confirmed mature enough here to parse the CIDR/port values directly; this rule matches on the event-name list alone and should be treated as a lead, not a self-sufficient hit.

Plausible expected result and interpretation: unchanged from the other five — a group-keyed match flagging the change event.

**[QUERY]** AWS via Elastic KQL.

```kql
event.dataset: "aws.cloudtrail" and event.provider: "ec2.amazonaws.com"
  and event.action: "AuthorizeSecurityGroupIngress"
  and aws.cloudtrail.request_parameters: (*0.0.0.0/0* and (*"fromPort":22* or *"fromPort":3389* or *"fromPort":3306*))
```

CONCEPTUAL SAMPLE — a raw-text match against `request_parameters`, fragile against reformatting; prefer a properly parsed field path once your integration exposes one.

Plausible expected result and interpretation: same as the Sigma form above.

**[FALSE POSITIVE]** A load balancer's security group or a bastion host explicitly designed for internet-facing access legitimately carries `0.0.0.0/0` on ports this pattern would otherwise flag — maintain an exception list of resource IDs deliberately internet-facing by design, per DEH Part 19 §4's own False Positive Trap, and alert unconditionally on any resource not already on that list. One provider-specific nuance worth a labeled aside: Azure NSGs evaluate rules by priority, so a newly added permissive low-priority rule can be entirely shadowed by an existing higher-priority `Deny` rule and never pass traffic — confirm the NSG's effective evaluation order before treating a KQL hit as live exposure. GCP VPC firewalls carry no equivalent shadowing concept, so a GCP hit is closer to guaranteed-live than an Azure one — see the Engineering Reality box below.

**[PIVOT]** Pull the full modification history for the flagged group or rule, not just the triggering event — a rule opened months ago and never closed is more common than a fresh malicious change, per DEH Part 19 §4's own Hunter's Note. Check flow logs (VPC Flow Logs, NSG Flow Logs, GCP Firewall Rules Logging) for an actual connection on the newly opened port — this pattern only proves the door opened, not that anyone walked through it.

> **Engineering Reality**
> Azure's priority-ordered rule evaluation and GCP's flatter default-deny model mean the same "0.0.0.0/0 on port 22" finding carries different confidence by provider. On AWS, a matching rule is unconditionally live the moment it's created — no shadowing concept exists. On Azure, always check whether a lower-priority-number Deny rule already blocks the traffic before treating a KQL hit as confirmed exposure. GCP sits close to AWS's confidence level. Don't apply one confidence read across all three query forms above.

---

### QC-25-04 — Control-plane discovery burst from a single principal

| Field | Value |
|---|---|
| **Pattern ID** | `QC-25-04` |
| **MITRE** | T1580 (Cloud Infrastructure Discovery) |
| **Behavior** | One principal issues an unusually high count of distinct read-only (`List`/`Describe`/`Get`-shaped) control-plane API operations within a short window. |
| **DEH cross-ref** | DEH Part 19 §1 (control-plane logging architecture), §8 (case study, Hour 0–1 discovery beat) |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (ES\|QL) |

**[HUNTER]** DEH Part 19 §8's case study opens with exactly this shape: `ListUsers`, `GetUser`, `ListAttachedUserPolicies`, and `ListRoles` called in quick succession from a source the compromised principal never used before — individually unremarkable calls that only look like an attack in aggregate. A per-call rule can express "unusual call," never "unusual breadth"; this pattern's distinct-operation-count aggregation is the shape a hunt reaches for instead.

**[QUERY]** AWS CloudTrail, Sigma correlation over a base read-only selection.

```yaml
title: Cloud Control-Plane Discovery Burst - Single Principal
correlation:
  type: value_count
  rules:
    - cloudtrail_readonly_call
  group-by:
    - userIdentity.arn
  timespan: 1h
  condition:
    field: eventName
    gte: 20
---
title: CloudTrail Read-Only API Call
id: cloudtrail_readonly_call
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName|startswith:
      - 'List'
      - 'Describe'
      - 'Get'
  condition: selection
```

CONCEPTUAL SAMPLE — threshold illustrative; validate `value_count` support against your Sigma backend, and confirm the `startswith` prefix list against your actual API-call inventory before deploying.

Plausible expected result: a principal with 20 or more distinct `eventName` values inside a single hour, almost entirely read-only. Interpretation: consistent with automated enumeration tooling (Pacu, ScoutSuite) or a compromised credential post-theft — not evidence of any downstream action yet.

**[QUERY]** Azure Activity Log via Sentinel/Defender KQL.

```kql
AzureActivity
| where OperationNameValue matches regex @"(?i)(LIST|READ|GET)$"
| summarize DistinctOps = dcount(OperationNameValue), Ops = make_set(OperationNameValue, 30)
      by Caller, bin(TimeGenerated, 1h)
| where DistinctOps >= 20
```

CONCEPTUAL SAMPLE — the regex suffix match against `OperationNameValue` is a coarse approximation of "read-only"; validate it against your own tenant's actual operation-name vocabulary.

Plausible expected result and interpretation: a handful of `Caller` values a day at most in a well-segmented tenant, each with a populated `Ops` set worth pivoting into — the same breadth-of-enumeration signal as the AWS form.

**[QUERY]** AWS CloudTrail SPL.

```spl
index=aws_cloudtrail (eventName=List* OR eventName=Describe* OR eventName=Get*)
| bin _time span=1h
| stats dc(eventName) as distinct_ops, values(eventName) as ops by userIdentity.arn, _time
| where distinct_ops >= 20
```

CONCEPTUAL SAMPLE — same threshold caveat as the Sigma form; raise `maxvalues` on `stats` if a wide campaign truncates the `ops` field.

Plausible expected result and interpretation: unchanged from the KQL form.

**[QUERY]** GCP Cloud Audit Logs via QRadar AQL (not standard SQL).

```sql
SELECT "Principal Email", UNIQUECOUNT("Method Name") AS distinct_ops
FROM events
WHERE "Method Name" ILIKE '%.list%' OR "Method Name" ILIKE '%.get%'
GROUP BY "Principal Email"
HAVING UNIQUECOUNT("Method Name") >= 20
LAST 1 HOURS
```

CONCEPTUAL SAMPLE — `UNIQUECOUNT()` is AQL's distinct-count function, not SQL's `COUNT(DISTINCT)`; confirm the DSM extension actually maps `"Method Name"` as a queryable field before trusting a zero-result run as clean.

Plausible expected result and interpretation: one row per offending principal within the rolling window — the same recurrence signal as the other surfaces, since GCP's Admin Activity logs are always on and free, per DEH Part 19 §1.

**[QUERY]** AWS via Google SecOps YARA-L.

```yaral
rule cloud_discovery_burst {
  meta:
    description = "Single principal produces an unusually broad set of read-only API calls"
  events:
    $e.metadata.event_type = "GENERIC_EVENT"
    $e.metadata.product_event_type = $api_call
    $api_call = /^(List|Describe|Get)/ nocase
    $e.principal.user.userid = $principal
  match:
    $principal over 1h
  outcome:
    $distinct_ops = count_distinct($api_call)
  condition:
    $e and count_distinct($api_call) >= 20
}
```

CONCEPTUAL SAMPLE — UDM field paths illustrative; confirm `metadata.product_event_type` carries the raw API operation name for your CloudTrail ingestion path.

Plausible expected result and interpretation: unchanged from the other surfaces.

**[QUERY]** AWS via Elastic ES\|QL, chosen because this is a threshold shape rather than an ordered sequence (per DEH Appendix A5 §8's decision table).

```esql
FROM logs-aws.cloudtrail-*
| WHERE event.action LIKE "List*" OR event.action LIKE "Describe*" OR event.action LIKE "Get*"
| STATS distinct_ops = COUNT_DISTINCT(event.action) BY aws.cloudtrail.user_identity.arn, BUCKET(@timestamp, 1h)
| WHERE distinct_ops >= 20
```

CONCEPTUAL SAMPLE — field path depends on your Elastic AWS integration version.

Plausible expected result and interpretation: unchanged from the other five surfaces.

**[FALSE POSITIVE]** A `terraform plan` run, a CSPM tool's asset-inventory scan, or the security team's own Prowler/ScoutSuite audit produce a near-identical enumeration burst with no attacker involved — the shape alone doesn't distinguish offense from defense. Allowlist known CI/CD and scanner principal ARNs explicitly, and weight source IP/ASN and first-time-seen status (the same novelty framing DEH Part 19 §6.1 uses for `AssumeRole`, cited rather than restated) more heavily than the raw count. Azure Resource Graph dashboards and GCP Security Command Center's own asset scans produce equivalent legitimate noise on their platforms.

**[PIVOT]** Check the flagged principal's call list for anything beyond read-only — a single write call inside an otherwise read-only burst is the highest-value next step. Check whether the credential is long-lived and recently created, which points toward Part 26 if a subsequent `AssumeRole` or credential-creation event follows. Check this book's Part 15 for a matching on-prem enumeration pattern if the identity has on-prem footprint too.

> **Hunter's Note**
> AWS's `eventName`, Azure's `OperationNameValue`, and GCP's `methodName` are three different vocabularies with different casing and verb-placement conventions — no single normalized field lets this threshold be written once across all three providers. Don't assume a KQL query written for Azure will "just work" against an AWS CloudTrail table with a find-and-replace on the field name.

---

### QC-25-05 — Mass compute-resource creation across regions consistent with resource hijacking

| Field | Value |
|---|---|
| **Pattern ID** | `QC-25-05` |
| **MITRE** | T1496.001 (Resource Hijacking: Compute Hijacking) |
| **Behavior** | A single principal creates a burst of compute instances across several regions it has never used before, within a short window. |
| **DEH cross-ref** | DEH Part 19 §1 (control-plane logging architecture); no DEH Part 19 worked detection targets this exact behavior — this pattern extends beyond DEH's own worked-example set rather than adapting a specific `DET-19-##`. |
| **Languages covered** | Sigma — `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar) — `N/A`, see below; YARA-L — `N/A`, see below; Elastic (ES\|QL) |

**[HUNTER]** A credential hijacked for cryptomining rarely stays in the account's usual region — the attacker wants capacity fast, wherever it's available. A raw instance-count threshold can't distinguish that from a legitimate autoscaling burst; what separates the two is whether the regions themselves are new for that principal, which needs a historical baseline compared against the current burst — a two-stage shape, not a single aggregation.

**[QUERY] — Sigma.** `N/A` — aggregation ceiling. This pattern needs two aggregation stages — a 30-day per-principal region baseline, then a current-window comparison against it — which Sigma's `value_count`/`event_count` correlation types cannot express in one rule, the same structural gap DEH Appendix A5 §4 documents and this book's own `QC-05-04` (Part 5) already relies on for an identical two-stage shape.

**[QUERY]** Azure via Sentinel/Defender KQL, comparing a 1-hour burst against a 30-day per-caller region baseline.

```kql
let Baseline = AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE" and ActivityStatusValue == "Success"
| where TimeGenerated between (ago(31d) .. ago(1h))
| summarize KnownRegions = make_set(Location) by Caller;
AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE" and ActivityStatusValue == "Success"
| where TimeGenerated > ago(1h)
| lookup kind=leftouter Baseline on Caller
| extend IsNewRegion = Location !in (KnownRegions)
| where IsNewRegion
| summarize NewRegionCount = dcount(Location), VmCount = count() by Caller
| where NewRegionCount >= 3 and VmCount >= 10
```

CONCEPTUAL SAMPLE — thresholds (3 new regions, 10 instances) are illustrative; validate against your own baseline, and confirm `Location` is populated on your `AzureActivity` records.

Plausible expected result: a small number of `Caller` values, each with three or more regions never used in the trailing 30 days and ten or more VM-creation calls in the same hour. Interpretation: consistent with a hijacked credential provisioning capacity outside its normal footprint — check instance type before treating this as confirmed cryptomining.

**[QUERY]** AWS via SPL, using a separately maintained lookup for the 30-day region baseline.

```spl
index=aws_cloudtrail eventName=RunInstances earliest=-1h
| lookup known_regions_by_principal_lookup principal_arn AS userIdentity.arn OUTPUT known_regions
| eval is_new_region=if(known_regions=="" OR NOT match(known_regions, awsRegion), 1, 0)
| where is_new_region=1
| stats count as vm_count, dc(awsRegion) as new_region_count by userIdentity.arn
| where new_region_count >= 3 AND vm_count >= 10
```

CONCEPTUAL SAMPLE — `known_regions_by_principal_lookup` assumes a scheduled search materializes each principal's 30-day region history into that lookup daily; build that search first, the same "saved search feeds a lookup" architecture `QC-05-05` (Part 5) uses.

Plausible expected result and interpretation: unchanged from the KQL form above.

**[QUERY] — AQL (QRadar).** `N/A` — aggregation ceiling. AQL's `SELECT` has no subquery or common-table-expression stage to feed a 30-day baseline's output into a second `GROUP BY` over the current hour's burst, the same gap this book's `QC-05-04` (Part 5) documents for AQL. A standing QRadar detection for this behavior would need a Reference Set populated daily with each principal's historical regions, tested by a separate Rule against new `RunInstances` events (DEH Part 27 §2's Building Block model) rather than one AQL statement.

**[QUERY] — YARA-L (Google SecOps).** `N/A` — aggregation ceiling. YARA-L's `outcome` section aggregates over one matched event window; it has no equivalent to a second pass that re-aggregates a separately computed historical baseline, the same structural gap named for AQL and Sigma above.

**[QUERY]** GCP Compute Engine via Elastic ES\|QL, chosen because this is a wide-lookback aggregation shape (per DEH Appendix A5 §8's decision table), using an enrich policy for the region baseline.

```esql
FROM logs-gcp.audit-*
| WHERE event.action == "v1.compute.instances.insert" AND event.outcome == "success"
| WHERE @timestamp > NOW() - 1 hour
| ENRICH known_regions_by_principal ON principal.email
| WHERE NOT MV_CONTAINS(known_regions, cloud.region)
| STATS new_region_count = COUNT_DISTINCT(cloud.region), vm_count = COUNT(*) BY principal.email
| WHERE new_region_count >= 3 AND vm_count >= 10
```

CONCEPTUAL SAMPLE — the `known_regions_by_principal` enrich policy assumes a separately maintained 30-day region index, the same architecture as the SPL lookup above; ES\|QL's `ENRICH` needs that policy built ahead of time, not computed inline, per `QC-05-03` (Part 5).

Plausible expected result and interpretation: unchanged from the KQL/SPL forms, read from GCP's insert calls.

**[FALSE POSITIVE]** A legitimate autoscaling group, a blue/green deployment, a disaster-recovery failover drill, or a genuine new-region product launch all produce an identical burst with no attacker involved — resolve these as documented negatives against a known change ticket, the same discipline DEH Part 19 §6.1's `HUNT-19-02` applies to dormant-credential reactivation, rather than tuning the thresholds down until real abuse stops firing too. The strongest secondary signal specific to resource-hijacking abuse is instance-type selection: legitimate autoscaling rarely reaches for the GPU-heavy or highest-vCPU families cryptomining favors, so new-region breadth paired with an unusual instance-type profile is a stronger finding than either signal alone.

**[PIVOT]** Check the specific instance types requested — GPU or high-vCPU instances are a stronger tell than region count alone. Check billing or cost-anomaly signals if your provider exposes them; a sudden compute-spend spike corroborates independently of any log query. Check whether the same principal produced a QC-25-01 or QC-25-04 hit beforehand — that combination is stronger than the creation burst alone.

> **What Would Change My Mind**
> This pattern assumes a principal's 30-day region history is stable enough that a burst of genuinely new regions is rare and worth a hunter's time. If a production review showed a given account's workloads routinely expand into new regions as ordinary, unremarkable scaling, the "never used this region before" framing would produce too many benign hits to be worth the review cost, and this pattern would need to shift its primary signal to the instance-type profile named above.

## Cross-references

DEH Part 19 (Cloud Infrastructure Detection Engineering) §1 (control-plane logging architecture, delivery-lag caveats), §2/§2.1 (`QC-25-01`), §3/§3.1 (`QC-25-02`), §4 (`QC-25-03`), and §8's case study (`QC-25-04`); DEH Appendix A5 §4 and §8 for the aggregation-ceiling and Elastic-surface-selection reasoning cited throughout, including `QC-25-05`'s three-language `N/A`; DEH Part 27 §2–§3 for the Building Block/Reference Set model named wherever AQL is marked `N/A`; DEH Parts 41–43 for the coverage/quality/debt tiers this part's `[SOC MANAGEMENT]` note assumes. This book's Part 5 for the `QC-05-04`/`QC-05-05` two-stage and lookup-fed shapes `QC-25-05` and `QC-25-02` build on; Part 14 for the log-tampering behavior class with no cloud-native counterpart yet, named as an explicit gap; Part 15 for the on-prem discovery counterpart to `QC-25-04`; Part 20 for mass object-level access and exfiltration from cloud data stores (DEH Part 19 §7), cited but not duplicated by `QC-25-02`; Part 24 for the identity-provider/SaaS layer this part's activity sits on top of; and Part 26 for credential usage, assumed-role chaining, and instance-metadata-service theft (DEH Part 19 §6), out of scope here.
