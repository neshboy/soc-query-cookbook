---
title: "Cloud-Native Lateral Movement & Privilege Escalation"
part: 26
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-15"
depends_on: []
---

# Part 26 — Cloud-Native Lateral Movement & Privilege Escalation

## Why this part exists

**[CONCEPT]** Part 25 covers a single account's own IAM policy abuse, storage/network exposure, and control-plane API volume — one identity, one account, one blast radius. This part starts where that stops: a principal moving *between* trust boundaries — assuming a chain of roles that crosses account lines, harvesting a temporary credential off a compromised workload's instance metadata service, or riding a role's trust policy into an account it was never supposed to reach. The query shape differs genuinely, not just in scale: a chain-walk or theft-then-reuse join needs multi-event correlation on a session identity that doesn't exist until the first event produces it, where Part 25's patterns are mostly single-event checks.

Three boundaries against neighboring parts:

- **Part 24 (Cloud Identity & SaaS Abuse)** owns the identity-provider layer — OAuth/app-consent grants, conditional-access bypass, federated sign-in. Where a chain here steps out to a federated IdP mid-hop, QC-26-01 names that as a blind spot rather than absorbing Part 24's telemetry.
- **Part 25 (Cloud Infrastructure Abuse)** owns single-account IAM abuse and escalation. QC-26-05 is the assumed-role-chained *variant* of DEH Part 19 §2's escalation analytic, extended across a session boundary Part 25 doesn't cross — not a restatement of its query.
- **This book's Part 7 vs. Part 17 theft-vs-use split** has a direct cloud analog: QC-26-02 is the theft of a credential off a compromised instance; QC-26-03 is its reuse from somewhere the instance never was — separate patterns for the same reason Part 7/17 are separate parts.

> **Detection Autopsy — "any cross-account AssumeRole is a finding"**
>
> **The rule:** Alert whenever `userIdentity.accountId` differs from `recipientAccountId` on an `sts:AssumeRole` CloudTrail record.
>
> **Why it shipped:** Cross-account access is the textbook lateral-movement signal, and it needs no policy-document parsing or session-key correlation — just two account-ID fields on one event.
>
> **How it failed:** A landing zone with a shared logging account, a shared CI/CD account, and per-environment spoke accounts produces this shape hundreds of times an hour, by design — the rule fired constantly against its own architecture, with no way to tell a deployment pipeline from a real pivot without opening every event by hand.
>
> **The fix:** Group by the (source role, destination role) pair instead of the account-ID mismatch alone, and alert only on a pair never seen in the trailing baseline — the known-pair allowlist discipline every pattern below builds around.

**[SOC MANAGEMENT]** QC-26-02 and QC-26-04 tune reasonably well into standing rules once their allowlists stabilize — both are rare, high-signal events. QC-26-01 and QC-26-05's chain-walk and session-join logic are a different story: several languages can't express either as one standing artifact (see the `N/A` entries below), and a scheduled hunt — hourly or per-shift, not continuous — is the more realistic cadence, matching DEH Part 43's cost framing for detection debt. QC-26-03 sits in between: cheap enough to run standing once its allowlist gets the same active maintenance as QC-26-02's.

## Query patterns

### QC-26-01 — Multi-hop assumed-role chain crossing account boundaries

| Field | Value |
|---|---|
| **Pattern ID** | `QC-26-01` |
| **MITRE** | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Behavior** | A principal's `sts:AssumeRole` chain crosses two or more AWS account boundaries within a short window, with `sourceIdentity` absent by the second hop, obscuring which human or service actually started the chain. |
| **DEH cross-ref** | DEH Part 19 §6 (assumed-role chains) and its Blind Spot on `sourceIdentity`; §6.1 (`HUNT-19-01`, anomalous `AssumeRole` usage), extended here from one hop to a walked chain; cf. DEH Part 23 §3's translation-loss framework behind this pattern's `N/A` entries. |
| **Languages covered** | Sigma — `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar, investigative form only — see below); YARA-L — `N/A`, see below; Elastic (ES\|QL) |

**[HUNTER]** A single `AssumeRole` event is completely ordinary — cross-account delegation is how a mature landing zone and any CI/CD pipeline work by design, the reason DEH Part 19 §6.1's own hunt frames this as a novelty problem, not a threshold one. What a per-event rule can't see is depth: the same session chaining through several roles in quick succession, landing in an account with no documented trust relationship to where it started. Walking the chain hop by hop, instead of scoring each call independently, is the only way to see the whole traversal.

**[QUERY]** *Sigma — `N/A` — structurally poor fit.* Sigma's `temporal_ordered` correlation type can express "event A, then event B, within a window," already a narrow-backend-support construct per this book's own `QC-05-05`. Walking a chain three or more hops deep needs something stronger: each hop's matching value is the *previous* hop's own response field (the assumed-role ARN), not a fixed field name shared across every hop. No Sigma correlation construct expresses a join key that changes identity between steps.

**[QUERY]** Sentinel/Defender KQL against `AWSCloudTrail`, self-joining `AssumeRole` events on the assumed-role ARN produced by the first hop.

```kql
let Window = 6h;
let Hops = AWSCloudTrail
| where TimeGenerated > ago(Window)
| where EventName == "AssumeRole"
| extend CallerArn = tostring(UserIdentityArn),
         CallerAccount = tostring(UserIdentityAccountId),
         AssumedRoleArn = tostring(parse_json(ResponseElements).AssumedRoleUser.Arn),
         SourceIdentity = tostring(parse_json(RequestParameters).SourceIdentity)
| project TimeGenerated, CallerArn, CallerAccount, AssumedRoleArn, RecipientAccountId, SourceIdentity;
Hops
| join kind=inner (Hops | project NextTime = TimeGenerated, NextCallerArn = CallerArn, NextAccount = RecipientAccountId)
    on $left.AssumedRoleArn == $right.NextCallerArn
| where NextTime between (TimeGenerated .. TimeGenerated + Window)
| where CallerAccount != NextAccount
| project TimeGenerated, CallerArn, AssumedRoleArn, NextAccount, SourceIdentity
```

CONCEPTUAL SAMPLE — field paths assume a common AWS-connector JSON shape; validate against your schema. The join reconstructs one hop-pair at a time; a third hop needs another self-join chained the same way.

Plausible expected result: a small number of rows where an assumed role from one hop immediately became the caller of a second `AssumeRole` landing in a different account, with `SourceIdentity` null. Interpretation: consistent with a chain crossing an account boundary with the original identity already lost — treat a null `SourceIdentity` two hops deep as expected, not a data-quality problem, per DEH Part 19 §6's own Blind Spot.

**[QUERY]** Splunk SPL against a CloudTrail index, same self-join shape.

```spl
index=aws_cloudtrail eventName=AssumeRole earliest=-6h
| eval assumed_role_arn=json_extract(responseElements, "AssumedRoleUser.Arn")
| eval source_identity=json_extract(requestParameters, "SourceIdentity")
| join type=inner assumed_role_arn
    [ search index=aws_cloudtrail eventName=AssumeRole earliest=-6h
      | eval assumed_role_arn=userIdentity.arn
      | eval next_account=recipientAccountId
      | rename _time as next_time ]
| where next_time > _time AND next_time < _time + 21600
| where userIdentity.accountId != next_account
| table _time, userIdentity.arn, assumed_role_arn, next_account, source_identity
```

CONCEPTUAL SAMPLE — SPL's `join` drops unmatched left-side rows by default; a single-hop `AssumeRole` with no second hop correctly disappears here, which is intended, not a bug.

Plausible expected result and interpretation: unchanged from the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL) — investigative form only, pulling every `AssumeRole` event touching a role ARN already suspected mid-chain for an analyst to walk by hand. A standing detection needs a Reference Set accumulating each hop's ARN for a second Rule to test membership against (DEH Part 27 §2–§3's Building Block/Reference Set/Rule model), not one statement.

```sql
SELECT starttime, "user identity arn" AS caller_arn, "assumed role arn", "recipient account id"
FROM events
WHERE qidname = 'AssumeRole'
  AND ("user identity arn" = 'arn:aws:iam::111111111111:role/deploy-role'
       OR "assumed role arn" = 'arn:aws:iam::111111111111:role/deploy-role')
LAST 6 HOURS
ORDER BY starttime ASC
```

CONCEPTUAL SAMPLE — the role ARN is a placeholder pasted in from whatever earlier signal made you suspect this role is mid-chain; the custom property names assume a CloudTrail DSM extension already maps `assumed role arn` and `recipient account id`.

Plausible expected result: an ordered list of every `AssumeRole` call the named role made or was the target of over six hours — typically a handful of rows even on an active role. Interpretation: reading it top to bottom is the manual version of the KQL/SPL self-join above; a role that both receives and immediately re-issues an `AssumeRole` call to a different account is exactly what this hunt surfaces.

**[QUERY]** *YARA-L — `N/A` — missing schema field.* No confirmed UDM field carries AWS STS's `sourceIdentity` value or a durable role-session-chain-depth counter. Without one, a YARA-L rule can match a single `AssumeRole`-shaped event but cannot distinguish hop one of a chain from hop three — the exact depth signal this pattern depends on — the same class of gap DEH Part 28 §1.1 documents for `GrantedAccess`.

**[QUERY]** Elastic ES\|QL, chosen over EQL because a changing join key across hops (the assumed-role ARN one event produces becomes the next event's caller ARN) is a self-referential lookup shape EQL's fixed-field `sequence by` cannot express, where ES\|QL's `LOOKUP JOIN` can (per DEH Appendix A5 §8's decision table).

```esql
FROM logs-aws.cloudtrail-*
| WHERE event.action == "AssumeRole" AND event.outcome == "success"
| EVAL assumed_role_arn = aws.cloudtrail.response_elements.assumed_role_user.arn,
       caller_arn = aws.cloudtrail.user_identity.arn,
       source_identity = aws.cloudtrail.request_parameters.source_identity,
       recipient_account = aws.cloudtrail.recipient_account_id
| LOOKUP JOIN aws_assume_role_hops ON assumed_role_arn
| WHERE recipient_account != next_recipient_account
| KEEP @timestamp, caller_arn, assumed_role_arn, next_recipient_account, source_identity
```

CONCEPTUAL SAMPLE — `LOOKUP JOIN` against `aws_assume_role_hops` assumes a maintained lookup index of recent hops already exists; building and refreshing it is a real prerequisite this query doesn't supply.

Plausible expected result and interpretation: unchanged from the KQL/SPL forms above.

**[FALSE POSITIVE]** A landing zone with a shared logging account, a shared CI/CD account, and per-environment spoke accounts produces this exact multi-hop shape as routine automation — a Terraform Cloud runner assuming a deploy role that itself assumes a per-environment role is indistinguishable in raw shape from an attacker doing the same. The signal isn't "a chain exists," it's "this (role, next-role) pair has never occurred before" — maintain an allowlist of expected hop-pairs from the org's documented design, not a hop-count threshold an attacker would trivially clear.

**[PIVOT]** Check whether `sourceIdentity` (or Azure/GCP's equivalent, where populated) survived to the final hop; if not, walk backward through each role's CloudTrail history to find the earliest human or service principal. Cross-check the terminal account against `QC-26-04`'s trust-policy change history — a chain landing somewhere new is far more concerning if that destination's trust policy was also recently modified.

> **Blind Spot**
> This pattern only walks a chain as far as CloudTrail can see. A chain that steps out to a federated IdP mid-way — a human authenticates to an IdP, which federates into AWS via `AssumeRoleWithSAML`, then assumes a second role — resets the visible starting point to the federated role, not the human, unless the IdP's own sign-in log is joined in separately (this book's Part 24, not this part's). CloudTrail alone reads a federated chain as shorter and more anonymous than it actually is.

---

### QC-26-02 — Instance-metadata-service credential theft via SSRF

| Field | Value |
|---|---|
| **Pattern ID** | `QC-26-02` |
| **MITRE** | T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) |
| **Behavior** | A process outside an approved allowlist — commonly a web-app or app-server worker — queries the instance metadata service's IAM credential path, consistent with SSRF harvesting an instance role's temporary credentials. |
| **DEH cross-ref** | DEH Part 19 §6 (instance metadata theft) and its Engineering Reality box on IMDSv2 enforcement gaps. |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** Metadata credential theft rarely looks like an exploit in the telemetry — it looks like an ordinary process making an ordinary-shaped HTTP request to a link-local address every instance can already reach. The hunt reaches for the IMDS credential path and IMDSv1's token-free request shape as the discriminator, since that combination turns routine metadata polling into a plausible credential grab, and the calling process is nearly always something with an internet-facing attack surface.

**[QUERY]** Sigma against a host-based `network_connection` log (a firewall/EDR network log, not raw VPC Flow Logs, which carry no process attribution).

```yaml
title: Process Queries IMDS Credential Path Outside Known Agents
id: 8c2a5f31-9b4e-4a2d-8e77-1f6b9d3c4a02
status: experimental
logsource:
  category: network_connection
  product: linux
detection:
  selection:
    DestinationIp: '169.254.169.254'
    DestinationPort: 80
  path_selection:
    HttpPath|contains: '/latest/meta-data/iam/security-credentials/'
  filter_known_agents:
    Image|endswith:
      - '/aws-cli'
      - '/amazon-ssm-agent'
      - '/aws-sdk-go'
  condition: selection and path_selection and not filter_known_agents
```

CONCEPTUAL SAMPLE — `HttpPath` assumes an HTTP-aware network log (an L7 proxy or host-based IMDS-call logger); a plain flow-log source will never surface it.

Plausible expected result: a handful of matches naming a process outside the allowlist — often a web-server or application-runtime binary — connecting to 169.254.169.254 on port 80 with the credentials path in the request. Interpretation: consistent with that process, or something injected into it, retrieving the role's temporary credentials directly; IMDSv1-enabled instances need no session token at all, worth flagging independent of the path matched.

**[QUERY]** Sentinel/Defender KQL against `DeviceNetworkEvents` (Defender for Endpoint/Servers agent on the instance).

```kql
DeviceNetworkEvents
| where RemoteIP == "169.254.169.254" and RemotePort == 80
| where InitiatingProcessFileName !in~ ("aws-cli", "amazon-ssm-agent", "aws-sdk-go", "systemd")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP
```

CONCEPTUAL SAMPLE — `DeviceNetworkEvents` doesn't capture the HTTP request path itself; this catches the connection, not confirmation the credentials path was requested. Pair with proxy or application logs where available.

Plausible expected result: a small number of rows per day at most on an instrumented fleet, each naming a process outside the known-agent list. Interpretation: weaker than the path-aware Sigma form since it can't confirm the exact URL requested — a lead to corroborate, not confirmed credential retrieval on its own.

**[QUERY]** Splunk SPL against a host-based network or EDR log source joined to flow data.

```spl
index=vpc_flow_logs OR index=host_firewall dest_ip="169.254.169.254" dest_port=80
| where NOT match(process_name, "aws-cli|amazon-ssm-agent|aws-sdk-go")
| table _time, host, process_name, src_ip, dest_ip
```

CONCEPTUAL SAMPLE — VPC Flow Logs carry no process attribution at all; `process_name` assumes a host-based source joined in, since raw flow logs only confirm an instance — not a process — reached that destination.

Plausible expected result: the same shape as the KQL form, with process attribution present only where a host-level source supplies it. Interpretation: a flow-logs-only environment can confirm the instance reached IMDS but not attribute it to a process — state that gap explicitly in any finding built from flow logs alone.

**[QUERY]** QRadar AQL (not standard SQL), assuming a host-based network or EDR source already mapped with a process-name custom property.

```sql
SELECT starttime, sourceip, "process name", destinationip, destinationport
FROM events
WHERE destinationip = '169.254.169.254' AND destinationport = 80
  AND "process name" NOT IN ('aws-cli','amazon-ssm-agent','aws-sdk-go')
LAST 24 HOURS
```

CONCEPTUAL SAMPLE — the destination IP/port match and the process-name custom property are illustrative; confirm the property is actually mapped in your DSM extension before relying on it.

Plausible expected result: the same shape as above, contingent on whether the process-name custom property is actually populated for your ingested log source. Interpretation: an empty result on a deployment ingesting only flow data most likely means the field mapping doesn't exist yet, not that the behavior didn't happen.

**[QUERY]** Google SecOps YARA-L over UDM `NETWORK_CONNECTION` events.

```yaral
rule imds_credential_path_unallowlisted_process {
  meta:
    description = "Process outside known agent allowlist connects to IMDS on the credential port"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.target.ip = "169.254.169.254"
    $e.target.port = 80
    $e.principal.process.file.full_path = $proc
    not $proc = /(aws-cli|amazon-ssm-agent|aws-sdk-go)$/ nocase
  condition:
    $e
}
```

CONCEPTUAL SAMPLE — UDM's `NETWORK_CONNECTION` event doesn't natively carry the requested HTTP path either; like the KQL form, this confirms the connection, not the specific credentials-path request.

Plausible expected result and interpretation: same caveats as the KQL/SPL forms — a lead worth corroborating with application-layer logs, not confirmed theft on its own.

**[QUERY]** Elastic KQL, chosen because this is a single-event boolean match with no correlation or aggregation stage (per DEH Appendix A5 §8's decision table).

```kql
destination.ip: "169.254.169.254" and destination.port: 80 and not process.name: ("aws-cli" or "amazon-ssm-agent" or "aws-sdk-go")
```

CONCEPTUAL SAMPLE — the destination IP/port match and known-agent exclusion list are illustrative; validate the list against your own fleet's actual SDK/agent binaries.

Plausible expected result: a filtered event list, one row per qualifying connection. Interpretation: unchanged from the other five surfaces.

**[FALSE POSITIVE]** Legitimate SDK/agent processes — the AWS CLI, the SSM agent, an application using the instance profile through the SDK's own credential chain — query this exact path routinely; the discriminator is the calling process's identity, not the destination. A newly deployed application, a container sidecar refreshing credentials, or a security scanner run from inside the instance can also trigger this. Allowlist by process path or hash, and treat a hit from a web-server worker, or anything spawned by one, as high priority regardless of allowlist maturity — that's the SSRF-shaped source this pattern exists to catch.

**[PIVOT]** Check application or WAF logs at the same timestamp for an SSRF-shaped request — a parameter containing an internal URL or `169.254.169.254`. Check CloudTrail for a subsequent call using the same role's credentials from a source IP other than the instance's own — exactly `QC-26-03`'s pattern, commonly chained in a real incident.

---

### QC-26-03 — Stolen instance-role credentials used from outside the instance's network context

| Field | Value |
|---|---|
| **Pattern ID** | `QC-26-03` |
| **MITRE** | T1550.001 (Use Alternate Authentication Material: Application Access Token) |
| **Behavior** | A temporary credential minted for an EC2/GCE/Azure VM instance role authenticates to the cloud control plane from a source IP outside that instance's known VPC egress range, or with a user-agent inconsistent with the SDK actually installed on that instance, consistent with the credential having been exfiltrated and reused elsewhere. |
| **DEH cross-ref** | DEH Part 19 §6 (Engineering Reality on IMDSv2 gaps) and §1 (`sourceIPAddress` reliability). |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** `QC-26-02` catches the theft, at the instance, in the act. This pattern catches the payoff, at the control plane, after the fact — a real share of instance-role credential theft happens through a channel host telemetry never observes (a copied credentials file, a crash dump). A "used from somewhere it has no business being" check has to stand on its own, not depend on `QC-26-02` having already fired.

**[QUERY]** Sigma against CloudTrail, excluding known egress ranges from a broad `AssumedRole` selection.

```yaml
title: EC2 Instance Role Credential Used Outside Known VPC Egress Range
id: 4d7e1a29-3c6f-4b81-9a5e-2d8c7f1e6b03
status: experimental
logsource:
  category: cloud
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: 'AssumedRole'
    userIdentity.sessionContext.sessionIssuer.type: 'Role'
  exclusion:
    sourceIPAddress|cidr:
      - '203.0.113.0/24'
  condition: selection and not exclusion
```

CONCEPTUAL SAMPLE — the excluded CIDR range is illustrative and must be your account's actual NAT gateway/egress ranges; this works cleanly for a small, stable egress footprint and needs a maintained, per-AZ range list on a larger fleet.

Plausible expected result: a small number of API calls per day, each showing an `AssumedRole` session tied to an instance-profile role, from a source IP outside the excluded egress ranges. Interpretation: consistent with the instance role's temporary credential being used from somewhere other than the instance's own network path — a legitimate workload has no ordinary reason to call AWS APIs from outside its own egress range.

**[QUERY]** Sentinel/Defender KQL against `AWSCloudTrail`.

```kql
AWSCloudTrail
| where UserIdentityType == "AssumedRole"
| extend RoleArn = tostring(UserIdentitySessionContext.sessionIssuer.arn)
| where RoleArn has "instance-role"
| where not(ipv4_is_in_range(SourceIpAddress, "203.0.113.0/24"))
| project TimeGenerated, RoleArn, SourceIpAddress, EventName, UserAgent
```

CONCEPTUAL SAMPLE — the instance-profile-role naming filter and egress CIDR are both illustrative; validate the naming convention against your own standard.

Plausible expected result: rows naming a specific instance-profile role and a source IP well outside the excluded range. Interpretation: a stronger version also checks `UserAgent` for a value inconsistent with the SDK/CLI version installed on that fleet, since a replayed credential often carries a telltale user-agent string.

**[QUERY]** Splunk SPL against a CloudTrail index.

```spl
index=aws_cloudtrail userIdentity.type=AssumedRole
| where match(userIdentity.sessionContext.sessionIssuer.arn, "instance-role")
| eval in_range=cidrmatch("203.0.113.0/24", sourceIPAddress)
| where in_range=0
| table _time, userIdentity.sessionContext.sessionIssuer.arn, sourceIPAddress, eventName, userAgent
```

CONCEPTUAL SAMPLE — same instance-profile-role naming filter and egress CIDR caveats as the KQL form above; validate both against your own naming convention and NAT/egress ranges.

Plausible expected result and interpretation: unchanged from the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL), assuming a CloudTrail DSM extension already maps the session-issuer ARN and user-agent as queryable fields.

```sql
SELECT starttime, "session issuer arn", sourceip, eventname, useragent
FROM events
WHERE "user identity type" = 'AssumedRole'
  AND "session issuer arn" ILIKE '%instance-role%'
  AND NOT INCIDR('203.0.113.0/24', sourceip)
LAST 24 HOURS
```

CONCEPTUAL SAMPLE — the role-naming filter and egress CIDR are illustrative and assume a CloudTrail DSM extension already maps `session issuer arn`; validate both against your deployment.

Plausible expected result and interpretation: the same shape as the other surfaces, contingent entirely on whether the DSM mapping for `session issuer arn` actually exists in your deployment.

**[QUERY]** Google SecOps YARA-L over a cloud-audit UDM mapping.

```yaral
rule instance_role_credential_used_outside_egress_range {
  meta:
    description = "AssumedRole session tied to an instance-profile role used from outside known VPC egress"
  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.principal.user.attribute.roles = $role
    $role = /instance-role/ nocase
    $e.principal.ip = $ip
    not net.ip_in_range($ip, "203.0.113.0/24")
  condition:
    $e
}
```

CONCEPTUAL SAMPLE — the exact UDM event type and field path standing in for CloudTrail's `sessionIssuer` role concept are illustrative; validate against your own SecOps CloudTrail feed's actual mapping before use.

Plausible expected result and interpretation: same as the other surfaces above.

**[QUERY]** Elastic KQL, chosen because this is a single-event boolean match against a known-range exclusion, not a sequence or aggregation.

```kql
aws.cloudtrail.user_identity.type: "AssumedRole" and aws.cloudtrail.user_identity.session_context.session_issuer.arn: *instance-role* and not source.ip: "203.0.113.0/24"
```

CONCEPTUAL SAMPLE — the role-naming wildcard and egress CIDR are illustrative; validate against your own naming convention and NAT/egress ranges.

Plausible expected result and interpretation: unchanged from the other five.

**[FALSE POSITIVE]** A legitimate cross-account architecture — a centralized logging/security account assuming read roles into every spoke from a fixed range, or a CI/CD runner pool handing a minted session token to a deployment step on a different runner — produces the identical "used from somewhere else" shape. Key the allowlist to the actual expected source population, not the assumption that the instance's own IP is the only legitimate source for its credential.

**[PIVOT]** Correlate the flagged session's `sourceIPAddress` against the instance's own VPC flow logs — no matching outbound connection means the credential likely left through a channel other than live network egress (a copied credentials file, a leaked environment variable in a crash dump). Check every other API call under the same access key or session for the full blast radius.

> **Hunter's Note**
> GuardDuty's `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding draws on a broadly similar signal and is worth running alongside this pattern, not instead of it — a discrepancy between the two (one silent, one hot) is worth chasing before trusting either alone.

---

### QC-26-04 — Cross-account trust-policy backdoor added to an existing role

| Field | Value |
|---|---|
| **Pattern ID** | `QC-26-04` |
| **MITRE** | T1098.003 (Account Manipulation: Additional Cloud Roles); cf. T1199 (Trusted Relationship) where the added principal belongs to an entirely separate organization rather than a sibling account inside the same one. |
| **Behavior** | A role's trust (assume-role) policy is modified to add a principal outside the account's own AWS Organization, or an external account ID never previously granted assume permission on that role, creating a standing cross-account pivot path. |
| **DEH cross-ref** | DEH Part 19 §2 (IAM policy abuse — adapted here from a permission-policy target to a trust-policy target); §6's Blind Spot on the entity-resolution gap a backdoored trust policy exploits. |
| **Languages covered** | Sigma; KQL (Sentinel/Defender); SPL; AQL (QRadar); YARA-L; Elastic (KQL) |

**[HUNTER]** DEH Part 19 §2's `DET-19-01` watches what a principal grants itself. This pattern watches a different door: who a role's own trust policy says is allowed through it at all. A trust-policy edit is rarer and higher-signal than a permission-policy edit — trust relationships change far less often than permissions — making a hunt against `UpdateAssumeRolePolicy` and its Azure/GCP equivalents cheap and high-value even before a mature allowlist exists.

**[QUERY]** Sigma against CloudTrail, flagging every trust-policy edit as a coarse first pass.

```yaml
title: Role Trust Policy Modified to Add External Account Principal
id: 1f9c3b8e-6a4d-4e02-9b71-3c8a5f2d7e14
status: experimental
logsource:
  category: cloud
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'UpdateAssumeRolePolicy'
  condition: selection
fields:
  - requestParameters.policyDocument
  - requestParameters.roleName
```

CONCEPTUAL SAMPLE — Sigma's selection flags every `UpdateAssumeRolePolicy` call, but testing whether the new `Principal` names an account outside your Organization needs a post-match enrichment step most backends don't perform inline; treat this as a coarse filter, refined downstream the way DEH Part 19 §2's `known_cicd_principals_lookup` refines its own rule.

Plausible expected result: every trust-policy edit in the window, most naming an account already inside your Organization. Interpretation: a hit naming an outside account is worth escalating; a sibling account is very likely routine.

**[QUERY]** Sentinel/Defender KQL against `AWSCloudTrail`, extracting added account IDs from the policy document.

```kql
let KnownOrgAccounts = dynamic(["111111111111","222222222222","333333333333"]);
AWSCloudTrail
| where EventName == "UpdateAssumeRolePolicy"
| extend PolicyDoc = tostring(RequestParameters.policyDocument)
| extend AddedPrincipals = extract_all(@'"AWS"\s*:\s*"(\d{12})"', PolicyDoc)
| mv-expand AddedPrincipals to typeof(string)
| where AddedPrincipals !in (KnownOrgAccounts)
| project TimeGenerated, UserIdentityArn, RequestParametersRoleName, AddedPrincipals, SourceIpAddress
```

CONCEPTUAL SAMPLE — the regex assumes the account ID appears as a bare 12-digit string; the ARN form (`arn:aws:iam::111111111111:root`) needs an adjusted pattern, and `KnownOrgAccounts` must be your Organization's real member list, pulled live rather than hardcoded.

Plausible expected result: a small number of rows, most weeks producing none; each names the role, the newly added external account, and who made the change. Interpretation: consistent with a deliberately created pivot path — treat every hit as worth review regardless of volume, since this call is rare enough that per-hit confidence matters more than tuning.

**[QUERY]** Splunk SPL against a CloudTrail index.

```spl
index=aws_cloudtrail eventName=UpdateAssumeRolePolicy
| spath input=requestParameters.policyDocument output=policy_doc
| rex field=policy_doc max_match=0 "\"AWS\"\s*:\s*\"(?<added_account>\d{12})\""
| mvexpand added_account
| lookup known_org_accounts_lookup account_id AS added_account OUTPUT is_known_org_account
| where isnull(is_known_org_account)
| table _time, userIdentity.arn, requestParameters.roleName, added_account, sourceIPAddress
```

CONCEPTUAL SAMPLE — same regex caveat as the KQL form; `known_org_accounts_lookup` needs the same active-maintenance discipline DEH Part 19 §2's own CI/CD allowlist requires.

Plausible expected result and interpretation: unchanged from the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL) — investigative form. A standing detection would pair this with a Reference Set of known Organization member-account IDs maintained by a scheduled Building Block (DEH Part 27 §2–§3), rather than a hardcoded list.

```sql
SELECT starttime, "user identity arn", "role name", "policy document"
FROM events
WHERE qidname = 'UpdateAssumeRolePolicy'
LAST 7 DAYS
```

CONCEPTUAL SAMPLE — this pulls the raw event set for manual review; the account-ID extraction the KQL/SPL forms perform inline isn't available in this investigative query.

Plausible expected result: every trust-policy edit in the trailing week, for manual review of the `policy document` field's `Principal` values against your account list. Interpretation: low natural call volume makes reviewing a week's hits by hand a realistic hunt cadence even without an extraction pipeline built yet.

**[QUERY]** Google SecOps YARA-L over a cloud-audit UDM mapping.

```yaral
rule trust_policy_external_principal_added {
  meta:
    description = "Role trust policy modified; review added principal against known Organization accounts"
  events:
    $e.metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE"
    $e.target.resource.resource_subtype = "AWS::IAM::Role::TrustPolicy"
    $e.principal.user.userid = $actor
  condition:
    $e
}
```

CONCEPTUAL SAMPLE — the `resource_subtype` value distinguishing a trust-policy edit from an ordinary permission-policy edit is illustrative; validate against your own feed mapping, which may collapse both edit types under one generic UDM event type with no subtype distinction at all.

Plausible expected result: a match per `UpdateAssumeRolePolicy` call, naming the actor and role. Interpretation: same as the other surfaces — the account-ID-extraction and allowlist comparison still happens outside this rule, in a review queue or downstream enrichment.

**[QUERY]** Elastic KQL, chosen because the query itself is a single-event filter; the actual analysis is a manual document review, not additional query logic.

```kql
event.action: "UpdateAssumeRolePolicy" and event.outcome: "success"
```

CONCEPTUAL SAMPLE — this filters to the raw event only; the added-principal extraction and allowlist comparison shown in the KQL/SPL forms happen outside this query, in manual review.

Plausible expected result: every trust-policy edit in the queried window. Interpretation: unchanged from the other five — this is the one pattern in this part where the simplest possible query is arguably the right one, and the real work happens in the pivot below.

**[FALSE POSITIVE]** A newly onboarded SaaS vendor's support-access role, a new Organizations member account, or a break-glass DR account added on a documented change ticket all produce the identical event. Maintain the allowlist keyed to a change-ticket reference, not "add and forget," re-reviewed on a fixed schedule — the single control this pattern's precision depends on.

**[PIVOT]** Check whether the newly trusted external principal actually calls `AssumeRole` against this role in the following hours or days (`QC-26-01`'s chain-walk is the natural next query) — an unused change is lower urgency than one followed quickly by a real assumption. Cross-check whoever made the change against a recent `DET-19-01` escalation signal.

> **Detection Autopsy — "any UpdateAssumeRolePolicy call is a finding"**
>
> **The rule:** Alert on every `UpdateAssumeRolePolicy` CloudTrail event, full stop.
>
> **Why it shipped:** It's the one API call every cross-account-backdoor write-up names as the mechanism, and it needs no document parsing to catch the call itself.
>
> **How it failed:** Every Organizations onboarding, every landing-zone Terraform module provisioning a spoke account's roles, and every access-request workflow granting a CI/CD account assume permission calls this exact API as routine work — in a growing Organization this fired dozens of times a month, with no way to separate onboarding from a backdoor without opening every document by hand.
>
> **The fix:** Parse the added principal's account ID out of the policy document and cross-reference it against the Organization's actual member-account list — the same document-parsing discipline DEH Part 19 §2's privilege-escalation rule applies to permission policies, applied here to trust policies instead.

**[SOC MANAGEMENT]** A genuine `UpdateAssumeRolePolicy` call is rare enough outside onboarding work that this pattern tunes into a low-volume, high-confidence standing alert rather than a hunt — treat every hit as worth same-day review, one tier down from the zero-tolerance posture DEH Part 19 §5 applies to logging-tamper calls.

---

### QC-26-05 — Chained role assumption immediately followed by a privilege-granting action

| Field | Value |
|---|---|
| **Pattern ID** | `QC-26-05` |
| **MITRE** | T1548.005 (Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access) |
| **Behavior** | A principal calls `sts:AssumeRole`, and within a short window the resulting session — identified by role session name or temporary access key ID — performs a privilege-granting action (attaching an administrator-equivalent policy, modifying another role's trust policy, or minting a new long-lived access key) that the originating principal could not have performed directly under its own identity. |
| **DEH cross-ref** | DEH Part 19 §2 (`DET-19-01`, extended here across an assumed-role boundary); §6.1 (`HUNT-19-01`'s novelty framing, here joined to a specific follow-on action). |
| **Languages covered** | Sigma — `N/A`, see below; KQL (Sentinel/Defender); SPL; AQL (QRadar, investigative form only — see below); YARA-L; Elastic (EQL) |

**[HUNTER]** `DET-19-01` (DEH Part 19 §2) catches a principal escalating its own permissions directly. It has a structural blind spot: a principal that assumes a role with broader permissions than its own, then uses that session to grant itself something permanent, never shows up as *that principal's own* escalation — the record for the privilege-granting call carries the assumed role's ARN, not the originating identity's. This hunt closes the gap by joining the `AssumeRole` event to whatever the session does next, rather than trusting either event alone.

**[QUERY]** *Sigma — `N/A` — aggregation ceiling.* This pattern joins two structurally different event types — `AssumeRole`, then a distinct privilege-granting call — on a derived key (the session's role-session-name or access key ID) that doesn't exist when the first event is evaluated. Sigma's `value_count`/`event_count` correlation types count occurrences of *matching* events; they don't join two differently-shaped event types on a value one produces for the other to consume — one step harder than the `temporal_ordered` gap `QC-05-05` already names for Sigma, since here the two events aren't even the same shape.

**[QUERY]** Sentinel/Defender KQL against `AWSCloudTrail`, joining an `AssumeRole` event to a following privilege-granting call from the same session.

```kql
let Window = 10m;
let Escalations = AWSCloudTrail
| where EventName in ("AttachUserPolicy","AttachRolePolicy","PutRolePolicy","UpdateAssumeRolePolicy","CreateAccessKey")
| project EscTime = TimeGenerated, SessionArn = tostring(UserIdentityArn), EventName;
AWSCloudTrail
| where EventName == "AssumeRole"
| extend AssumedArn = tostring(parse_json(ResponseElements).AssumedRoleUser.Arn),
         OriginArn = tostring(UserIdentityArn)
| join kind=inner Escalations on $left.AssumedArn == $right.SessionArn
| where EscTime between (TimeGenerated .. TimeGenerated + Window)
| project TimeGenerated, OriginArn, AssumedArn, EscTime, EventName
```

CONCEPTUAL SAMPLE — the join key (`AssumedArn == SessionArn`) assumes both events carry a directly comparable session-identity string; the assumed-role session ARN embeds a session name the follow-on event's `userIdentity.arn` usually, but not always, reproduces verbatim depending on the calling SDK's own session-naming behavior.

Plausible expected result: a small number of rows pairing one `AssumeRole` call with a privilege-granting action from the resulting session within 10 minutes. Interpretation: consistent with a principal reaching a permission it doesn't hold directly by routing through an assumed session — a stronger signal than `DET-19-01` alone, precisely because `DET-19-01` cannot see this originating principal at all.

**[QUERY]** Splunk SPL, same join shape.

```spl
index=aws_cloudtrail eventName=AssumeRole
| eval assumed_arn=json_extract(responseElements, "AssumedRoleUser.Arn")
| join type=inner assumed_arn
    [ search index=aws_cloudtrail
        (eventName=AttachUserPolicy OR eventName=AttachRolePolicy OR eventName=PutRolePolicy
         OR eventName=UpdateAssumeRolePolicy OR eventName=CreateAccessKey)
      | rename userIdentity.arn as assumed_arn
      | eval esc_time=_time ]
| where esc_time > _time AND esc_time < _time + 600
| table _time, userIdentity.arn, assumed_arn, esc_time, eventName
```

CONCEPTUAL SAMPLE — same session-key caveat as the KQL form above: the join assumes the follow-on event's `userIdentity.arn` reproduces the assumed-role session ARN verbatim, which depends on the calling SDK's own session-naming behavior.

Plausible expected result and interpretation: unchanged from the KQL form above.

**[QUERY]** QRadar AQL (not standard SQL) — investigative form only. Paste in the assumed-role session ARN a suspicious `AssumeRole` event produced and check what that session did in the following ten minutes. A standing detection needs a Reference Set holding recently-assumed session ARNs, tested against a second Rule watching for privilege-granting calls (DEH Part 27 §2–§3), not one query.

```sql
SELECT starttime, "user identity arn", qidname
FROM events
WHERE "user identity arn" = 'arn:aws:sts::111111111111:assumed-role/deploy-role/session-abc123'
  AND qidname IN ('AttachUserPolicy','AttachRolePolicy','PutRolePolicy',
                  'UpdateAssumeRolePolicy','CreateAccessKey')
LAST 10 MINUTES
```

CONCEPTUAL SAMPLE — the session ARN is a placeholder pasted in from whatever `AssumeRole` event made you suspicious; this is the manual, investigative version of the KQL/SPL join above, not a standing rule.

Plausible expected result: zero or one row, since a real escalation attempt is a single deliberate action, not a repeated one. Interpretation: unchanged from the KQL/SPL forms — a hit is a probable-escalation lead pending the pivot below.

**[QUERY]** Google SecOps YARA-L, matching an `AssumeRole` event followed by a privilege-granting call under the same session ARN.

```yaral
rule assumed_session_privilege_grant_followup {
  meta:
    description = "AssumeRole followed within 10m by a privilege-granting call from the same session"
  events:
    $assume.metadata.event_type = "USER_RESOURCE_ACCESS"
    $assume.metadata.product_event_type = "AssumeRole"
    $assume.target.resource.attribute.labels["assumed_role_arn"] = $session_arn
    $esc.metadata.event_type = "USER_RESOURCE_ACCESS"
    $esc.metadata.product_event_type = ("AttachUserPolicy" or "AttachRolePolicy" or
      "PutRolePolicy" or "UpdateAssumeRolePolicy" or "CreateAccessKey")
    $esc.principal.user.userid = $session_arn
    $esc.metadata.event_timestamp.seconds > $assume.metadata.event_timestamp.seconds
  match:
    $session_arn over 10m
  condition:
    $assume and $esc
}
```

CONCEPTUAL SAMPLE — the `labels["assumed_role_arn"]` path is illustrative; confirm how your SecOps CloudTrail feed actually surfaces the assumed-role session ARN before relying on this join key.

Plausible expected result and interpretation: unchanged from the KQL/SPL forms above.

**[QUERY]** Elastic EQL, chosen because this is an ordered two-event join on a derived session key rather than a threshold or a single boolean match (per DEH Appendix A5 §8's decision table).

```eql
sequence by aws.cloudtrail.session_arn with maxspan=10m
  [any where event.action == "AssumeRole" and event.outcome == "success"]
  [any where event.action in ("AttachUserPolicy","AttachRolePolicy","PutRolePolicy",
                               "UpdateAssumeRolePolicy","CreateAccessKey") and event.outcome == "success"]
```

CONCEPTUAL SAMPLE — assumes an ingest-time enrichment step populates `aws.cloudtrail.session_arn` identically on both the `AssumeRole` response and the follow-on call's `userIdentity.arn`; native ECS carries no such normalized field, so this query's join key is a prerequisite you would need to build, not something CloudTrail hands you already aligned.

Plausible expected result: a sequence match per qualifying (session, escalation) pair inside the 10-minute window. Interpretation: unchanged from the other surfaces.

**[FALSE POSITIVE]** Deployment pipelines routinely assume a role and immediately perform a privileged action under that session as their entire purpose — a CI/CD job assuming a deploy role that creates an execution role or attaches a policy as part of an IaC apply produces exactly this shape. The discriminator: whether the *originating* principal already held the permission directly. A pipeline scoped to grant permissions it doesn't hold outside the role is normal by design; a low-privilege principal reaching that permission through an unprovisioned role is not. Allowlist known deployment-role ARNs and session-name patterns, not the action type alone.

**[PIVOT]** Diff the originating principal's permissions against what the assumed role grants — a large, undocumented gap is a live escalation candidate. Check for other recent `AssumeRole` calls against other high-privilege roles in the same window, suggesting role-chaining is being probed systematically.

> **What Would Change My Mind**
> This pattern's 10-minute window assumes a genuine escalation attempt acts quickly. If real incident timelines showed attackers routinely waiting hours before escalating — letting the `AssumeRole` event age out of a short-lookback rule's reach — the window would need to widen substantially, and the join would run as a batch hunt rather than a near-real-time correlation, the tradeoff `QC-05-04` makes explicit for password spraying's own long-horizon variant.

## Cross-references

This part's queries build on DEH Part 19 §1 (control-plane logging architecture), §2 (`DET-19-01`, extended in different directions by `QC-26-04` and `QC-26-05`), and §6 (credential usage, instance-metadata theft, and assumed-role chains — the section this part is organized around). DEH Part 23 §3's translation-loss framework is the general mechanism behind this part's Sigma/YARA-L `N/A` entries, and DEH Appendix A5 §8 governs every Elastic-surface choice above. See this book's Part 24 for the federated-identity layer `QC-26-01`'s Blind Spot hands off to, Part 25 for the single-account patterns this part doesn't repeat, Part 7/Part 17 for the on-premises theft-vs-use split `QC-26-02`/`QC-26-03` mirror, and Part 5 (`QC-05-04`, `QC-05-05`) for the wide-lookback and investigative-AQL precedent reused throughout.
