# Cloud - AWS unauthenticated entry: Cognito and public assets

## Unauthenticated Cognito identity pool as an external entry point

**Trigger:** A web or mobile client bundle exposes a Cognito identity pool ID and the app lets you use some functionality before logging in.

An identity pool ID looks like a harmless configuration constant and is meant to be client-visible, which is exactly why it gets overlooked. If the pool has unauthenticated access enabled, anyone holding that ID can request an identity and then exchange it for real, temporary AWS credentials bound to the pool's unauthenticated role — no account, no password, no token. Two calls do it: get-id returns an identity ID, get-credentials-for-identity turns that into an access key, secret and session token. The entire question then becomes what the unauth role is allowed to do, so feed those credentials straight into permission discovery; in practice these roles are frequently over-scoped with wildcard access to a DynamoDB table, an S3 prefix, or a Lambda, because the developer reasoned about the app's UI rather than about the role's policy. Harvest pool IDs from JavaScript bundles, decompiled mobile apps, and configuration endpoints. Treat this as one of the few genuine unauthenticated-to-inside-the-account transitions in AWS, and check it before any credential-guessing effort.

```bash
aws cognito-identity get-id --identity-pool-id <pool-id>
aws cognito-identity get-credentials-for-identity --identity-id <identity-id>
# then export the returned keys and run permission discovery against them
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock

## Public bucket and cloud asset discovery from a company name

**Trigger:** You have a target organization and no credentials at all, and need an external entry point.

Storage bucket names live in a single global namespace and are usually derived mechanically from the organization name plus a suffix like -backups, -dev, -assets or -logs, which makes them guessable rather than discoverable. cloud_enum takes a keyword and sweeps the predictable permutations across providers, while s3scanner checks a candidate list and reports which buckets exist and which are readable or writable — the writable ones matter as much as the readable ones, since a writable asset bucket serving a live site is a supply-chain foothold. Once a bucket responds, separate three distinct conditions before claiming a finding: the bucket exists but denies you, the bucket permits listing, or the bucket permits object reads without listing (in which case you need object names from the application's own HTML and JavaScript). Read the bucket policy directly when you can, since the policy is where an over-broad Principal shows up. Pull the contents down with s3 sync rather than clicking through objects, and remember that leaked long-lived keys in public repositories and CI logs are the other half of this same unauthenticated phase — any key at all feeds directly into permission discovery.

```bash
cloud_enum -k <companyname>
s3scanner scan --bucket-file guessed_names.txt

curl -s https://<bucket>.s3.amazonaws.com/        # anonymous listing test
aws s3api get-bucket-policy --bucket <b>
aws s3 sync s3://<bucket> ./loot
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock
