# Cloud - Azure/Entra external recon and token pivoting

## MicroBurst resource enumeration and Entra password spraying with Smart Lockout awareness

**Trigger:** You are attacking an Azure/M365 tenant from the outside with only a domain name and want to discover its cloud footprint and get a first valid credential.

Cloud recon and spraying differ operationally from on-prem AD and are not gated by the domain lockout policy. Discover the tenant's public surface with MicroBurst — Azure subdomain permutations (<name>.onmicrosoft.com, azurewebsites.net, blob/file/queue/table.core.windows.net, database.windows.net, vault.azure.net) and open blob containers — and validate which guessed emails exist via o365creeper against the GetCredentialType endpoint. Then spray against login.microsoftonline.com with MSOLSpray, but respect Entra Smart Lockout: it is per-user and partly per-source-IP, does NOT increment on-prem badPwdCount, and typically locks after ~10 bad attempts from a region — so use one password per user per cycle, rotate source IPs (FireProx), and watch for the AADSTS error codes that distinguish valid-user/wrong-password (AADSTS50126) from MFA-required (AADSTS50079/50076, i.e. the password was correct) and disabled/locked (AADSTS50053/50057).

```powershell
# Federation / managed check + tenant surface:
curl "https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1"
Invoke-EnumerateAzureSubDomains -Base <name> -Verbose      # MicroBurst
# Validate emails then spray:
python3 o365creeper.py -f emails.txt -o valid.txt
Invoke-MSOLSpray -UserList valid.txt -Password 'Summer2026!' -Verbose
# Interpret: AADSTS50126=valid user/bad pass; 50079/50076=correct pass, MFA needed; 50053=locked/Smart Lockout
```

Source: https://offsecexams.com/cheatsheets/cartp-exam---guided-by-redblock

## Azure token audiences and FOCI multi-audience pivot

**Trigger:** You hold any Azure credential or foothold and need to know what a token can reach, or want to turn access to one API into access to another.

Azure access tokens are JWTs scoped to a single audience (aud); a token minted for ARM will not work against Graph, Key Vault, or Storage. From any authenticated az session, mint a token per resource with az account get-access-token --resource <uri>: management.azure.com (ARM), graph.microsoft.com (Graph), vault.azure.net (Key Vault), storage.azure.com (Storage), database.windows.net (SQL). Decode the middle segment (base64url) and read aud/scp/roles/oid/tid/appid to learn exactly which API, which delegated scopes (scp) or app-permission roles, which principal (oid), and which tenant the token represents before you touch anything. Drive raw APIs with az rest --method GET --url ... or a bare curl bearer request when az subcommands do not expose an operation. The pivot lever is FOCI: family first-party clients (Azure CLI 04b07795-8ddb-461a-bbee-02f9e1bf7b46, Az PowerShell, Office) share refresh tokens, so a refresh token for one family client can redeem access tokens for a different audience without re-authenticating, using TokenTactics or roadtx. This is the resource-plane counterpart to the PRT/device-code flows in ctf-ad/entra-hybrid.md.

```bash
az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv
TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
echo "$TOKEN" | cut -d. -f2 | sed 's/-/+/g;s/_/\//g' | base64 -d 2>/dev/null | jq '{aud,scp,roles,oid,tid,appid}'
az rest --method GET --url "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock

## AzureHound attack-path graph and Cypher edge hunting

**Trigger:** You have read access to a tenant or subscription and want the shortest path to Global Admin or Owner instead of hand-walking role assignments.

AzureHound collects Entra directory objects and Azure RBAC assignments into a BloodHound graph so privilege-escalation chains become Cypher queries. Run azurehound -u user@tenant -p '***' --tenant <tid> list -o out.json and ingest the JSON. Then hunt edges: shortestPath to an AZRole node named 'Global Administrator' finds identity escalation; AZAddSecret or AZOwns over an AZServicePrincipal means you can add a credential and log in as that SP; AZOwns or AZUserAccessAdministrator over an AZSubscription means you can self-assign Owner. This complements the offline directory dump from roadrecon (documented in ctf-ad/entra-hybrid.md) by scoring resource-plane RBAC paths, not just directory objects and role activations.

```bash
azurehound -u user@tenant -p '***' --tenant <tid> list -o azurehound.json
// escalation to Global Admin
MATCH p=shortestPath((n)-[*1..]->(m:AZRole {displayname:"Global Administrator"})) RETURN p
// principals that can add creds to a privileged SP
MATCH (u)-[:AZAddSecret|AZOwns]->(sp:AZServicePrincipal) RETURN u.name, sp.name
// subscription owners / User Access Administrators
MATCH (u)-[:AZOwns|AZUserAccessAdministrator]->(s:AZSubscription) RETURN u.name, s.name
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock
