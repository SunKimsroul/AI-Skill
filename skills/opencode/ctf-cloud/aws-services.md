# Cloud - AWS service abuse: secrets, snapshots, and SSM shells

## Secret-store sweep after any credential foothold

**Trigger:** You have any working AWS principal and want the next credential — database passwords, API keys, other accounts' keys — rather than more IAM permissions.

Escalation is not always the fastest route to the objective; in most real accounts the plaintext you need is already sitting in one of four stores, and sweeping them costs four commands. Secrets Manager is the obvious one, but list first and pull selectively because get-secret-value is per-secret and each call is a logged event. Parameter Store is the higher-yield target and the one people forget: get-parameters-by-path with --path / --recursive --with-decryption walks the entire hierarchy and decrypts SecureString values in one shot, provided the principal can use the backing KMS key. Lambda functions leak in their configuration rather than their code — query the Environment block of get-function-configuration, since developers routinely park connection strings and third-party tokens there. EC2 user data is the classic one: describe-instance-attribute with --attribute userData returns the base64 bootstrap script, which frequently contains bootstrap credentials, repository tokens, or a hardcoded admin password, and reading it needs only a describe permission rather than any access to the running host. Do all four before attempting anything noisy — a found password often makes the whole escalation chain unnecessary.

```bash
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <id>

aws ssm get-parameters-by-path --path / --recursive --with-decryption

aws lambda get-function-configuration --function-name <f> --query Environment

aws ec2 describe-instance-attribute --instance-id <i> --attribute userData \
  --query 'UserData.Value' --output text | base64 -d
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock

## Snapshot restore as a read path around a locked-down datastore

**Trigger:** The data you want lives on a volume or in a database you cannot reach — no network path, no DB credentials — but the principal can describe and act on snapshots.

Backups are governed by a completely different permission set from the resources they copy, and that asymmetry is the whole technique: you do not need access to the running database, you need access to a copy of it. For EBS, enumerate snapshots owned by the account with describe-snapshots --owner-ids self, create a volume from an interesting one in an availability zone you control, attach it to an instance you own, and mount it — you now read the filesystem of a host you were never able to log into. For RDS, restore-db-instance-from-db-snapshot spins up a brand-new instance from the snapshot, and because it is a new instance you set the master credentials rather than needing the original ones, then connect from a security group of your choosing. Both paths are also worth checking from the other direction: snapshots are frequently shared more permissively than their source resources, so a snapshot marked public or shared with another account is an exfiltration route that no amount of hardening on the live database will close. Snapshot creation and restore are conspicuous and expensive, so pick the specific snapshot from the describe output rather than restoring everything.

```bash
aws ec2 describe-snapshots --owner-ids self
aws ec2 create-volume --snapshot-id snap-<id> --availability-zone <az>
# then attach-volume to an instance you control and mount it

aws rds describe-db-snapshots
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier pwn --db-snapshot-identifier <snap>
# new instance, so you choose the master password and the security group
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock

## SSM Session Manager as an inbound-free shell on EC2

**Trigger:** You need command execution on an EC2 instance that has no open inbound port, no SSH key you hold, and sits in a private subnet — but the principal has ssm permissions.

When an instance runs the SSM agent with an instance profile that permits it, the agent maintains an outbound channel to the SSM service and AWS will broker an interactive session to it. That inverts the usual reachability assumption: there is no listening port to find, no key to steal, and no network path to build, because authorization is purely IAM and the connection is established from the instance outward. Practically this means an ssm permission discovered during IAM enumeration is a shell, and should be ranked above any attempt to reach the host over the network. It is also the cleanest way to convert a passed or assumed role into on-host execution when the role's value is what it can reach inside the VPC rather than what it can call in the API. Two things to check before spending time on network pivoting: whether the target instance appears in the SSM inventory at all (an agentless or misconfigured instance will not), and what the instance profile itself can do, since the session lands you as a local user on a host that has its own IMDS credentials to harvest per the metadata technique.

```bash
aws ssm start-session --target i-<instance-id>
```

Source: https://offsecexams.com/cheatsheets/arte-exam---guided-by-redblock
