# Cloud, IaC, and endpoint telemetry CTF workflow

Use this note for supplied cloud logs, Terraform state/plan files, CI artifacts, endpoint telemetry, and mobile backups. Keep analysis offline unless the challenge explicitly provides a target and scope.

## Preserve and normalize first

1. Hash original log bundles, state files, disk images, and exported JSON before parsing.
2. Normalize timestamps to UTC while retaining original time zones and clock fields.
3. Build a single event table with time, actor/identity, source IP or workload, action, resource, result, and source artifact.
4. Distinguish evidence of configuration from evidence of use: a role policy may be broad, but audit logs establish whether and how it was exercised.

## Cloud and IaC artifact map

| Artifact | First questions |
|---|---|
| Terraform state / plan | Which outputs, prior values, provider data, resources, and dependencies reveal the intended trust graph? |
| CI logs / workflow | Which event, branch, artifact, or identity caused a deployment or credential exchange? |
| Cloud audit logs | Which principal called which API, from where, in what order, and did it succeed? |
| Kubernetes audit / container logs | Which service account, pod, exec/attach request, secret access, or image pull occurred? |
| Endpoint telemetry | Which parent process, command line, network connection, file, and user/session explain the sequence? |

## CTF-specific cloud timeline method

1. Start from the solved-condition resource or flag location and work backward through its most recent modification/access event.
2. Resolve temporary identities: role sessions, workload identities, service accounts, OIDC subjects, and CI tokens can map one action to another even when user names differ.
3. Reconstruct artifact provenance: source revision -> CI job -> produced image/package -> deployment -> workload action.
4. Correlate errors and denials. In CTFs, an `AccessDenied`, failed AssumeRole, failed Kubernetes authorization, or plan error often names the missing relation.
5. Test only against the supplied data or replay harness; report the smallest evidence-backed chain.

## Endpoint and mobile extensions

- **Windows:** correlate EVTX, registry, Amcache, Prefetch, PowerShell history, browser history, and USN/MFT chronology. A single event ID rarely proves a full chain.
- **Linux:** correlate shell/auth logs, auditd, journald, cron/systemd, package history, container runtime logs, and browser/application caches.
- **Mobile backups:** inventory manifest/database metadata, application sandboxes, key-value stores, tokens, and attachment timestamps before brute-forcing or carving.

## Common CTF pitfalls

- reading secrets directly from a state file without checking whether they are stale, masked, or challenge decoys;
- sorting mixed local/UTC timestamps lexicographically;
- treating a cloud resource ID as an authenticated principal;
- ignoring CI artifacts and image layers that bridge source code to runtime;
- assuming deleted or rotated logs erase corroborating filesystem, audit, or workflow evidence.

## Source technique examples

- [Wiz Cloud Security Challenge “State of Affairs” write-up](https://kabinet.gitbook.io/ctf-writeup/2026/wiz-cloud-security-challenge/state-of-affairs)
- [Hacking the Cloud: CI/CDon't CTF walkthrough](https://hackingthe.cloud/aws/capture_the_flag/cicdont/)

## Frequency stacking and statistical outliers over large endpoint telemetry sets

**Trigger:** You are handed weeks of process/network/file telemetry (Sysmon, EDR export, auditd) with no starting IOC, and per-event review is impossible.

With no lead, invert the problem: instead of searching for known-bad, rank by rarity and by deviation from each entity's own baseline. Stack frequencies first — group by parent/child image pair, by binary path, by destination port, by loaded module — and read the bottom of the count-sorted list, since attacker tooling is almost always the least frequent thing in the set. Then compute per-entity baselines rather than global ones: for each process, take a rolling mean and standard deviation of its hourly connection count over a trailing window and flag hours that exceed the mean by a chosen number of deviations, which catches beaconing from a binary that is otherwise normal without flagging chatty browsers. Continuous fields have their own tells: sort command lines by length, because encoded PowerShell and long base64 blobs sit far out on the tail of a distribution whose body is a handful of characters. Path-shape predicates are cheap and productive — executables created or run under a user's Downloads or AppData tree, archive extensions appearing on a server, PE writes anywhere outside the Windows directory, destinations on ports outside the site's normal set. Finally, pair related events into sessions by grouping on the process image and bounding the span, so a process creation followed by an outbound connection within a minute becomes one reviewable unit instead of two unlinked rows. Every one of these produces false positives by design; the output is a shortlist to timeline, not a verdict.

```bash
# Rarity stacking: read the bottom of the list
index=main EventCode=1 | stats count by ParentImage, Image | sort count

# Per-process rolling baseline of outbound connections (deviation, not threshold)
index=main EventCode=3 | bin _time span=1h
| stats count as conns by _time, Image
| streamstats time_window=24h avg(conns) as avg stdev(conns) as sd by Image
| eval outlier=if(conns > avg + 2*sd, 1, 0) | search outlier=1

# Long command lines: encoded payloads live on the tail
index=main EventCode=1 | eval len=len(CommandLine)
| table _time, User, Image, len, CommandLine | sort - len

# Path-shape predicates
index=main EventCode=1 | regex Image="C:\\\\Users\\\\.*\\\\(Downloads|AppData)\\\\.*"
index=main EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll" OR TargetFilename="*.zip" OR TargetFilename="*.7z") TargetFilename!="*\\Windows\\*"
  | stats count by User, TargetFilename
index=main EventCode=3 NOT (DestinationPort IN (80,443,53,445,3389))
  | stats count by SourceIp, DestinationIp, DestinationPort

# Pair process start to its first callout as one session
index=main | transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m

# Exclude the top-N noisiest images via subsearch instead of hand-built allowlists
index=main EventCode=1 NOT [ search index=main EventCode=1 | top limit=100 Image | fields Image ]
```

Source: https://offsecexams.com/cheatsheets/cdsa-exam---guided-by-redblock

