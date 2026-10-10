# Penetration Test Report — Example Zone (worked sample, fictional data)

**Tester:** exam-candidate  **Date:** 2026-09-01  **Scope:** 10.10.99.0/24 (exclusions per exam dashboard)
**Objective:** Answer the zone's question set with reproducible evidence.

## 1. Executive Summary

One fictional web target (10.10.99.10, "demoapp") was assessed using
step-wise capture (every step = explanation + command + screenshot). An
unauthenticated file-disclosure flaw led to credential access and flag
recovery. All values are illustrative.

## 2. Answer Summary

| # | Question (short) | Answer | Step | Evidence |
|---|------------------|--------|------|----------|
| 1 | Web server version | DemoHTTP 2.4.41 | S-1 | E-demo01-001 |
| 2 | Flag fragment | ab12cd | S-3 | E-demo01-003 |

## 3. Scope and Rules

Authorized scope: 10.10.99.0/24 minus dashboard-listed exclusions. Rules:
exam conduct rules as published on the dashboard at report time; no
prohibited tooling; all actions inside the scope and exam window.

## 4. Detailed Walkthrough

### Step S-1 — Service discovery on 10.10.99.10

**Explain:** Before any application testing we need the service map. A
version scan on the top ports identifies the web server and version —
this directly answers question 1 and directs the enumeration tooling.

**Reproduce:**
```
nmap -sV -Pn 10.10.99.10
```

**Expected:** an HTTP service with a version banner.
**Observed:** TCP 22 OpenSSH; TCP 80 DemoHTTP 2.4.41 (answer 1).
**Evidence:** Figure 1 (E-demo01-001) — scan output showing the version.

### Step S-2 — Confirm path traversal in view.php

**Explain:** Directory enumeration (gobuster, raft-medium) located
`view.php`; manual probing added the `file` parameter. A relative-path
traversal request proves or disproves arbitrary file read — the core
primitive for the next step. Expected on a patched app: an error page.

**Reproduce:**
```
curl -s "http://10.10.99.10/view.php?file=../../../../etc/passwd"
```

**Expected:** HTML error or empty response.
**Observed:** contents of `/etc/passwd` returned (Figure 2, E-demo01-002).
**Evidence:** Figure 2 (E-demo01-002) — response body showing passwd lines.

### Step S-3 — Credential access and flag recovery

**Explain:** With arbitrary file read, application configuration was
retrieved, yielding a service-account credential (fictional `svc-demo`).
SSH as that account permits reading the flag file — the objective of
question 2.

**Reproduce:**
```
sshpass -p '<recovered-password>' ssh -o StrictHostKeyChecking=no svc-demo@10.10.99.10 'cat /home/svc-demo/flag.txt'
```

**Expected:** flag file content.
**Observed:** flag fragment `ab12cd` (answer 2).
**Evidence:** Figure 3 (E-demo01-003) — terminal showing the flag read.

## 5. Technical Findings

### 5.1 Unauthenticated local file disclosure — Severity: Critical
- **Host:** 10.10.99.10/view.php (F-1)
- **Root cause:** user-controlled `file` parameter joined to a base path
  without canonicalization or allowlist.
- **Reproduce:** Step S-2 command.
- **Evidence:** Figure 2 (E-demo01-002)
- **Impact:** arbitrary file read as the web user → credential material.
- **Remediation:** map user input to a server-side allowlist of filenames;
  reject path components. **Retest:** repeat S-2 — expect error page.

## 6. Attack Chain Narrative

Recon (S-1) exposed an outdated HTTP service; enumeration found `view.php`,
whose `file` parameter accepted relative traversal (S-2), giving arbitrary
file read; configuration read through the flaw yielded service credentials
whose SSH session recovered the flag (S-3).

## 7. Credentials Recovered

| Account | Scope | How obtained (Step) |
|---------|-------|---------------------|
| svc-demo (fictional) | web host | file disclosure (S-2) |

## 8. Tools Used

nmap, gobuster, curl, sshpass.

## 9. Command Index

| ID | Purpose | Command | Result | Step |
|----|---------|---------|--------|------|
| CMD-demo01-001 | Service discovery | `nmap -sV -Pn 10.10.99.10` | HTTP identified | S-1 |
| CMD-demo01-002 | Traversal proof | `curl -s "http://10.10.99.10/view.php?file=../../../../etc/passwd"` | passwd returned | S-2 |
| CMD-demo01-003 | Flag read | `sshpass -p '<recovered-password>' ssh svc-demo@10.10.99.10 'cat /home/svc-demo/flag.txt'` | flag read | S-3 |

## 10. Evidence Index

| ID | Description | Figure | Path |
|----|-------------|--------|------|
| E-demo01-001 | nmap version output | Figure 1 | ~/loot/demo/steps/01.png |
| E-demo01-002 | Traversal response | Figure 2 | ~/loot/demo/steps/02.png |
| E-demo01-003 | Flag recovery terminal | Figure 3 | ~/loot/demo/steps/03.png |

## Appendix — Figures

| Figure | Step | Proves | Path |
|--------|------|--------|------|
| Figure 1 | S-1 | server version | ~/loot/demo/steps/01.png |
| Figure 2 | S-2 | file disclosure | ~/loot/demo/steps/02.png |
| Figure 3 | S-3 | flag recovery | ~/loot/demo/steps/03.png |

Independent reproduction: performed (fictional sample). Time zone: UTC
throughout.
