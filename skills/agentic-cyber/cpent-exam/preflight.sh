#!/usr/bin/env bash
# cpent-exam preflight — run at exam start. Verifies this laptop's attack kit.
# Usage: bash ~/.config/opencode/skills/cpent-exam/preflight.sh [exam-range-cidr]

PASS=0; FAIL=0; WARN=0
ok(){   printf "  \033[32mPASS\033[0m %s\n" "$1"; PASS=$((PASS+1)); }
bad(){  printf "  \033[31mFAIL\033[0m %s %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
warn(){ printf "  \033[33mWARN\033[0m %s\n" "$1"; WARN=$((WARN+1)); }
have(){ command -v "$1" >/dev/null 2>&1; }

T=/tmp/opencode/cpent-preflight; mkdir -p "$T"

echo "== 1. Core tooling =="
for t in nmap nxc john hydra ldapsearch kerbrute evil-winrm bloodhound-python impacket-secretsdump ffuf gobuster sqlmap searchsploit gdb checksec upx socat chisel proxychains4 sshpass sqlite3 file; do
  have "$t" && ok "$t" || bad "$t" "MISSING — see toolkit.md provisioning"
done
have impacket-GetNPUsers && ok "impacket-GetNPUsers" || bad "impacket-GetNPUsers"
command -v keylistattack.py >/dev/null 2>&1 && ok "keylistattack.py (Key List attack)" || warn "keylistattack.py not on PATH (~/.local/bin?)"

echo "== 2. Zone-critical tools =="
have binwalk  && ok "binwalk (IoT zone)"          || bad "binwalk" "pipx install binwalk — IoT zone stalls without it"
have radare2  && ok "radare2 (binary RE)"         || bad "radare2" "build per toolkit.md provisioning"
have wpscan   && ok "wpscan (WordPress)"          || warn "wpscan missing — manual WP enum (zone-ctf.md)"
have git-dumper && ok "git-dumper (git exposure)" || warn "git-dumper missing — pipx install git-dumper"
have ROPgadget && ok "ROPgadget (ROP chains)"     || warn "ROPgadget missing (ropper unavailable on py3.14)"
have tshark   && ok "tshark (OT pcap analysis)"   || warn "tshark missing — needed for Modbus range"
{ python3 -c "import pymodbus" 2>/dev/null || ~/.local/share/pipx/venvs/pymodbus/bin/python -c "import pymodbus" 2>/dev/null; } && ok "pymodbus (OT active)" || warn "pymodbus missing — pipx install pymodbus"
have python3  && python3 -c "import pwn" 2>/dev/null && ok "pwntools" || bad "pwntools" "pipx install pwntools"
python3 -c "import paramiko" 2>/dev/null && ok "paramiko" || warn "paramiko missing"
python3 -c "import socketio" 2>/dev/null && ok "python-socketio (web zone bots)" || warn "python-socketio missing — pip install python-socketio"
python3 -c "import jwt" 2>/dev/null && ok "pyjwt (JWT forge/verify)" || warn "pyjwt missing — pipx install pyjwt"
[ -f /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb ] && ok "msf pattern tools (/opt path)" || warn "pattern_create.rb not at /opt path"
[ -d ~/tools/Responder ] && ok "~/tools arsenal present" || warn "~/tools missing (Responder, PKINITtools, targetedKerberoast)"

echo "== 3. Wordlists =="
if [ -f "$HOME/rockyou.txt" ] && [ "$(wc -l < "$HOME/rockyou.txt")" -gt 1000000 ]; then
  ok "rockyou full (~/rockyou.txt, $(wc -l < ~/rockyou.txt) lines)"
elif [ -f /usr/share/wordlists/rockyou.txt ]; then ok "rockyou (/usr/share/wordlists)"
else warn "no full rockyou — extract: tar -xzf /snap/seclists/current/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C ~"
fi
[ -d /usr/share/seclists ] && ok "seclists" || warn "seclists dir missing"

echo "== 4. Cracker sanity (known hash: NT 'password') =="
printf 'pf:8846f7eaee8fb117ad06bdd830b7586c:::\n' > "$T/nt.jtr"; printf 'password\n' > "$T/wl"
printf '8846f7eaee8fb117ad06bdd830b7586c\n' > "$T/nt.raw"
if hashcat -m 1000 -a 0 --potfile-path="$T/hpot" --quiet "$T/nt.raw" "$T/wl" >/dev/null 2>&1; then
  ok "hashcat cracks NT (verified live)"
else
  warn "hashcat failed this run — do NOT trust it today"
fi
( cd "$T" && HOME="$T" john --format=nt --wordlist="$T/wl" "$T/nt.jtr" ) > "$T/john.out" 2>&1
HOME="$T" john --show --format=NT "$T/nt.jtr" 2>/dev/null | grep -q '^pf:' \
  && ok "john cracks NT (jumbo build active)" \
  || warn "john cannot crack NT (core build) — NT-family via hashcat, or install jumbo (toolkit.md)"

echo "== 5. Connectivity =="
if [ -n "$1" ]; then
  ping -c1 -W2 "${1%/*}" >/dev/null 2>&1 && ok "range reachable (${1%/*})" || bad "range ${1%/*} unreachable" "check VPN"
else
  ip -4 addr show tun0 >/dev/null 2>&1 && ok "tun0 up (VPN)" || warn "no tun0 — connect exam VPN, then re-run with CIDR"
fi
nxc --version 2>/dev/null | grep -qE '[0-9]+\.[0-9]+' && ok "nxc runs" || bad "nxc fails to execute"
df -h / | awk 'NR==2{if ($5+0 < 90) print "  \033[32mPASS\033[0m disk " $5 " used"; else print "  \033[31mFAIL\033[0m disk " $5 " used"}'
mkdir -p ~/loot && ok "~/loot ready"

echo
echo "== RESULT: $PASS pass / $WARN warn / $FAIL fail =="
[ "$FAIL" -gt 0 ] && { echo "Fix FAIL items before the window opens (toolkit.md §Provisioning)."; exit 1; }
echo "Kit ready. Initialize state: cp state-template.md ~/loot/engagement-state.md"
