# Zone 4 — IoT & Firmware analysis

Prior range: `172.25.120.0/24` (excl `.250`). Two SSH analysis hosts hold `.bin`
firmware images (given creds, e.g. `ubuntu/toor`, `cpent/cpentpw`).
Full evidence (PRIVATE, do not share): `~/.config/opencode/skills/cpent-exam/private/CPENT_IoT_Methodology.md`.
Load with: `ctf-reverse`. Tools: see toolkit.md §5 — **install binwalk first**.

## Workflow per image

```bash
binwalk <image>.bin          # signature scan — answers MOST questions alone
binwalk -e <image>.bin       # carve; extracted files are named by HEX OFFSET
cd _<image>.bin.extracted/   # squashfs-root/ if SquashFS present
file *; strings <f> | grep -iE 'version|gcc|busybox|linux'
```

Question archetypes map directly onto binwalk output lines:

| Question asks | Where it lives |
|---|---|
| Block size | SquashFS line: `blocksize: 65536 bytes` |
| CPU architecture | uImage header: `CPU: Blackfin` / MIPS / ARM |
| Linux version | uImage `image-name: Linux-2.6.26.5-…` or `strings vmlinux` |
| File format of carved file N | `file N` (binwalk names files BY OFFSET — `813682`, `D8232C`) |
| Offset of file X | the carved filename itself, or the binwalk entry column |
| File system type | SquashFS / JFFS2 / CramFS signature lines (extraction tool missing ≠ unknown FS) |
| Image size | TRX header: `image size: 7753728 bytes` |
| FS start address | offset column of the SquashFS/JFFS2 signature line |
| BusyBox version | `strings squashfs-root/bin/busybox \| grep -i "busybox v"` |
| GCC version at offset X | `strings X* \| grep -i gcc` (kernel banner strings) |
| Device IP in a DB | `find . -name "*.sqlite"` → `strings db \| grep -i <devicename>` |
| Device model | `grep -i DeviceID */cgi-bin/router-info.asp`, `cat firmware_version` |
| Root password file | `find . \( -name passwd -o -name shadow \)` → check `usr/etc/passwd` (when `/etc` is a runtime symlink into `/tmp`, the persistent copy is `usr/etc/`) |

## Firmware families seen (recon shortcuts)

- **TRX header** (Broadcom/D-Link/Netgear): TRX + SquashFS v3, non-standard
  signature (needs sasquatch), CRC32 field, image-size question.
- **uImage** (U-Boot): header itself states CPU arch + image name (Linux version).
- **SquashFS v4.0 LZMA**: modern MIPS routers; standard unsquashfs often handles it.
- **JFFS2**: raw NAND image; `jefferson` extracts, but the signature line alone
  answers "which filesystem" questions.
- **Layered**: gzip → xz → ELF ARM object files inside.

## Credential hunting inside extracted roots

```bash
grep -rl 'admin\|root' --include='passwd' --include='shadow' .
cat usr/etc/passwd           # MD5-crypt hashes, possibly EMPTY SALT ($1$$hash)
grep -rhoE 'psk=[^\n]*|password=[^\n]*' etc/config/ 2>/dev/null
sqlite3 mnt/config.sqlite 'select * from lan;'   # device IP / netmask / hostname
strings mnt/config.sqlite | grep -iE 'pass|key'
```

Record every hard-coded credential in the answer table AND the report's findings —
they are also exam points ("file containing root password" style questions).

## Gotchas

- `binwalk -e` names carved files by hex offset — a question showing `D8232C` is
  literally asking you to find that file in the extraction directory.
- Extraction warning "jefferson not installed" still leaves the JFFS2 *signature*
  in `binwalk <image>` output — answerable without extracting.
- Multiple images per host: answer all signature-scan questions across every image
  FIRST (cheap points), then extract only what deeper questions need.
- Same image under two names across hosts (prior: IOT.bin == FileOne.bin) — hash
  them (`md5sum`) to avoid re-analyzing.
