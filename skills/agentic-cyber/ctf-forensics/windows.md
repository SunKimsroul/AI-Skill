# CTF Forensics - Windows

## Table of Contents
- [Windows Event Logs (.evtx)](#windows-event-logs-evtx)
- [Registry Analysis](#registry-analysis)
  - [OEMInformation Backdoor Detection](#oeminformation-backdoor-detection)
- [SAM Database Analysis](#sam-database-analysis)
- [Recycle Bin Forensics](#recycle-bin-forensics)
- [Browser History](#browser-history)
- [Windows Telemetry (imprbeacons.dat)](#windows-telemetry-imprbeaconsdat)
- [Hosts File Hidden Data](#hosts-file-hidden-data)
- [Contact Files (.contact)](#contact-files-contact)
- [WinZip AES Encrypted Archives](#winzip-aes-encrypted-archives)
- [NTFS Alternate Data Streams](#ntfs-alternate-data-streams)
- [NTFS MFT Analysis](#ntfs-mft-analysis)
- [USN Journal ($J) Analysis](#usn-journal-j-analysis)
- [SAM Account Creation Timing](#sam-account-creation-timing)
- [Impacket wmiexec.py Artifacts](#impacket-wmiexecpy-artifacts)
- [PowerShell History as Timeline](#powershell-history-as-timeline)
- [User Profile Creation as First Login Indicator](#user-profile-creation-as-first-login-indicator)
- [RDP Session Event IDs](#rdp-session-event-ids)
- [Windows Defender MPLog Analysis](#windows-defender-mplog-analysis)
- [Anti-Forensics Detection Checklist](#anti-forensics-detection-checklist)
- [Windows Memory Forensics: certutil Base64 ZIP Recovery (SEC-T CTF 2017)](#windows-memory-forensics-certutil-base64-zip-recovery-sec-t-ctf-2017)
- [NTFS EFSTMPWP Folder as cipher.exe Wipe Artifact (Security Fest CTF 2018)](#ntfs-efstmpwp-folder-as-cipherexe-wipe-artifact-security-fest-ctf-2018)
- [Volatility clipboard Plugin for Copy-Paste Secret Recovery (OtterCTF 2018)](#volatility-clipboard-plugin-for-copy-paste-secret-recovery-otterctf-2018)
- [Volatility Credential Recovery Toolkit (OtterCTF 2018)](#volatility-credential-recovery-toolkit-otterctf-2018)

---

## Windows Event Logs (.evtx)

**Key Event IDs:**

| Event ID | Description |
|----------|-------------|
| 1001 | Bugcheck/reboot |
| 41 | Unclean shutdown |
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempted |
| 4726 | User account deleted |
| 4738 | User account changed |
| 4781 | Account name changed (renamed) |

**Parse with python-evtx:**
```python
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml_str = record.xml()
        root = ET.fromstring(xml_str)
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        event_id = root.find('.//ns:EventID', ns).text
        if event_id == '4720':
            data = {}
            for d in root.findall('.//ns:Data', ns):
                data[d.get('Name')] = d.text
            print(f"User created: {data.get('TargetUserName')}")
```

---

## Registry Analysis

```bash
# RegRipper
rip.pl -r NTUSER.DAT -p all

# Key hives
NTUSER.DAT   # User settings
SAM          # User accounts
SYSTEM       # System config
SOFTWARE     # Installed software
```

### OEMInformation Backdoor Detection

**Location:** `SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation`

```python
from Registry import Registry

reg = Registry.Registry("SOFTWARE")
key = reg.open("Microsoft\\Windows\\CurrentVersion\\OEMInformation")
for val in key.values():
    print(f"{val.name()}: {val.value()}")
```

**Malware indicator:** Modified `SupportURL` pointing to C2.

---

## SAM Database Analysis

**Required files:**
- `Windows/System32/config/SAM` - Password hashes
- `Windows/System32/config/SYSTEM` - Boot key

**Extract hashes with impacket:**
```python
from impacket.examples.secretsdump import LocalOperations, SAMHashes

localOps = LocalOperations('SYSTEM')
bootKey = localOps.getBootKey()
sam = SAMHashes('SAM', bootKey)
sam.dump()  # username:RID:LM:NTLM:::
```

**Verify/Crack NTLM:**
```python
from Crypto.Hash import MD4

def ntlm_hash(password):
    h = MD4.new()
    h.update(password.encode('utf-16-le'))
    return h.hexdigest()

# Crack with hashcat
# hashcat -m 1000 hashes.txt wordlist.txt
```

**Common RIDs:**
- 500 = Administrator
- 501 = Guest
- 1000+ = User accounts

---

## Recycle Bin Forensics

**Location:** `$Recycle.Bin\<SID>\`

**File structure:**
- `$R<random>.<ext>` - Actual deleted content
- `$I<random>.<ext>` - Metadata (original path, timestamp)

**Parse $I metadata:**
```python
# strings shows original path
# C.:.\.U.s.e.r.s.\.U.s.e.r.4.\.D.o.c.u.m.e.n.t.s.\.file.docx
```

**Hex-encoded flag fragments:**
```bash
cat '$R_InternSecret.txt'
# Output: 4B4354467B72656330...
echo "4B4354467B72656330..." | xxd -r -p
```

---

## Browser History

**Edge/Chrome (SQLite):**
```python
import sqlite3

history = "Users/<user>/AppData/Local/Microsoft/Edge/User Data/Default/History"
conn = sqlite3.connect(history)
cur = conn.cursor()
cur.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC")
for url, title in cur.fetchall():
    print(f"{title}: {url}")
```

---

## Windows Telemetry (imprbeacons.dat)

**Location:** `Users/<user>/AppData/Local/Packages/Microsoft.Windows.ContentDeliveryManager_*/LocalState/`

```bash
strings imprbeacons.dat | tr '&' '\n' | grep -E "CIP|geo_|COUNTRY"
```

**Key fields:** `CIP` (client IP), `geo_lat/long`, `COUNTRY`, `SMBIOSDM`

---

## Hosts File Hidden Data

**Location:** `Windows/System32/drivers/etc/hosts`

Attackers hide data with excessive whitespace:
```bash
# Detect hidden content
xxd hosts | tail -20
```

---

## Contact Files (.contact)

**Location:** `Users/<user>/Contacts/*.contact`

**Hidden data in Notes:**
```xml
<c:Notes>h1dden_c0ntr4ct5</c:Notes>
```

---

## WinZip AES Encrypted Archives

```bash
# Extract hash
zip2john encrypted.zip > zip_hash.txt

# Crack with hashcat (mode 13600)
hashcat -m 13600 zip_hash.txt wordlist.txt

# Hybrid: word + 4 digits
hashcat -m 13600 zip_hash.txt wordlist.txt -a 6 '?d?d?d?d'
```

---

## NTFS Alternate Data Streams

**Pattern:** NTFS supports multiple data streams per file. The default stream stores normal file content, but additional named streams (Alternate Data Streams / ADS) can hide arbitrary data invisibly. `dir`, Explorer, and most tools only show the default stream.

**Detection and enumeration:**

```bash
# On a mounted NTFS volume (Linux):
getfattr -R -n ntfs.streams.list /mnt/ntfs/     # List all streams on all files

# Using Sleuth Kit on a raw NTFS image (best for forensics):
fls -r ntfs_image.dd                              # Recursive file listing
fls -r ntfs_image.dd | grep -i ":"                # ADS entries contain ":"
# Output: r/r 66-128-4: Documents/credentials.txt:hidden_flag.jpg

# Extract ADS by inode — find inode first:
istat ntfs_image.dd 66                            # Show all attributes for inode 66
# Look for $DATA attributes with names (e.g., $DATA "hidden_flag.jpg")

icat ntfs_image.dd 66-128-4 > hidden_flag.jpg    # Extract ADS by full address

# Using ntfsstreams (part of ntfs-3g):
ntfs_streams_list /dev/sda1
```

**On Windows (live analysis):**

```powershell
# List ADS on a file
Get-Item -Path C:\file.txt -Stream *

# Read ADS content
Get-Content -Path C:\file.txt -Stream hidden_data

# dir /r shows ADS (Windows Vista+)
dir /r C:\Users\suspect\Documents\

# Common ADS names to check:
# Zone.Identifier — marks files downloaded from the internet
# (contains ZoneId, ReferrerUrl, HostUrl)
Get-Content -Path C:\file.exe -Stream Zone.Identifier
```

**Python extraction from raw NTFS image:**

```python
# Using pytsk3 (Python bindings for Sleuth Kit)
import pytsk3

img = pytsk3.Img_Info("ntfs_image.dd")
fs = pytsk3.FS_Info(img)

# Walk all files and check for ADS
for entry in fs.open_dir("/"):
    for attr in entry:
        if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA:
            name = attr.info.name or "(default)"
            if name != "(default)":
                print(f"ADS found: {entry.info.name.name}/{name} "
                      f"(size: {attr.info.size})")
                # Read ADS content
                data = entry.read_random(0, attr.info.size, attr.info.type, attr.info.id)
```

**Key insight:** ADS are invisible to `dir` (without `/r`), Explorer, and most forensic tools that only check default data streams. The Sleuth Kit's `fls` with the colon notation (`inode-type-id`) is the most reliable way to enumerate and extract ADS from images. Malware uses ADS to hide payloads; CTF challenges use them to hide flags. The `Zone.Identifier` stream is the most common ADS — it's automatically added by browsers and email clients to downloaded files.

**When to recognize:** Challenge provides an NTFS image, mentions "hidden data", "hidden in plain sight", or "alternate streams". Credentials files or documents that seem too simple may have ADS attached. Always run `fls -r image.dd | grep ":"` on any NTFS forensics challenge.

**References:** Google CTF 2019 "Home Computer", TCP1P CTF 2023 "hide and split", De1CTF 2019 "DeeplnReal"

---

## NTFS MFT Analysis

**Location:** `C:\$MFT` (Master File Table)

**Key techniques:**
- Filenames are stored in UTF-16LE in the MFT
- Each file has two timestamp sets: `$STANDARD_INFORMATION` (user-modifiable) and `$FILE_NAME` (system-controlled)
- Timestomping detection: Compare SI vs FN timestamps; if SI dates are much older than FN dates, the file was timestomped

```python
# Search MFT for filenames (binary file, use strings)
# ASCII:
# strings $MFT | grep -i "suspicious"
# UTF-16LE:
# strings -el $MFT | grep -i "suspicious"

# MFT record structure (1024 bytes each, starting at offset 0):
# - Offset 0x00: "FILE" signature
# - Attribute 0x30 ($FILE_NAME): Contains FN timestamps (reliable)
# - Attribute 0x10 ($STANDARD_INFORMATION): Contains SI timestamps (modifiable)
```

---

## USN Journal ($J) Analysis

**Location:** `C:\$Extend\$J` (Update Sequence Number Journal)

Tracks all file system changes. Critical when event logs are cleared.

```python
import struct, datetime

def parse_usn_record(data, offset):
    """Parse USN_RECORD_V2 at given offset"""
    rec_len = struct.unpack_from('<I', data, offset)[0]
    major = struct.unpack_from('<H', data, offset + 4)[0]  # Must be 2
    file_ref = struct.unpack_from('<Q', data, offset + 8)[0] & 0xFFFFFFFFFFFF
    parent_ref = struct.unpack_from('<Q', data, offset + 16)[0] & 0xFFFFFFFFFFFF
    timestamp = struct.unpack_from('<Q', data, offset + 32)[0]
    reason = struct.unpack_from('<I', data, offset + 40)[0]
    file_attr = struct.unpack_from('<I', data, offset + 52)[0]
    fn_len = struct.unpack_from('<H', data, offset + 56)[0]
    fn_off = struct.unpack_from('<H', data, offset + 58)[0]  # Usually 60
    filename = data[offset + fn_off:offset + fn_off + fn_len].decode('utf-16-le')
    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp // 10)
    return dt, filename, reason, file_attr, parent_ref

# USN Reason flags:
# 0x1=DATA_OVERWRITE, 0x2=DATA_EXTEND, 0x4=DATA_TRUNCATION
# 0x100=FILE_CREATE, 0x200=FILE_DELETE, 0x1000=NAMED_DATA_OVERWRITE
# 0x80000000=CLOSE
```

**Key forensic uses:**
- Find file creation/deletion times even when logs are cleared
- Track wmiexec.py output files (`__<timestamp>.<random>`)
- Determine when PowerShell history was written (timeline of commands)
- Detect user profile creation (first interactive login time)

---

## SAM Account Creation Timing

When Security event logs (EventID 4720) are cleared, determine account creation time from the SAM registry:

```python
from regipy.registry import RegistryHive

sam = RegistryHive('SAM')
# Navigate to: SAM\Domains\Account\Users\Names\<username>
# The key's last_modified timestamp = account creation time
names_key = sam.get_key('SAM\\Domains\\Account\\Users\\Names')
for subkey in names_key.iter_subkeys():
    print(f"{subkey.name}: created {subkey.header.last_modified}")
```

---

## Impacket wmiexec.py Artifacts

**wmiexec.py** is a popular remote command execution tool using WMI. Key artifacts:

1. **Output files:** Creates `__<unix_timestamp>.<random>` in `C:\Windows\` (ADMIN$ share)
   - File is created, written with command output, read back, then deleted
   - Each command execution creates a new cycle
   - USN journal preserves create/delete timestamps even after file deletion

2. **WMI Provider Host:** `WMIPRVSE.EXE` prefetch file confirms WMI usage

3. **Timeline reconstruction:** Count USN create-delete cycles for the output file to determine number of commands executed

```python
# Search for wmiexec output files in MFT
# strings -el $MFT | grep -E '^__[0-9]{10}'
# The unix timestamp in the filename = approximate execution start time
```

---

## PowerShell History as Timeline

**Location:** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

PSReadLine writes commands incrementally. **USN journal DATA_EXTEND events on this file correspond to individual command executions:**

```text
08:05:19 - FILE_CREATE + DATA_EXTEND → First command entered
08:05:50 - DATA_EXTEND → Second command entered
08:09:57 - DATA_EXTEND → Third command entered
```

This provides exact execution timestamps for each command even when PowerShell logs are cleared.

---

## User Profile Creation as First Login Indicator

When event logs are cleared, the user profile directory creation in USN journal reveals the first interactive login:

```python
# Search USN journal for username directory creation
# Reason flag 0x100 (FILE_CREATE) with parent ref matching C:\Users (MFT ref 512)
# Example: ithelper DIR FILE_CREATE parent=512 at 08:03:51
# → First login (RDP/console) was at approximately 08:03
```

**Key insight:** User profiles are only created on first interactive logon (RDP or console), not via WMI/wmiexec remote execution.

---

## RDP Session Event IDs

**TerminalServices-LocalSessionManager\Operational:**

| Event ID | Description |
|----------|-------------|
| 21 | Session logon succeeded |
| 22 | Shell start notification received |
| 23 | Session logoff succeeded |
| 24 | Session disconnected |
| 25 | Session reconnection succeeded |
| 40 | Session created |
| 41 | Session begin (user notification) |
| 42 | Shell start (user notification) |

**TerminalServices-RemoteConnectionManager\Operational:**

| Event ID | Description |
|----------|-------------|
| 261 | Listener received connection |
| 1149 | RDP user authentication succeeded (contains source IP) |

**RemoteDesktopServices-RdpCoreTS\Operational:**

| Event ID | Description |
|----------|-------------|
| 131 | Connection accepted (TCP, contains ClientIP:port) |
| 102 | Connection from client |
| 103 | Disconnected (check ReasonCode) |

---

## Windows Defender MPLog Analysis

**Location:** `C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log`

Rich source of threat detection timeline, even when other logs are cleared:

```bash
# Find threat detections
grep -i "DETECTION\|THREAT\|QUARANTINE" MPLog*.log

# Find ASR (Attack Surface Reduction) rule activity
grep -i "ASR\|Process.*Block" MPLog*.log

# Key ASR rules (indicators of attack attempts):
# - "Block Process Creations originating from PSExec & WMI commands"
# - "Block credential stealing from lsass.exe"
```

**Detection History files:** `C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\`
- Binary files containing SHA256, file paths, and detection names
- Parse with `strings` to extract IOCs

---

## Anti-Forensics Detection Checklist

When event logs are cleared (attacker used `wevtutil cl` or `Clear-EventLog`):

1. **USN Journal** - Survives log clearing; shows file operations timeline
2. **SAM registry** - Account creation timestamps preserved
3. **PowerShell history** - ConsoleHost_history.txt often survives
4. **Prefetch files** - Shows executed programs (C:\Windows\Prefetch\)
5. **MFT** - File metadata preserved even for deleted files
6. **Defender MPLog** - Separate from Windows event logs, often not cleared
7. **RDP event logs** - TerminalServices logs are separate from Security.evtx
8. **WMI repository** - C:\Windows\System32\wbem\Repository\OBJECTS.DATA
9. **Browser history** - SQLite databases in user AppData
10. **Registry timestamps** - Key last_modified times reveal activity

**Security.evtx EventID 1102** = "The audit log was cleared" (ironically logged even during clearing)

---

## Windows Memory Forensics: certutil Base64 ZIP Recovery (SEC-T CTF 2017)

Volatility memory dump analysis where `psxview` reveals hidden cmd/powershell processes. A malware batch script uses `bitsadmin` to download and `certutil -decode` to base64-decode payloads. Search memory for `UEsD` (the base64 encoding of ZIP magic `PK\x03`) to find in-transit base64 archives, then decode to recover ZIP contents including registry entries.

```bash
# Step 1: Find hidden processes (psxview compares multiple process lists)
vol.py -f dump.raw --profile=Win7SP1x64 psxview

# Step 2: Dump suspicious process memory
vol.py -f dump.raw --profile=Win7SP1x64 procdump -p <PID> -D ./dumps/

# Step 3: Scan raw memory for base64-encoded ZIP archives
# UEsD = base64("PK\x03") — ZIP magic bytes encoded in base64
strings dump.raw | grep -o 'UEsD[A-Za-z0-9+/=]*' > candidates.txt

# Step 4: Decode each candidate
python3 -c "
import base64, sys
with open('candidates.txt') as f:
    for line in f:
        line = line.strip()
        # Pad to valid base64 length
        padded = line + '=' * (-len(line) % 4)
        try:
            data = base64.b64decode(padded)
            if data[:4] == b'PK\x03\x04':
                with open('recovered.zip', 'wb') as out:
                    out.write(data)
                print('ZIP recovered')
                break
        except Exception:
            pass
"

# Step 5: Extract ZIP contents
unzip recovered.zip
```

**Malware indicators to look for:**
- `bitsadmin /transfer` — background download without browser
- `certutil -decode input.b64 output.exe` — base64 decode abuse
- Batch files (`.bat`, `.cmd`) in unusual locations (`%TEMP%`, `%APPDATA%`)
- Registry exports (`.reg` files) inside ZIP payloads

**Key insight:** `certutil` is commonly abused by malware for base64 decoding as a living-off-the-land technique. `UEsD` is the base64 encoding of ZIP magic bytes `PK\x03` — use it as a memory scanning signature to find in-transit ZIP archives before they are written to disk or after they are deleted.

---

## NTFS EFSTMPWP Folder as cipher.exe Wipe Artifact (Security Fest CTF 2018)

**Pattern (Mr.reagan):** An NTFS image contains `$RECYCLE.BIN` but also a sparsely-used hidden directory named `EFSTMPWP`. This directory is created by `cipher.exe /w` — Windows' built-in tool for overwriting the free space of a volume — to hold the temporary files used for the multi-pass wipe. Its presence means the suspect ran a secure-erase command, so file recovery of deleted data is unlikely to succeed.

**Detection:**
```bash
# Mount the NTFS image read-only
sudo mount -o ro,loop,show_sys_files image.dd /mnt/ntfs

# Look for the wipe artifact
find /mnt/ntfs -maxdepth 2 -iname 'EFSTMPWP' -o -iname '$Recycle.Bin'

# MFT entry also records the directory with `cipher.exe` as the creator process
mft_parser -i image.dd -o mft.csv
grep -i 'EFSTMPWP' mft.csv
```

**Implications:**
- Do not waste time on carving for deleted user data in the free space; it has been overwritten.
- Switch focus to alternate persistence paths: `$Recycle.Bin` contents, NTFS journal ($LogFile / $UsnJrnl), Volume Shadow Copies, and MFT resident data.
- Check `Event Log` (`Security.evtx`, `Microsoft-Windows-Application-Experience%4Program-Inventory.evtx`) for `cipher.exe` execution timestamps — they anchor the anti-forensics timeline.

**Key insight:** Secure-erase tools leave their own filesystem fingerprints. `cipher.exe /w` creates `EFSTMPWP`; `sdelete` creates files named after the wiped target with a `.ZZZ`-style extension; BleachBit leaves `~BleachBit*.tmp`. Grep for these artifact names before launching any recovery job — they tell you whether recovery is even worth attempting.

**References:** Security Fest CTF 2018 — writeup 10206

---

## Volatility clipboard Plugin for Copy-Paste Secret Recovery (OtterCTF 2018)

**Pattern:** Users copy passwords / keys / flags into the clipboard. Windows keeps clipboard data live in memory even after the source application closes. Volatility's `clipboard` plugin enumerates `CF_UNICODETEXT` / `CF_TEXT` buffers and prints the most recent copy-paste content verbatim.

```bash
vol.py -f memory.vmem --profile=Win7SP1x64 clipboard
# Volatility 3:
vol -f memory.vmem windows.clipboard
```

**Key insight:** Before spending hours carving LSASS or walking process heaps, run `clipboard` — CTF challenges about "Silly Rick copied his password" always surface here. Combine with `cmdline`, `consoles`, and `filescan` for full user-activity reconstruction.

**References:** OtterCTF 2018 — Silly Rick, writeup 12596

---

## Volatility Credential Recovery Toolkit (OtterCTF 2018)

**Pattern:** One memory dump, a shopping list of Volatility plugins to try in order:

```bash
# 1. Recent copy-pasted passwords
vol.py -f dump.vmem --profile=Win7SP1x64 clipboard

# 2. Loaded plugins: mimikatz (third-party) — plaintext wdigest creds
vol.py --plugins=./plugin/ -f dump.vmem --profile=Win7SP1x64 mimikatz

# 3. NTLM / LM hashes from SAM hive
vol.py -f dump.vmem --profile=Win7SP1x64 hivelist          # find SAM offset
vol.py -f dump.vmem --profile=Win7SP1x64 hashdump -y SYSTEM_off -s SAM_off

# 4. Registry values (computer name, policies)
vol.py -f dump.vmem --profile=Win7SP1x64 printkey \
    -K 'ControlSet001\Control\ComputerName\ComputerName'

# 5. Process memory carving: dump and grep for patterns
vol.py -f dump.vmem --profile=Win7SP1x64 memdump -p 3720 -D out/
strings out/3720.dmp | grep -iE 'pass|flag'

# 6. Network connection artifacts
vol.py -f dump.vmem --profile=Win7SP1x64 netscan

# 7. Process tree and loaded DLLs for malware triage
vol.py -f dump.vmem --profile=Win7SP1x64 pstree
vol.py -f dump.vmem --profile=Win7SP1x64 dlllist -p PID
```

**Key insight:** Don't hunt with `strings` alone. The Volatility plugin suite has a plugin for every artifact: clipboard, mimikatz (plaintext), hashdump (hashes), printkey (registry), memdump (per-process memory), netscan (sockets), pstree (process hierarchy), dlllist (loaded modules). Run them in order from cheapest to most expensive.

**References:** OtterCTF 2018 — multiple challenges, writeups 12569–12572, 12596

## RDP bitmap cache reconstruction with bmc-tools

**Trigger:** An evidence bundle contains a file named `Cache0000.bin` / `bcache*.bmc`, or any blob whose first bytes are the ASCII string `RDP8bmp`, or the collection path includes `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\`. Also reach for it whenever a challenge asks what an attacker *saw on screen* during a remote session.

The Windows RDP client caches screen tiles locally so it does not retransmit unchanged regions. Those tiles persist on disk per-user and are effectively a partial screen recording of every remote session — credentials, wallet seed phrases, document contents, anything the user displayed. ANSSI's `bmc-tools` parses the cache and dumps every 64x64 tile as a PNG, and the `-b` flag also emits a collage of all tiles in file order. The collage is usually enough to read text directly; tiles arrive roughly in paint order, so lines of text tend to survive as readable horizontal runs even though the layout is scrambled. A single cache file routinely yields a few thousand tiles, so skim the collage rather than the individual PNGs. Identify the artifact by the `RDP8bmp` magic — `file(1)` reports it as data and neither browser-history nor wallet-database tooling will touch it.

```bash
git clone https://github.com/ANSSI-FR/bmc-tools.git
python3 bmc-tools/bmc-tools.py -s Cache_dir -d rdp_tiles -b -v
```

Source: https://cybersecurityelite.com/ctf-writeups/r3ctf-2026-writeup/

## Jump List and Recent-folder LNK parsing for file access proof

**Trigger:** You have a disk image or KAPE triage collection and need to prove a user opened a specific file, or the file itself is gone (deleted, on removed USB media, or on an unmounted network share) and you need its original path, size, and timestamps.

Shortcut artifacts survive the deletion of what they point at, which makes them the fastest way to reconstruct file access from a triage set. Pull C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk for automatically-created shortcuts to every recently opened document. Each .lnk embeds the full target path, the target's size and MAC timestamps as they were at access time, the volume serial number, and the drive type — so a .lnk whose volume serial does not match any partition in the image is direct evidence of a removable drive, and a UNC target names a share the box touched. Then parse the two Jump List directories under the same Recent folder: AutomaticDestinations (OLE compound files, one per application, named by an AppID hash) and CustomDestinations (application-pinned entries). Inside an AutomaticDestinations file each numbered stream is an embedded LNK, and the DestList stream is an MRU-ordered index that gives you access counts and last-access times per entry — that ordering is what turns a pile of paths into a timeline. Map the AppID filename against a public AppID list to learn which program did the opening; an AppID for a browser or archive tool next to a payload path ties execution to delivery. Parse with lnkparse/pylnk3 for individual shortcuts and LECmd/JLECmd for the Jump List containers, or fall back to `strings -el` on the compound file when tooling is unavailable. Cross-check what you recover against Prefetch and the MFT rather than trusting a single artifact.

```bash
# Recent-folder shortcuts (target path, volume serial, drive type, MAC times)
lnkparse ~/case/Users/victim/AppData/Roaming/Microsoft/Windows/Recent/report.lnk
python3 -c "import pylnk3,sys;print(pylnk3.parse(sys.argv[1]))" recent.lnk

# Jump Lists — AutomaticDestinations is an OLE compound file of embedded LNKs + a DestList MRU stream
JLECmd.exe -d "C:\Users\victim\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv out\
LECmd.exe  -d "C:\Users\victim\AppData\Roaming\Microsoft\Windows\Recent" --csv out\

# No tooling: enumerate embedded streams / pull UTF-16LE paths
python3 -c "import olefile;f=olefile.OleFileIO('1b4dd67f29cb1962.automaticDestinations-ms');print(f.listdir())"
strings -el *.automaticDestinations-ms | grep -Ei '\\\\|\.docx|\.exe|\.zip'

# Volume serial in a .lnk that matches no partition in the image => removable media
fsstat -o <offset> image.dd | grep -i 'serial'
```

Source: https://offsecexams.com/cheatsheets/btl1-exam---guided-by-redblock

## DeepBlueCLI first-pass triage of an EVTX set

**Trigger:** You are handed a pile of .evtx files (or a live Windows box in a challenge) and have no idea which of the hundreds of thousands of records matter — you need a ranked starting point before hand-parsing anything.

Before writing python-evtx loops, run a rules-based EVTX triage pass to tell you where to look. DeepBlueCLI is a self-contained PowerShell script that walks Security, System, Application, PowerShell/Operational, Sysmon, and AppLocker logs and emits only records matching known-bad patterns: base64/encoded and obfuscated PowerShell command lines (it decodes -EncodedCommand for you rather than leaving you the blob), unusually long command lines, service installs from suspicious paths, account creation and admin-group additions, password-spray and brute-force bursts, log clearing, and process-creation entries with attacker tooling. Point it at a file with `.\DeepBlue.ps1 <path>.evtx` or at a live log by name with `.\DeepBlue.ps1 -log security`. Treat its output as a lead list, not a verdict: every hit is a record ID and timestamp you then pull in full and correlate against Prefetch, MFT/USN, and PowerShell history using the workflow already in this file. Its main forensic value is that it recovers the plaintext of encoded PowerShell that would otherwise need manual base64/UTF-16LE decoding, and that it flags the interesting minute in a multi-day log so your timeline has a seed. It runs offline on exported logs, so it works on triage collections. Sibling tools with the same role and richer Sigma-backed rule sets are Chainsaw, Hayabusa, and EvtxECmd + Zircolite — reach for those when you need coverage beyond DeepBlue's fixed heuristics.

```bash
# offline, against exported logs from a triage collection
.\DeepBlue.ps1 .\Security.evtx
.\DeepBlue.ps1 .\Microsoft-Windows-PowerShell%4Operational.evtx

# against live logs by name
.\DeepBlue.ps1 -log security
.\DeepBlue.ps1 -log system

# keep the hits for correlation
.\DeepBlue.ps1 .\Security.evtx | Export-Csv -NoTypeInformation deepblue.csv

# broader Sigma-backed alternatives on the same input
chainsaw hunt ./evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
hayabusa csv-timeline -d ./evtx/ -o timeline.csv

# then pull the flagged record in full
python3 -c "import Evtx.Evtx as e;[print(r.xml()) for r in e.Evtx('Security.evtx').records() if r.record_num()==<N>]"
```

Source: https://offsecexams.com/cheatsheets/btl1-exam---guided-by-redblock

## Unbacked call frames in Sysmon ProcessAccess (ID 10) to LSASS

**Trigger:** You are triaging a credential-theft allegation and the Sysmon log has ID 10 events targeting lsass.exe, or LSASS access events are so numerous that legitimate AV/OS noise buries the real one.

ID 10 records one process opening a handle to another and, crucially, includes a CallTrace: the stack of modules that led to the OpenProcess call. Normal callers resolve every frame to a module on disk, so the trace reads as a chain of `ntdll.dll+...`/`kernelbase.dll+...` entries. Shellcode and reflectively-loaded modules execute from private memory that maps to no file, so those frames render as `UNKNOWN(0x...)` — an unbacked frame in a trace ending at LSASS is the strongest single indicator of injected code dumping credentials, and it holds regardless of what the calling process is named. Filter the noise before judging: exclude JIT-compiled managed code (`clr.dll`, `mscorlib.ni.dll`, anything under Microsoft.NET), WOW64 thunks, and Explorer, all of which legitimately produce UNKNOWN frames, then drop self-access where SourceImage equals TargetImage. Also read GrantedAccess as a severity signal — a mask including PROCESS_VM_READ (0x10) plus query rights, classically 0x1010 or 0x1410, means the caller intended to read LSASS memory rather than merely query it. Pair a surviving hit with the corresponding ID 11 file create to find where the minidump landed.

```powershell
# Splunk: everything touching lsass, then strip the known-benign UNKNOWN producers
index=main EventCode=10 TargetImage="*lsass.exe"
| search CallTrace="*UNKNOWN*"
  SourceImage!="*Microsoft.NET*" CallTrace!="*clr.dll*" CallTrace!="*ni.dll*"
  CallTrace!="*wow64*" SourceImage!="C:\\Windows\\Explorer.EXE"
| where SourceImage!=TargetImage
| stats count by SourceImage, GrantedAccess, CallTrace

# Offline equivalent over a saved EVTX
Get-WinEvent -Path .\Sysmon.evtx -FilterXPath "*[System[EventID=10]]" | ForEach-Object {
  $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data|%{$d[$_.Name]=$_.'#text'}; $d
} | Where-Object {
  $_.TargetImage -like '*lsass.exe' -and $_.CallTrace -match 'UNKNOWN' -and
  $_.CallTrace -notmatch 'clr\.dll|ni\.dll|wow64' -and $_.SourceImage -ne $_.TargetImage
} | Select SourceImage, GrantedAccess, CallTrace

# Then find the dump the handle was used to write
... EventCode=11 | search TargetFilename="*.dmp" OR TargetFilename="*lsass*"
```

Source: https://offsecexams.com/cheatsheets/cdsa-exam---guided-by-redblock

## Windows execution-evidence artifact hierarchy (UserAssist, ShimCache, BAM, SRUM, Prefetch internals, ActivitiesCache)

**Trigger:** You have a registry hive set or triage collection and need to prove a binary ran, when, how many times, or by which user — and Prefetch is empty, disabled (servers default off), or the attacker deleted it.

No single Windows artifact answers "did it run"; each one answers a different question, and the discriminating logic matters more than the parser command. AppCompatCache (ShimCache) in the SYSTEM hive records path, $STANDARD_INFORMATION modified time and size for binaries the shim engine merely *examined* — presence there is evidence of existence on disk, NOT of execution, and it is the single most misread artifact; it is also written to the hive only at shutdown, so a live-acquired hive lags. UserAssist under NTUSER.DAT is the opposite: it only records GUI-launched programs, per user, ROT13-encoded value names, with a run counter and last-execution timestamp — so it proves a human double-clicked something, and its absence for a binary suggests script or service invocation. BAM/DAM under SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID> gives last-execution time keyed by user SID, which is the cheapest way to bind an execution to an account. SRUM (C:\Windows\System32\sru\SRUDB.dat, an ESE database) is the exfiltration artifact: it holds per-process bytes-sent/bytes-received per network interface in hourly buckets, so it can quantify a data theft even when the pcap is gone. Prefetch's internal structure is the richest single file — each .pf holds up to eight last-run timestamps, a run count, and the full list of files and directories the process touched in its first ten seconds, which reveals the payload path a dropper opened. Windows Timeline (ActivitiesCache.db per user, an SQLite file parsed by WxTCmd) survives on hosts where Prefetch is off and records application focus with start/end times. Build the chain by correlating them: ShimCache says the file existed, UserAssist or BAM says who ran it, Prefetch says what it opened, SRUM says how much it shipped out.

```bash
# ShimCache (existence, not execution) — SYSTEM hive
AppCompatCacheParser.exe -f SYSTEM --csv out\ --csvf shimcache.csv
python ShimCacheParser.py -i SYSTEM -o shimcache.csv

# UserAssist (GUI launches, ROT13 value names) — NTUSER.DAT
# NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
python3 -c "import codecs;print(codecs.decode('{QNIR}\\pzq.rkr','rot13'))"

# BAM/DAM (last execution per SID) — SYSTEM hive
# SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>

# SRUM (per-process network bytes sent/received, hourly)
SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv out\ --csvf srum.csv

# Prefetch: run count, 8 timestamps, referenced-file list
PECmd.exe -d C:\Windows\Prefetch --csv out\ --csvf prefetch.csv

# Windows Timeline (per-user SQLite)
WxTCmd.exe -f "C:\Users\<u>\AppData\Local\ConnectedDevicesPlatform\L.<u>\ActivitiesCache.db" --csv out\
```

Source: https://offsecexams.com/cheatsheets/ccd---l1-exam---guided-by-redblock

## Shell-item artifacts: ShellBags, LNK targets, and JumpLists for vanished paths

**Trigger:** You need to prove a user opened a file or folder that no longer exists on the image — content on a removed USB stick, a mapped share, a wiped staging directory, or a deleted exfil archive.

Shell items are the artifact class that outlives the files they describe, which makes them the answer whenever the evidence path is gone. ShellBags live in UsrClass.dat under Local Settings\Software\Microsoft\Windows\Shell\BagMRU (and NTUSER.DAT for older paths) and record every folder the user browsed in Explorer, including removable-drive and UNC paths, with the folder's own MFT entry number and creation/modified times embedded in the shell item — so a BagMRU entry for E:\exfil proves the user navigated a directory tree that never existed on this disk. LNK files in AppData\Roaming\Microsoft\Windows\Recent are far more than shortcuts: each carries the target's full path, size, the three target timestamps as of last access, the volume serial number, the drive type, and frequently the source machine's NetBIOS name and MAC address from the tracker block — enough to attribute a file to a specific removable device or a specific remote host. JumpLists carry the same shell-item payload but keyed by application: AutomaticDestinations files are named by an AppID hash identifying the program, and their internal structure is an OLE compound file where each stream is an embedded LNK, so a 7-Zip or PuTTY JumpList enumerates exactly which archives or hosts that tool touched. CustomDestinations are the pinned/task entries and are a flat concatenation of LNK structures. Practically: parse all three, then join on volume serial number to cluster activity by physical device, and on target path to reconstruct the staging directory an attacker built and deleted. Timestamps in shell items are snapshots taken at access time, not live values, so they can be older than the MFT and that discrepancy is itself evidence.

```bash
# ShellBags (browsed folders, incl. removable and UNC)
# C:\Users\<u>\AppData\Local\Microsoft\Windows\UsrClass.dat
#   Local Settings\Software\Microsoft\Windows\Shell\BagMRU
ShellBagsExplorer / SBECmd.exe -d C:\Users\<u>\AppData\Local\Microsoft\Windows --csv out\

# LNK: target path, volume serial, drive type, tracker MAC/hostname
LECmd.exe -d "C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent" --csv out\ --csvf lnk.csv

# JumpLists (AppID hash = the application)
JLECmd.exe -d "C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv out\
JLECmd.exe -d "...\Recent\CustomDestinations" --csv out\

# Linux-side parsing
python3 -c "import LnkParse3,sys;print(LnkParse3.lnk_file(open(sys.argv[1],'rb')).get_json())" file.lnk
olevba/oledump.py -s a AutomaticDestinations\<appid>.automaticDestinations-ms  # streams are LNKs
```

Source: https://offsecexams.com/cheatsheets/ccd---l1-exam---guided-by-redblock

