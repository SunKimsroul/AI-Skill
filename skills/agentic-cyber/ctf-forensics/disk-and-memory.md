# CTF Forensics - Disk and Memory Analysis

## Table of Contents
- [Memory Forensics (Volatility 3)](#memory-forensics-volatility-3)
- [Disk Image Analysis](#disk-image-analysis)
- [VM Forensics (OVA/VMDK)](#vm-forensics-ovavmdk)
- [VMware Snapshot Forensics](#vmware-snapshot-forensics)
- [GIMP Raw Memory Dump Visual Inspection (INShAck 2018)](#gimp-raw-memory-dump-visual-inspection-inshack-2018)
- [Coredump Analysis](#coredump-analysis)
- [Windows KAPE Triage Analysis (UTCTF 2026)](#windows-kape-triage-analysis-utctf-2026)
- [PowerShell Ransomware Analysis](#powershell-ransomware-analysis)
- [Android Forensics](#android-forensics)
- [Container Forensics (Docker)](#container-forensics-docker)
- [Cloud Storage Forensics (AWS S3 / GCP / Azure)](#cloud-storage-forensics-aws-s3--gcp--azure)
- [Public GCS Bucket Object-Listing Triage (UofTCTF 2024)](#public-gcs-bucket-object-listing-triage-uoftctf-2024)
- [BSON (Binary JSON) Format Reconstruction (IceCTF 2016)](#bson-binary-json-format-reconstruction-icectf-2016)
- [TrueCrypt / VeraCrypt Volume Mounting (GreHack CTF 2016)](#truecrypt--veracrypt-volume-mounting-grehack-ctf-2016)
- [Volatility mftparser Offset-Based Deleted File Recovery (BSides Delhi 2018)](#volatility-mftparser-offset-based-deleted-file-recovery-bsides-delhi-2018)
- [Brotli Blob Detection via ASCII-Art Signature (ASIS Finals 2018)](#brotli-blob-detection-via-ascii-art-signature-asis-finals-2018)
- [corkami/pocs MD5 PDF Collision Generation (35C3 2018)](#corkamipocs-md5-pdf-collision-generation-35c3-2018)
- [See Also](#see-also)

---

## Memory Forensics (Volatility 3)

```bash
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.netscan
vol3 -f memory.dmp windows.filescan
vol3 -f memory.dmp windows.dumpfiles --physaddr <addr>
vol3 -f memory.dmp windows.mftscan | grep flag
```

**Common plugins:**
- `windows.pslist` / `windows.pstree` - Process listing
- `windows.cmdline` - Command line arguments
- `windows.netscan` - Network connections
- `windows.filescan` - File objects in memory
- `windows.dumpfiles` - Extract files by physical address
- `windows.mftscan` - MFT FILE objects in memory (timestamps, filenames). Note: `mftparser` was Volatility 2 only; Vol3 uses `mftscan`

---

## Disk Image Analysis

```bash
# Mount read-only
sudo mount -o loop,ro image.dd /mnt/evidence

# Autopsy / Sleuth Kit
fls -r image.dd              # List files recursively
icat image.dd <inode>        # Extract file by inode

# Carving deleted files
photorec image.dd
foremost -i image.dd
```

---

## VM Forensics (OVA/VMDK)

```bash
# OVA = TAR archive containing VMDK + OVF
tar -xvf machine.ova

# 7z reads VMDK directly (no mount needed)
7z l disk.vmdk | head -100
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r
```

**Key files to extract from VM images:**
- `Windows/System32/config/SAM` - Password hashes
- `Windows/System32/config/SYSTEM` - Boot key
- `Windows/System32/config/SOFTWARE` - Installed software
- `Users/*/NTUSER.DAT` - User registry
- `Users/*/AppData/` - Browser data, credentials

---

## VMware Snapshot Forensics

**Converting VMware snapshots to memory dumps:**
```bash
# .vmss (suspended state) + .vmem (memory) → memory.dmp
vmss2core -W path/to/snapshot.vmss path/to/snapshot.vmem
# Output: memory.dmp (analyzable with Volatility/MemprocFS)
```

**Malware hunting in snapshots (Armorless):**
1. Check Amcache for executed binaries near encryption timestamp
2. Look for deceptive names (Unicode lookalikes: `ṙ` instead of `r`)
3. Dump suspicious executables from memory
4. If PyInstaller-packed: `pyinstxtractor` → decompile `.pyc`
5. If PyArmor-protected: use PyArmor-Unpacker

**Ransomware key recovery via MFT:**
- Even if original files deleted, MFT preserves modification timestamps
- Seed-based encryption: recover mtime → derive key
```bash
vol3 -f memory.dmp windows.mftscan | grep flag
# mtime as Unix epoch → seed for PRNG → derive encryption key
```

---

## GIMP Raw Memory Dump Visual Inspection (INShAck 2018)

**Pattern:** When Volatility fails or profiles don't match, open raw memory dumps directly in GIMP as raw image data. Scroll through memory while adjusting image width to find previously-displayed images rendered as pixel data.

**Steps:**
1. Open `.dmp` file in GIMP: File > Open, set image type to "Raw image data"
2. Set pixel format to RGB, width to ~1920 (monitor resolution)
3. Scroll through the file offset while adjusting width with arrow keys
4. Previously-displayed images (desktop, browser content) become visible when width matches the original stride

```bash
# Alternative: use Python + PIL to scan memory as pixel data
python3 -c "
from PIL import Image
import numpy as np

with open('memory.dmp', 'rb') as f:
    data = f.read()

# Try common display widths: 1920, 1366, 1280, 1024
for width in [1920, 1366, 1280, 1024]:
    stride = width * 3  # RGB = 3 bytes per pixel
    # Sample at various offsets through the dump
    for offset in range(0, len(data) - stride * 100, stride * 500):
        chunk = data[offset:offset + stride * 100]
        if len(chunk) == stride * 100:
            img = Image.frombytes('RGB', (width, 100), chunk)
            # Check if image has meaningful content (not all zeros/noise)
            arr = np.array(img)
            if 10 < arr.mean() < 245 and arr.std() > 20:
                img.save(f'frame_{width}_{offset}.png')
                print(f'Potential image at offset {offset}, width {width}')
"
```

**Key insight:** Raw memory dumps contain framebuffer data that was displayed on screen. GIMP can render arbitrary binary data as pixels. When the image width matches the original display stride, screenshots of the user's desktop become visible without any forensics tools, profiles, or decryption.

---

## Coredump Analysis

```bash
gdb -c core.dump
(gdb) info registers
(gdb) x/100x $rsp
(gdb) find 0x0, 0xffffffff, "flag"
```

---

## Windows KAPE Triage Analysis (UTCTF 2026)

**Pattern (Landfall, Sherlockk, Cold Workspace):** KAPE (Kroll Artifact Parser and Extractor) triage collection ZIP containing Windows forensic artifacts. Multiple challenges reference the same triage dataset.

**KAPE triage structure:**
```text
Modified_KAPE_Triage_Files/
├── C/
│   ├── Users/<username>/
│   │   ├── AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/
│   │   │   └── ConsoleHost_history.txt    # PowerShell command history
│   │   ├── NTUSER.DAT                     # User registry hive
│   │   └── AppData/Roaming/Microsoft/Windows/Recent/  # Recent files
│   ├── Windows/
│   │   ├── System32/config/
│   │   │   ├── SAM          # Password hashes
│   │   │   ├── SYSTEM       # System config + boot key
│   │   │   └── SOFTWARE     # Installed software
│   │   └── appcompat/Programs/
│   │       └── Amcache.hve  # Execution history with SHA-1 hashes
│   └── $MFT                 # Master File Table
└── ...
```

**High-value artifacts:**

1. **PowerShell history** — reveals attacker commands:
```bash
cat "C/Users/*/AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
# Look for: credential access, lateral movement, data staging
```

2. **Amcache** — executed programs with timestamps and hashes:
```bash
# Parse with Eric Zimmerman's AmcacheParser or regipy
python3 -c "
from regipy.registry import RegistryHive
reg = RegistryHive('C/Windows/appcompat/Programs/Amcache.hve')
for entry in reg.recurse_subkeys(as_json=True):
    print(entry)
" | grep -i "flag\|suspicious\|malware"
```

3. **MFT resident data** — small files stored directly in MFT records:
```python
# Parse MFT for resident file data (files < ~700 bytes stored inline)
# Use analyzeMFT or python-ntfs
import struct

with open('$MFT', 'rb') as f:
    mft_data = f.read()

# Search for flag patterns in raw MFT data
import re
flags = re.findall(rb'utflag\{[^}]+\}', mft_data)
for flag in flags:
    print(f"Found: {flag.decode()}")
```

4. **Environment variables from memory dumps** (Cold Workspace pattern):
```bash
# Small .dmp files may be minidumps with environment variable blocks
strings -a cold-workspace.dmp | grep -i "flag\|password\|key\|secret"
# Environment variables survive in process memory snapshots
```

**Challenge patterns from UTCTF 2026:**
- **Landfall:** Flag hidden in PowerShell history or Amcache execution records
- **Sherlockk:** Correlate Amcache entries with MFT timestamps to identify malicious activity
- **Cold Workspace:** Flag in environment variables extracted from memory dump
- **Checkpoint A/B:** Multi-part investigation using combined artifacts

**Key insight:** KAPE triage ZIPs contain pre-collected forensic artifacts — no need for full disk imaging. Start with PowerShell history (fastest wins) → Amcache (execution timeline) → MFT (resident data for small files) → registry hives (persistence, credentials).

---

## PowerShell Ransomware Analysis

**Pattern (Email From Krampus):** PowerShell memory dump + network capture.

**Analysis workflow:**
1. Extract script blocks from minidump:
```bash
python power_dump.py powershell.DMP
# Or: strings powershell.DMP | grep -A5 "function\|Invoke-"
```

2. Identify encryption (typically AES-CBC with SHA-256 key derivation)

3. Extract encrypted attachment from PCAP:
```bash
# Filter SMTP traffic in Wireshark
# Export attachment, base64 decode
```

4. Find encryption key in memory dump:
```bash
# Key often generated with Get-Random, regex search:
strings powershell.DMP | grep -E '^[A-Za-z0-9]{24}$' | sort | head
```

5. Find archive password similarly, decrypt layers

---

## Android Forensics

```bash
# Extract APK from device
adb pull /data/app/com.target.app/base.apk

# Analyze APK contents
apktool d base.apk -o decompiled/
# Check: AndroidManifest.xml, res/values/strings.xml, shared_prefs/

# Extract data from Android backup
adb backup -apk -shared -all -f backup.ab
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar

# SQLite databases (contacts, messages, browser history)
sqlite3 /data/data/com.android.providers.contacts/databases/contacts2.db ".tables"
sqlite3 /data/data/com.android.providers.telephony/databases/mmssms.db "SELECT * FROM sms"

# Parse Android filesystem image
mkdir android_mount && mount -o ro android_image.img android_mount/
# Key locations:
# /data/data/<app>/databases/     — app SQLite databases
# /data/data/<app>/shared_prefs/  — app preferences (XML)
# /data/system/packages.xml       — installed packages
# /data/misc/wifi/wpa_supplicant.conf — saved WiFi passwords
```

**Key insight:** Android stores app data in `/data/data/<package>/` with SQLite databases and XML shared preferences. `adb backup` captures the full app state. For CTFs, check `shared_prefs/` for hardcoded secrets and `databases/` for flags.

---

## Container Forensics (Docker)

```bash
# Export Docker image layers
docker save IMAGE:TAG -o image.tar
tar xf image.tar
# Each layer is a directory with layer.tar containing filesystem changes
# Check: layer.tar files for added/modified files, deleted files (.wh.* whiteout)

# Inspect image history for build commands (may contain secrets)
docker history IMAGE:TAG --no-trunc
# Shows every Dockerfile instruction including ARGs and ENV values

# Extract filesystem without running the container
docker create --name extract IMAGE:TAG
docker export extract -o container_fs.tar
docker rm extract

# Analyze with dive (layer-by-layer diff viewer)
dive IMAGE:TAG

# Common forensic targets in container images:
# /app/.env, /app/config/* — application secrets
# /root/.bash_history     — build-time commands
# /etc/shadow             — leaked credentials
# Deleted files visible in earlier layers even if removed in later ones
```

**Key insight:** Docker images are layered — a file deleted in a later layer still exists in the earlier layer's tar. Use `docker history --no-trunc` to see full Dockerfile commands including secrets passed via `ARG` or `ENV`. The `dive` tool visualizes layer diffs interactively.

---

## Cloud Storage Forensics (AWS S3 / GCP / Azure)

```bash
# Enumerate public S3 buckets
aws s3 ls s3://target-bucket/ --no-sign-request
aws s3 cp s3://target-bucket/flag.txt . --no-sign-request

# Check bucket versioning (previous versions may contain deleted flags)
aws s3api list-object-versions --bucket target-bucket --no-sign-request
aws s3api get-object --bucket target-bucket --key secret.txt --version-id VERSION_ID out.txt

# GCP Cloud Storage
gsutil ls gs://target-bucket/
gsutil cp gs://target-bucket/flag.txt .

# Azure Blob Storage
az storage blob list --container-name target --account-name storageaccount
az storage blob download --container-name target --name flag.txt --account-name storageaccount
```

**Key insight:** Cloud storage versioning preserves deleted objects. Even if a flag file is deleted from the bucket, previous versions may still be accessible via `list-object-versions`. Always check for versioning-enabled buckets.

---

## Public GCS Bucket Object-Listing Triage (UofTCTF 2024)

**Scope:** Use only for a bucket explicitly supplied by a CTF challenge or an asset you are authorized to assess. Do not guess bucket names, expand scope, upload objects, or alter storage settings.

**Recognition:** A challenge gives a URL such as `https://storage.googleapis.com/<bucket>/path/file`, a public GCS static-site URL, or an XML `ListBucketResult`. A visible page can expose only a small subset of otherwise readable objects.

1. Preserve the exact supplied URL and derive the bucket name and object prefix from it.
2. Request the bucket root or the documented listing endpoint once. Save the XML/JSON listing as an artifact; record object key, size, generation, ETag, and last-modified time.
3. Build an inventory before downloading: prioritize obvious configuration, source, backup, and `secret/`-style paths, but do not invent paths not present in the listing.
4. Fetch only listed, in-scope objects. Hash downloaded files and retain the URL plus generation ID in a small evidence ledger.
5. If the listing includes generations, check whether an explicitly listed historical generation is readable; do not enumerate unrelated services or credentials.

```bash
# CTF/authorized bucket only; inventory before retrieval.
gcloud storage ls --recursive "gs://CTF_BUCKET/**" > object-inventory.txt
gcloud storage cp "gs://CTF_BUCKET/LISTED_OBJECT" ./evidence/
sha256sum ./evidence/LISTED_OBJECT
```

If cloud tooling is unavailable, treat the supplied listing itself as evidence and download only the exact listed object URLs through the challenge's normal interface.

**Validation:** Confirm the recovered data came from the recorded bucket, exact object key, and (when present) generation. Compare file size and ETag/checksum against the inventory. A CTF flag or source finding is not enough by itself if its provenance cannot be reproduced.

**Key insight:** Bucket-level list permission and object-read permission are independent from the static-site page. The object inventory is the pivot; it exposes available paths without brute-forcing names.

**Source inspiration:** UofTCTF 2024, *Out of the Bucket*: <https://ctftime.org/writeup/38449>.

---

## BSON (Binary JSON) Format Reconstruction (IceCTF 2016)

BSON is MongoDB's binary serialization format. Corrupted BSON files need header repair before parsing, and may contain base64-encoded file fragments.

```python
import bson

# BSON header: first 4 bytes = little-endian document size
# Fix corrupted header by setting correct size
with open('data.bson', 'rb') as f:
    data = bytearray(f.read())

# Fix size header if corrupted (e.g., missing first 3 bytes)
import struct
correct_size = len(data) + 3  # account for missing bytes
data = struct.pack('<I', correct_size)[1:] + data  # prepend missing bytes

# Parse BSON documents
docs = bson.decode_all(bytes(data))
for doc in docs:
    print(doc)

# Reconstruct file from BSON chunks (common pattern):
# Each document has: {index: N, data: "base64_chunk"}
import base64
chunks = sorted(docs, key=lambda d: d.get('index', d.get('i', 0)))
reconstructed = b''
for chunk in chunks:
    b64_data = chunk.get('data', chunk.get('d', ''))
    reconstructed += base64.b64decode(b64_data)

with open('reconstructed.png', 'wb') as f:
    f.write(reconstructed)
```

**Key insight:** BSON starts with a 4-byte little-endian size field. If the file appears corrupted, check if the first bytes are missing or incorrect. Parse with `bson.decode_all()` (from pymongo), sort chunks by index, and concatenate base64-decoded data to reconstruct embedded files.

---

## TrueCrypt / VeraCrypt Volume Mounting (GreHack CTF 2016)

Encrypted volumes in CTF challenges may use TrueCrypt or VeraCrypt. Identify by logo/branding clues, then mount with a recovered keyfile or password.

```bash
# Identify TrueCrypt volumes:
# - No file signature/magic bytes (by design)
# - Exact size is multiple of 512 bytes
# - High entropy throughout the file
# - Context clues: TrueCrypt logo in related images

# Mount with password:
truecrypt -t -p "password123" volume.tc /mnt/tc
veracrypt -t -p "password123" volume.tc /mnt/vc

# Mount with keyfile (no password):
truecrypt -t -p "" -k keyfile.png volume.tc /mnt/tc
veracrypt -t -p "" -k keyfile.png volume.tc /mnt/vc

# Mount hidden volume (different password):
truecrypt -t -p "hidden_password" volume.tc /mnt/tc

# Common keyfile locations in CTFs:
# - Images extracted from other challenge steps
# - GPG-encrypted files with keys found in git repos
# - Files embedded in other forensic artifacts

# If TrueCrypt is not available (discontinued):
# Use VeraCrypt (backwards-compatible with TrueCrypt volumes)
# Add --truecrypt flag for old TC volumes:
veracrypt -t --truecrypt -p "password" volume.tc /mnt/vc
```

**Key insight:** TrueCrypt volumes have no magic bytes or identifiable header -- they look like random data. Identify them from context clues (related images showing TrueCrypt logo, file sizes that are exact multiples of 512, or challenge descriptions mentioning encryption). VeraCrypt with `--truecrypt` flag handles legacy TC volumes.

---

## Volatility mftparser Offset-Based Deleted File Recovery (BSides Delhi 2018)

**Pattern:** Standard `dumpfiles` or `filescan` + `dumpfiles --physaddr` fails on a deleted file because its directory entry has been marked free. The MFT record that still holds the file's `$DATA` attribute survives until the record is reused. Volatility 2's `mftparser` can dump the resident `$DATA` directly when given the exact `--offset` of the MFT record found via `filescan`.

```bash
# 1. Locate the MFT record offset (Volatility 2 example; Vol3 uses windows.mftscan)
vol.py -f Challenge.raw --profile=Win7SP1x86 mftparser \
    | grep -A2 "target_filename"

# 2. Dump every attribute of the matching MFT entry, including $DATA
vol.py -f Challenge.raw --profile=Win7SP1x86 mftparser \
    --offset=0x7ca3c00 --dump-dir=./out/

ls ./out/
# file.data.$DATA contains the recovered content
```

**Key insight:** NTFS marks files "deleted" by flipping one bit in the MFT record header (`0x16` byte: `0x01 == in use`). Until the record is reallocated, the entire `$DATA` attribute is still intact and only lazily freed. Use `mftparser --offset=<record>` for resident files (under ~700 bytes — stored inline in the MFT) and `dd`/`icat` with the cluster runs for larger files. Always also grep for the filename in `windows.mftscan` output before giving up: memory-resident MFT fragments are still findable after on-disk deletion.

**References:** BSides Delhi CTF 2018 — Never Too Late Mister, writeups 11963, 11970

---

## Brotli Blob Detection via ASCII-Art Signature (ASIS Finals 2018)

**Pattern:** Binwalk and `file` miss Brotli-compressed data because the format has no fixed magic. Decompress candidate blobs with `brotli.decompress()`; the Brotli reference implementation embeds its own ASCII-art logo `Brrroootttllliii` as a sanity-check output. If the decompressed bytes contain that or other Brotli-specific telemetry strings, the original blob was Brotli.

```python
import brotli
try:
    out = brotli.decompress(blob)
    if b'rrrooottl' in out or b'Brotli' in out:
        print('Brotli-compressed')
except Exception: pass
```

**Key insight:** Any compressor without a magic byte is identifiable by trial decompression. For Brotli, `zstd`, `snappy`, `lzma-alone`, spin through each library in order until one succeeds without raising.

**References:** ASIS CTF Finals 2018 — Green Cabbage, writeup 12419

---

## corkami/pocs MD5 PDF Collision Generation (35C3 2018)

**Pattern:** Challenge demands two valid PDFs with the same MD5 but different content. Use corkami/pocs `pdf.py` combined with `enscript | ps2pdf` to produce a PDF header with collision-friendly padding, then drive the collision via `fastcoll` (or `hashclash` for chosen-prefix). Works because the PDF format tolerates garbage in the `%PDF` trailer region that the MD5 collision block can overwrite.

```bash
enscript -p out.ps content.txt
ps2pdf out.ps base.pdf
python pdf.py base.pdf target1.pdf target2.pdf
fastcoll -p base.pdf -o target1.pdf target2.pdf
md5sum target1.pdf target2.pdf    # identical
```

**Key insight:** PDF collision is a one-command pipeline with the right toolchain. The harder variant is chosen-prefix MD5 (different visible content) which requires `hashclash` and 10-20 CPU-hours. Check `pocs/collisions/` for every file format with prebuilt scaffolds.

**References:** 35C3 CTF 2018 — collider, writeup 12836

---

## See Also

- [disk-advanced.md](disk-advanced.md) - Advanced disk and memory techniques (deleted partition recovery, ZFS forensics, GPT GUID encoding, VMDK sparse parsing, memory dump string carving, ransomware key recovery, WordPerfect macro XOR, minidump ISO 9660 recovery, APFS snapshot recovery, RAID 5 XOR recovery, Kyoto Cabinet hash DB forensics)
- [disk-recovery.md](disk-recovery.md) - Disk recovery and extraction patterns (LUKS master key recovery, PRNG timestamp seed brute-force, VBA macro binary recovery, FemtoZip decompression, XFS reconstruction, tar duplicate entry extraction, nested matryoshka filesystem extraction, anti-carving via null byte interleaving)

## Mount a VMDK with qemu-nbd and blank the shadow hash to boot the VM

**Trigger:** The handout is a whole desktop VM (multi-GB `.vmdk` / `.vmx` bundle) and the challenge requires you to actually log in and use the running system rather than pull one file out of it — no credentials given, and `7z x disk.vmdk` gets you files but not a session.

`qemu-nbd` exposes any format QEMU understands (VMDK, VHD/VHDX, QCOW2, VDI) as a real block device, so you get partition tables and normal mounting rather than format-specific extraction. Load the NBD kernel module with a partition count, attach the disk, and mount the root partition read-write. To get a shell, edit `/etc/shadow` in place and replace the target user's hash field with an empty string — an empty second field means "no password", so the display manager or console accepts a blank password. The hash prefix tells you what you would otherwise be up against: `$y$` is yescrypt, `$6$` SHA-512crypt, `$2b$` bcrypt — all a waste of time next to blanking the field. Detach the device and unload the module when done, then point VirtualBox/VMware at the modified VMDK and boot it. Same workflow with `guestmount`/`libguestfs` if NBD is unavailable, and the equivalent Windows move is `chntpw` against `SAM`.

```bash
sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 disk.vmdk
sudo mount /dev/nbd0p1 /mnt/vm
sudo sed -i 's/^kali:[^:]*:/kali::/' /mnt/vm/etc/shadow
sudo umount /mnt/vm && sudo qemu-nbd --disconnect /dev/nbd0 && sudo rmmod nbd
```

Source: https://hackmd.io/@EPIDaX-NTqKc4Xpu5lWmVQ/HJmv07Av-l

## Volatility iehistory for URL recovery from memory

**Trigger:** You need the URL a payload was downloaded from or a browsing trail, but the on-disk history databases are absent, wiped, or the activity was private-mode — and all you have is a memory image.

Browsing and download records live in memory long after they are removed from disk, because the WinINet cache structures stay resident in the process heap. iehistory scans a Windows memory image for WinINet index.dat records — URL, LEAK, and REDR entries — and recovers the visited URL, the cache filename it was stored as, and the access and modification timestamps. Its real value is broader than Internet Explorer: anything that calls the WinINet API populates the same cache, which includes InPrivate sessions (deleted-on-close on disk, still in RAM), Windows Update and many installers, and a large class of malware downloaders and HTTP-based C2 that use WinINet rather than raw sockets. So run it even on an image with no browser of interest: a URL record owned by a process that has no business making HTTP requests is the download or beacon URL you are looking for. It also recovers records already marked deleted, since it is scanning freed structures rather than reading a live index. Combine it with windows.netscan for the connections that were still open and with the cmdline of the owning PID to attribute the fetch. This is a Volatility 2 plugin; on Volatility 3 there is no shipped equivalent, so fall back to dumping the suspect process memory and grepping for URL patterns and cache-record magic.

```bash
# Volatility 2 — recover WinINet URL/LEAK/REDR records, including deleted ones
vol.py -f memory.raw --profile=Win7SP1x64 iehistory
vol.py -f memory.raw --profile=Win7SP1x64 iehistory -p 1892       # scope to one PID

# attribute a recovered URL to the process that fetched it
vol.py -f memory.raw --profile=Win7SP1x64 pslist   | grep -i 1892
vol.py -f memory.raw --profile=Win7SP1x64 cmdline  -p 1892
vol.py -f memory.raw --profile=Win7SP1x64 netscan  | grep -i 1892

# Volatility 3 fallback: dump the process and carve URLs out of the heap
vol3 -f memory.dmp windows.memmap --pid 1892 --dump
strings -a -el pid.1892.dmp | grep -aoE 'https?://[^"<> ]{8,}' | sort -u
strings -a     pid.1892.dmp | grep -aoE 'https?://[^"<> ]{8,}' | sort -u

# raw-image sweep when you have no profile at all
strings -a -td memory.raw | grep -aoE 'https?://[^"<> ]{8,}' | sort -u | head -50
```

Source: https://offsecexams.com/cheatsheets/btl1-exam---guided-by-redblock

## bulk_extractor feature-file sweep as first pass on large dumps

**Trigger:** You are handed a multi-gigabyte memory dump, disk image, or pcap and have no lead — before scripting targeted carving or committing to a Volatility profile.

When the dump is too big to read and you have no starting hypothesis, run a stream-oriented scanner that ignores the filesystem entirely and pulls every recognizable structure into per-type feature files. bulk_extractor reads the raw bytes in parallel, so it works on corrupted images, unallocated space, hibernation files, swap, and memory dumps with no profile identified — anything the format-aware tools would refuse. Each scanner writes a text file of offset-plus-value pairs, so url.txt gives you every URL including C2 callbacks pulled from browser and process memory, email.txt gives addresses, domain.txt gives hostnames, ip.txt and ether.txt give network indicators without a pcap, telephone.txt and ccn.txt give PII, winpe.txt flags embedded PE headers at their exact offsets, and zip.txt plus rar.txt locate archive members inside the blob. The offsets are the real payoff: once a feature file points at byte 0x3f2a1000, you seek there with dd and carve the surrounding structure precisely instead of running blind file-carving over the whole image. Enable the recursive scanners so it decompresses gzip/zip members and decodes base64 in-line and re-scans the result, which surfaces payloads that plain strings misses. Treat the histogram files (*_histogram.txt) as the triage view — the most frequent domain or email in a memory dump is usually the answer or the attacker infrastructure.

```bash
bulk_extractor -o out/ memory.dmp
bulk_extractor -o out/ -e all disk.raw           # enable every scanner incl. base64/hiberfile
bulk_extractor -o out/ -E winpe -S write_feature_context=1 memory.dmp

# Triage view first
head -50 out/domain_histogram.txt out/url_histogram.txt out/email_histogram.txt

# Feature files are 'offset<TAB>value' — pivot on the offset
grep -iE 'flag|\.onion|pastebin' out/url.txt
awk -F'\t' '{print $1}' out/zip.txt | head

# Carve precisely at a reported offset instead of blind file-carving
dd if=memory.dmp bs=1 skip=$((0x3f2a1000)) count=200000 of=carved.bin

# Useful outputs: url.txt email.txt domain.txt ip.txt ether.txt ccn.txt
#                 telephone.txt winpe.txt zip.txt rar.txt json.txt pii.txt
```

Source: https://offsecexams.com/cheatsheets/ccd---l1-exam---guided-by-redblock

