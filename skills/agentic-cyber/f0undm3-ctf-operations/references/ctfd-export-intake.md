# CTFd Export Intake

CTFd is an event platform, not a global writeup index. Use this route only for a saved export or archive from a CTF you are entitled to analyze. Do not discover, enumerate, or query unrelated live CTFd instances.

## Normalize a saved export

```powershell
$root = 'C:\Users\ASUS\Desktop\CTF\claudemcp-tool'   # this toolkit's folder
$py = "$root\runtime\python313\python.exe"
& $py "$root\skills\f0undm3-ctf-operations\scripts\ingest_ctfd_export_catalog.py" `
  --input 'D:\authorized-ctf\challenges.json' `
  --output 'D:\authorized-ctf\ctfd-metadata.jsonl'
```

The normalizer keeps event name, challenge title, category, tags, and a local export identifier. It intentionally excludes descriptions, flags, writeup bodies, credentials, and live URLs.

## Review alongside the CTFtime index

Copy the public metadata index first, then append the saved CTFd export:

```powershell
Copy-Item "$root\sources\public-writeup-catalog.jsonl" 'D:\authorized-ctf\combined-metadata.jsonl'
& $py "$root\skills\f0undm3-ctf-operations\scripts\ingest_ctfd_export_catalog.py" `
  --input 'D:\authorized-ctf\challenges.json' `
  --output 'D:\authorized-ctf\combined-metadata.jsonl' --append
& $py "$root\skills\f0undm3-ctf-operations\scripts\review_public_writeup_coverage.py" `
  --catalog 'D:\authorized-ctf\combined-metadata.jsonl' --min-count 2
```

For each proposed gap, inspect the supplied challenge artifacts first. Add a compact, original workflow only when it captures a genuinely different technique or trust boundary.
