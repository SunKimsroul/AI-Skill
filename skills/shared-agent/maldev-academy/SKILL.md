---
name: maldev-academy
description: Full-spectrum Windows malware development knowledge base drawn from MalDev Academy's 91-module curriculum. Use when writing, modifying, or reversing C2 implants, shellcode loaders, process injection techniques, evasion logic, EDR bypasses, payload obfuscation/encryption, or any Windows userland/ kernel-level agent code. Source: /home/numpav/Documents/RedTeaming-OPSEC/malware/c2_platform/MalDevAcademy
---

# MalDev Academy — C2 & Implant Knowledge Base

This skill encodes the full MalDev Academy (maldevacademy.com) curriculum for Windows malware development, organized by module. All techniques are relevant to C2 agent/implant development, payload generation, and defense evasion.

## Module Map (91 Modules)

### Foundations (Modules 1–9)
- **1-2**: Welcome, Intro to Malware Development
- **3**: Required Tools (x64dbg, Process Hacker, IDA, Visual Studio, MSVC/Clang)
- **4**: Coding Basics (C/C++ for malware, Windows data types, calling conventions)
- **5**: Windows Architecture (userland vs kernel, rings, HAL, NT kernel)
- **6**: Windows Memory Management (virtual memory, pages, heaps, stacks, PEB/TEB)
- **7**: Introduction To The Windows API (Win32 API, NTAPI, ntdll exports)
- **8**: Portable Executable Format (DOS header, NT headers, sections, IAT, EAT, relocations)
- **9**: Dynamic-Link Library (DLL entry point, exports, DllMain, load-time vs run-time linking)

### Detection Mechanisms (Module 10)
- How AV/EDR static analysis works (signatures, heuristics, ML)
- How dynamic analysis works (behavioral monitoring, sandboxing, hooking)
- AMSI, ETW, WLDP, Windows Defender, Cloud-delivered protection

### Windows Processes (Module 11)
- Process structure, handle table, EPROCESS, creation flow
- CreateProcess internals, image loading, process environment block (PEB)

### Undocumented Structures (Module 12)
- PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY, RTL_USER_PROCESS_PARAMETERS
- TEB/PEB manual traversal for API resolution and evasion

### Payload Placement (Modules 13–15)
- **13**: `.data` & `.rdata` sections — storing shellcode in read/write or read-only data sections
- **14**: `.text` section — code cave insertion, extending sections
- **15**: `.rsrc` section — embedding payloads as resources, loading with FindResource/LoadResource

### Payload Encryption (Modules 16–19)
- **16**: Intro to payload encryption (why encrypt, decrypt before execute)
- **17**: XOR encryption — single-byte, multi-byte, key generation
- **18**: RC4 encryption — KSA/PRGA, standard RC4 implementation
- **19**: AES encryption — AES-128/256, CBC/ECB modes, CryptoAPI/CNG, wincrypt.h

### Evading Microsoft Defender (Module 20)
- Static analysis bypass via encryption/obfuscation
- AMSI bypass techniques (patching, DLL unhooking, hardware breakpoints)
- Defender behavioral analysis bypass

### Payload Obfuscation (Modules 21–23)
- **21**: IPv4/IPv6Fuscation — convert shellcode to IP address strings
  - IPv4: 4 bytes per address via `RtlIpv4StringToAddressA`
  - IPv6: 16 bytes per address via `RtlIpv6StringToAddressA`
  - Shellcode must be multiple of 4 (IPv4) or 16 (IPv6)
- **22**: MACFuscation — convert shellcode to MAC address strings (6 bytes each)
  - Deobfuscation via `RtlEthernetStringToAddressA` (since Win10)
- **23**: UUIDFuscation — convert shellcode to UUID strings (16 bytes each, little-endian segments)
  - Deobfuscation via `UuidFromStringA` from Rpcrt4.dll
  - First 3 UUID segments use reversed byte order (little-endian)

### MalDev Academy Tools (Modules 24–25)
- **24**: HellShell — shellcode generation/encryption helper tool
- **25**: MiniShell — minimal beacon/shellcode runner (prototype C2 agent concepts)

### Local Payload Execution (Modules 26–27)
- **26**: DLL execution via `rundll32`, reflective DLL loading
- **27**: Shellcode execution — VirtualAlloc → memcpy → VirtualProtect → CreateThread
  - Function pointer cast `(*(VOID(*)())pShellcodeAddress)()` as alternative
  - WaitForSingleObject for thread synchronization
  - VirtualFree for cleanup

### Process Injection (Modules 28–29)
- **28**: DLL Injection — CreateToolhelp32Snapshot → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread (LoadLibrary as start address)
- **29**: Shellcode Injection — same flow but shellcode address as thread start
  - Process enumeration via CreateToolhelp32Snapshot/Process32First/Process32Next
  - VirtualFreeEx for remote cleanup

### Payload Staging (Modules 30–31)
- **30**: Web server staging — download payload from remote server
  - InternetOpen/InternetOpenUrl/InternetReadFile (WinHTTP/WinINet)
- **31**: Windows Registry staging
  - Store/read payload from registry keys (HKCU, HKLM)
  - RegOpenKeyEx/RegQueryValueEx/RegSetValueEx

### Malware Binary Signing (Module 32)
- Self-signing with MakeCert, CertEnroll, or stolen certificates
- Timestamping, signature validation bypass

### Process Enumeration (Modules 33–34)
- **33**: EnumProcesses (PSAPI) — simple PID list
- **34**: NtQuerySystemInformation (SystemProcessInformation) — detailed process info (PID, PPID, threads, handles, command line)

### Thread Hijacking (Modules 35–38)
- **35-36**: Local/Remote thread creation via CreateRemoteThread
- **37-38**: Local/Remote thread enumeration via CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) + Thread32First/Thread32Next → OpenThread
  - SuspendThread/ResumeThread for hijacking execution flow

### APC Injection (Modules 39–40)
- **39**: APC Injection — QueueUserAPC to alertable or suspended threads
  - Alertable state via SleepEx, WaitForSingleObjectEx, MsgWaitForMultipleObjectsEx, SignalObjectAndWait (with bAlertable=TRUE)
  - Suspended threads: create with CREATE_SUSPENDED, QueueUserAPC, then ResumeThread
- **40**: Early Bird APC Injection — CreateProcess (CREATE_SUSPENDED) → VirtualAllocEx → WriteProcessMemory → QueueUserAPC → ResumeThread

### Callback Code Execution (Module 41)
- Using Windows callback functions for code execution (EnumWindowStations, EnumDesktops, EnumChildWindows, etc.)
- Pass shellcode address as callback parameter

### Mapping Injection (Modules 42–43)
- **42**: Local Mapping Injection — CreateFileMapping → MapViewOfFile (SEC_IMAGE) → execute
- **43**: Remote Mapping Injection — CreateFileMapping → MapViewOfFile in local + remote via MapViewOfFile2 (or ZwMapViewOfSection)

### Function Stomping Injection (Modules 44–45)
- **44**: Local Function Stomping — overwrite a benign function's code with shellcode
- **45**: Remote Function Stomping — VirtualProtectEx + WriteProcessMemory to overwrite remote function

### Payload Execution Control (Module 46)
- Scheduling execution, delay logic, conditional execution
- Using Windows Task Scheduler, WMI, or timer-based triggers

### PPID Spoofing (Module 47)
- InitializeProcThreadAttributeList with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
- CreateProcess with extended startup info to spoof parent PID
- Evading process-tree based detection

### Process Argument Spoofing (Modules 48–49)
- **48**: Modify PEB.CommandLine post-creation
- **49**: Use RtlUserProcessParameters + WriteProcessMemory to spoof arguments in a suspended process

### PE Parsing (Module 50)
- Manual parsing of DOS header (e_magic, e_lfanew), NT headers (Signature, FileHeader, OptionalHeader), section headers
- Walking IAT, EAT, relocations manually for evasion

### String Hashing (Module 51)
- Compile-time string hashing (constexpr, macro-based)
- Run-time string hashing (CRC32, DJB2, custom hashes)
- Resolving API names by hash at runtime

### IAT Hiding & Obfuscation (Modules 52–57)
- **52**: Introduction to IAT hiding — why EDRs scan IAT
- **53**: Custom GetProcAddress — manual PEB → LDR → InMemoryOrderModuleList → export directory parse
- **54**: Custom GetModuleHandle — PEB_LDR_DATA traversal to find loaded base address
- **55**: API Hashing — store API names as hashes, resolve at runtime
- **56**: Custom pseudo-handle for NtClose
- **57**: Compile-time API hashing — constexpr hash generation in C++

### API Hooking (Modules 58–62)
- **58**: Introduction to API hooking (detours, trampolines, inline hooks)
- **59**: Detours library (Microsoft Research) — professional hooking framework
- **60**: Minhook library — minimalistic hooking library
- **61**: Custom code — manual JMP/NOP sled/trampoline hooks
- **62**: Using Windows APIs — VEH, page guard hooks, HWBP

### Syscalls (Modules 63–69)
- **63**: Syscall introduction — syscall numbers, SSDT, transitioning from user to kernel
- **64**: Userland Hooking — EDRs hook ntdll.dll to monitor syscalls
- **65**: SysWhispers — embedded syscall tables, direct syscalls via assembly
- **66**: Hell's Gate — dynamic syscall number resolution from ntdll on disk
- **67-69**: Reimplementing classic injection via direct syscalls (NtCreateThreadEx, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtQueueApcThread)

### Anti-Analysis (Modules 70–75)
- **70**: Anti-analysis introduction
- **71**: Anti-debugging — IsDebuggerPresent, NtQueryInformationProcess (ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle), CheckRemoteDebuggerPresent, NtSetInformationThread (HideThreadFromDebugger), TLS callbacks, INT3/CC detection
- **72**: Self-deletion — FILE_FLAG_DELETE_ON_CLOSE, MoveFileEx (MOVEFILE_DELAY_UNTIL_REBOOT), NtSetInformationFile (FileDispositionInfo)
- **73**: Anti-virtual environment — VM detection (MAC OUI, registry keys, hardware, DLLs), sandbox detection (username, disk size, RAM, CPU cores)
- **74**: Delayed execution — Sleep, timer-based delays, Sleep skips via NtDelayExecution
- **75**: API Hammering — call non-malicious APIs before malicious ones to evade behavioral analysis

### Binary Entropy Reduction (Module 76)
- Lowering file entropy to match legitimate software
- Padding, blending with legitimate sections, bypassing entropy-based detection

### Brute Force Decryption (Module 77)
- Using weak/broken crypto deliberately to delay analysis
- Key brute-force gates, time-based decryption

### KeyGuard Tool (Module 78)
- MalDev Academy utility for secure key management
- Encryption key handling and protection

### CRT Library Removal (Module 79)
- Removing C runtime dependency to reduce binary size and indicators
- Manual implementation of memset, memcpy, strlen, etc.
- Setting entry point manually (/ENTRY linker flag)

### IAT Camouflage (Module 80)
- Adding legitimate imports alongside malicious ones
- Import address table obfuscation to blend with benign software

### Bypassing AVs (Module 81)
- Combining multiple evasion techniques
- Layered approach: encryption → obfuscation → injection → anti-debug → anti-sandbox

### Introduction to EDRs (Module 82)
- EDR architecture (kernel callbacks, ETW, AMSI, behavioral monitoring, telemetry)
- How EDRs differ from AV (stack traces, event correlation, IOC gathering)

### NTDLL Unhooking (Modules 83–87)
- **83**: Introduction — EDRs hook ntdll, need to restore original
- **84**: From Disk — read clean ntdll.dll from C:\Windows\System32, map it, copy over hooked sections
- **85**: From KnownDlls Directory — use KnownDlls directory object to get clean ntdll
- **86**: From a Suspended Process — duplicate ntdll mapping from a suspended, non-hooked process
- **87**: From a Web Server — download clean ntdll from a server running the matching Windows version

### Indirect Syscalls (Modules 88–89)
- **88**: Updating Hell's Gate — improved syscall resolution techniques
- **89**: HellsHall — indirect syscalls via ret/gadget to break EDR stack tracing
  - Combines Hell's Gate syscall resolution + gadget-based indirect call

### Block DLL Policy (Module 90)
- Using ProcessSignaturePolicy / ProcessDynamicCodePolicy (Mitigation Policies) to block unsigned DLLs
- SetProcessMitigationPolicy, ProcessSignaturePolicy = BlockNonMicrosoftSigned
- Prevents reflective DLL injection from loading unsigned DLLs

### NtCreateUserProcess (Module 91)
- Deep dive into NtCreateUserProcess — the NT-native process creation API
- Parameters, flags, object attributes, process/thread handle creation
- Understanding what CreateProcess ultimately calls

## Key API Categories for Implant Development

### Memory
- `VirtualAlloc`, `VirtualAllocEx`, `VirtualProtect`, `VirtualProtectEx`, `VirtualFree`, `VirtualFreeEx`
- `HeapAlloc`, `HeapFree`, `RtlAllocateHeap`, `RtlFreeHeap`
- `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`
- `CreateFileMapping`, `MapViewOfFile`, `MapViewOfFile2`, `ZwMapViewOfSection`

### Process/Thread
- `CreateProcess`, `CreateProcessA/W`, `NtCreateUserProcess`
- `OpenProcess`, `CreateRemoteThread`, `NtCreateThreadEx`
- `CreateToolhelp32Snapshot`, `Process32First/Next`, `Thread32First/Next`
- `QueueUserAPC`, `NtQueueApcThread`
- `SuspendThread`, `ResumeThread`, `OpenThread`
- `GetThreadContext`, `SetThreadContext`, `NtGetContextThread`, `NtSetContextThread`

### Payload Writing
- `WriteProcessMemory`, `NtWriteVirtualMemory`, `ReadProcessMemory`
- `memcpy`, `RtlCopyMemory`, `RtlMoveMemory`

### Execution
- `CreateThread`, `CreateRemoteThread`, `RtlCreateUserThread`
- `EnumWindowStations`, `EnumDesktops`, `EnumChildWindows` (callback execution)
- Function pointers, `(*(VOID(*)())addr)()`

### Crypto
- XOR, RC4 (manual implementation), AES (CryptEncrypt/CryptDecrypt via wincrypt.h)
- BCryptEncrypt/BCryptDecrypt (CNG API)

### Obfuscation/Deobfuscation
- `RtlIpv4StringToAddressA` / `RtlIpv6StringToAddressA` (IP deobfuscation, ntdll)
- `RtlEthernetStringToAddressA` (MAC deobfuscation, since Win10)
- `UuidFromStringA` (UUID deobfuscation, Rpcrt4.dll)

### Process Enumeration
- `EnumProcesses`, `CreateToolhelp32Snapshot`, `NtQuerySystemInformation`
- `WTSEnumerateProcesses`, `GetProcessTimes`, `GetProcessMemoryInfo`

### PEB/LDR Traversal
- `__readgsqword(0x60)` / `__readfsdword(0x30)` for PEB
- PEB->Ldr->InMemoryOrderModuleList for module enumeration
- PEB->ProcessParameters->CommandLine for argument spoofing
- Manual export directory parsing (ImageBase + IMAGE_EXPORT_DIRECTORY)

### Anti-Debug
- `IsDebuggerPresent`, `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`
- `NtSetInformationThread(ThreadHideFromDebugger)`
- TLS callbacks, `OutputDebugString` detection, timing checks

### EDR Evasion
- NTDLL unhooking (from disk, KnownDlls, suspended process, web server)
- Direct syscalls (Hell's Gate, SysWhispers, HellsHall)
- Indirect syscalls (ret gadget trampoline)
- IAT hiding (custom GetProcAddress/GetModuleHandle via PEB walk)
- API hashing (runtime + compile-time)
- PPID spoofing, process argument spoofing

## Build & Compilation Notes
- Compile in **Release mode** (Debug mode breaks many techniques)
- Use MSVC (cl.exe) or Clang (clang-cl.exe)
- Remove CRT dependency when needed: `/ENTRY:"mainCRTStartup"` or custom entry
- Link against: `kernel32.lib`, `ntdll.lib`, `advapi32.lib`, `rpcrt4.lib`, `iphlpapi.lib`
- Use `#pragma comment(lib, ...)` for explicit linking
- For direct syscalls: use MASM (`amd64`) or inline assembly for x86
- Hell's Gate/HellsHall need shellcode extraction of ntdll on disk

## Reference Source Location
Full course materials (HTML with embedded code and images):
`/home/numpav/Documents/RedTeaming-OPSEC/malware/c2_platform/MalDevAcademy/MalDevAcademy/MALWARE 8b74ccffb7e64efea30e3da4d919418d/`
