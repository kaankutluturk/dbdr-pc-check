# Evidence source matrix

| Source | Purpose | Scope/minimization | Timestamp semantics | Failure meaning |
| --- | --- | --- | --- | --- |
| `Win32_Process` | Preserve live process identity and parentage | No command lines or owners | Process creation time from WMI | Snapshot unavailable/incomplete |
| `Process.Modules` | Record file-backed modules loaded by live DBD processes | DBD-named processes only; no addresses or memory | No source timestamp | Module-list coverage gap |
| File APIs / WinVerifyTrust | Hash and inspect referenced executables | Referenced paths only; no file copies | File times remain labeled fields | Per-file inspection gap |
| Shannon entropy | Identify compressed/packed-like byte distributions for corroboration | Calculated during the same full-file SHA-256 read; no extra file scope | No source timestamp | Per-file inspection gap |
| libyara 4.5.5 | Match embedded and optional custom rules against referenced files | Rule IDs and ruleset hashes only; no matched bytes, offsets or file copies | No source timestamp | Per-file YARA coverage gap |
| BAM registry | Time-bounded execution observation | Explicit review window; SIDs excluded | BAM FILETIME | Layout/key access gap |
| Prefetch directory | Corroborating recent Prefetch metadata | `.pf` files in explicit review window | File last-write time, not parsed run time | Directory/access gap |
| System event 7045 | Service-install observation | Selected event ID only; account field/message excluded | Event creation time | Channel/query gap |
| Code Integrity operational log | Integrity warning/error observations | Warning/error levels only; message excluded | Event creation time | Channel/query gap |
| Live Amcache registry | Corroborating executable application inventory | Opt-in; executable file types only; redacted paths; 5,000-record cap; no key hashes or user identities | No source timestamp; link date remains labeled file metadata | Hive/layout/access/cap coverage |
| Application Error event 1000 | Crash and fault-module observation | Opt-in; selected fields only; message, report ID and dumps excluded | Event creation time | Channel/query/layout gap |
| Windows PowerShell events 400/403/600 | Engine and provider lifecycle observation | Opt-in; system metadata only; event payload, command/script content, host arguments and users excluded | Event creation time | Channel/query/retention gap |
| Run keys/services/drivers | Current persistence configuration | Selected configuration fields only | No source timestamp | Source-specific gap/warning |
| Scheduled task definitions | Current task persistence configuration | Command only; arguments/principals excluded | Registration date where parseable | Per-task or directory gap |
| `Win32_PnPEntity` | Privacy-minimized device context | Unique IDs and serial suffixes excluded | No source timestamp | Device-inventory gap |

Planned USN, MFT, SRUM and path-correlation adapters remain disabled until their parsing, retention, redaction and timestamp behavior has a separate review. Browser data, PowerShell command/script content and memory-dump collection remain privacy-gated exclusions.
