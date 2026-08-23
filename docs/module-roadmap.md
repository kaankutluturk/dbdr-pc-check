# Module roadmap

The product remains one portable executable with internal adapters and one normalized evidence model. Status labels are literal: `available` and `preview` have running code; `planned` is visible scope, not a fake tool; `privacy gated` conflicts with the current collection contract.

| Requested capability | v0.5 status | Adapter direction | Boundary / blocker |
| --- | --- | --- | --- |
| WinPrefetch View | Preview | Bounded parser emits executable identity and parsed run timestamps inside the case window | Add signed Windows fixture coverage for every supported compressed Prefetch version; volume/device data remains excluded by minimization |
| Autoruns | Available | Existing Run keys, services, drivers and scheduled tasks under one searchable persistence view | Current state does not establish creation time |
| String Explorer | Preview | Search normalized file metadata now; add bounded printable-string extraction only for already referenced files | Never read raw process memory or crawl arbitrary files |
| USBDeview | Preview | Existing privacy-minimized PnP inventory, then time-bounded device-install artifact correlation | Unique serials and instance IDs remain excluded |
| Saved Files Viewer | Privacy gated | None under the current contract | Personal filenames and save paths are excluded |
| PowerShell Parser | Preview | Opt-in time-bounded engine/provider lifecycle event metadata | Command, script-block, event payload, user and terminal history remain excluded |
| Paths Parser | Preview | Exact redacted executable-path correlation across BAM/Amcache/SRUM usage and live-module/persistence binary evidence | Requires an independent signature, YARA or PE-import signal; no LNK/Jump List or personal recent-file parsing |
| MFT Explorer | Planned | Read-only, time-bounded NTFS parser with strict caps and redaction | Raw-volume access, scale, timestamp semantics and recovery records need tests |
| Kernel Live Dump | Privacy gated | None in this suite | Kernel dumps can contain user-mode pages and violate the no-memory boundary |
| Journal Trace | Preview | Read-only bounded USN journal tail for execution-capable leaf filenames and change sequences | No full path reconstruction or file-reference serialization; a missing/rotated/capped journal is a coverage gap, never evasion proof |
| Crashed File Viewer | Preview | Opt-in Application Error event 1000 metadata and redacted executable identity | Messages, report IDs, dumps and memory-derived contents remain excluded |
| Browsing History View | Privacy gated | None in this suite | Browser history is excluded |
| Browser Downloads View | Privacy gated | None in this suite | Browser download records are excluded |
| BAM Parser | Available | Existing time-bounded BAM adapter | Windows layout and retention vary |
| Amcache Parser | Preview | Capped live registry adapter for executable application inventory with redacted paths | Current inventory is not execution proof; no locked-hive fallback yet |
| SRUM Explorer | Preview | Opt-in `powercfg /srumutil` adapter retaining only in-window executable name, redacted path and timestamp, capped at 5,000 records | Native export is 64 MiB/60 s capped and immediately deleted; user IDs, network fields, usage amounts and unresolved identities are discarded |
| YARA + entropy | Available | libyara 4.5.5, embedded baseline, optional custom rules and full-file Shannon entropy | Scans only already referenced files; matches are leads |

## Integration rule

Open-source parsers are integrated as libraries or source-reviewed adapters where practical. The suite does not download tools at runtime or present a folder of third-party EXEs. MIT/BSD components may be embedded in the self-contained build with notices; every parser still returns the DBDR schema, cancellation behavior, coverage status and redacted paths.

## Case handling

Encrypted `.dbdr` export, authenticated reopening, legacy ZIP manifest verification and in-app evidence reloading are available in v0.5. Further case-backend work still requires short-lived authorization, server-side retention enforcement and audited access; the desktop client contains no upload path or embedded decryption key.
