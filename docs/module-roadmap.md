# Module roadmap

The product remains one portable executable with internal adapters and one normalized evidence model. Status labels are literal: `available` and `preview` have running code; `planned` is visible scope, not a fake tool; `privacy gated` conflicts with the current collection contract.

| Requested capability | v0.3 status | Adapter direction | Boundary / blocker |
| --- | --- | --- | --- |
| WinPrefetch View | Preview | Upgrade existing Prefetch metadata source to a tested parser with parsed run timestamps and volume/device data | Timestamp semantics and compressed Prefetch variants need fixtures |
| Autoruns | Available | Existing Run keys, services, drivers and scheduled tasks under one searchable persistence view | Current state does not establish creation time |
| String Explorer | Preview | Search normalized file metadata now; add bounded printable-string extraction only for already referenced files | Never read raw process memory or crawl arbitrary files |
| USBDeview | Preview | Existing privacy-minimized PnP inventory, then time-bounded device-install artifact correlation | Unique serials and instance IDs remain excluded |
| Saved Files Viewer | Privacy gated | None under the current contract | Personal filenames and save paths are excluded |
| PowerShell Parser | Privacy gated | A future engine-lifecycle metadata adapter may be acceptable | Command, script-block and terminal history remain excluded |
| Paths Parser | Planned | Cross-source path correlation over redacted normalized evidence; later LNK/Jump List review | Personal recent-file content needs separate approval |
| MFT Explorer | Planned | Read-only, time-bounded NTFS parser with strict caps and redaction | Raw-volume access, scale, timestamp semantics and recovery records need tests |
| Kernel Live Dump | Privacy gated | None in this suite | Kernel dumps can contain user-mode pages and violate the no-memory boundary |
| Journal Trace | Planned | Read-only `$UsnJrnl:$J` parser with explicit journal-ID and range coverage | A missing/rotated journal is a coverage gap, never evasion proof |
| Crashed File Viewer | Planned | WER metadata and referenced executable identity only | Dumps and memory-derived contents remain excluded |
| Browsing History View | Privacy gated | None in this suite | Browser history is excluded |
| Browser Downloads View | Privacy gated | None in this suite | Browser download records are excluded |
| BAM Parser | Available | Existing time-bounded BAM adapter | Windows layout and retention vary |
| Amcache Parser | Planned | Prefer a reviewed MIT-licensed parser/library integration with locked-hive handling | Redaction, inventory semantics and fixtures required |
| SRUM Explorer | Planned | Time-bounded application usage only, with identities and destinations removed | ESE parsing, SOFTWARE mapping and minimization tests required |
| YARA + entropy | Available | libyara 4.5.5, embedded baseline, optional custom rules and full-file Shannon entropy | Scans only already referenced files; matches are leads |

## Integration rule

Open-source parsers are integrated as libraries or source-reviewed adapters where practical. The suite does not download tools at runtime or present a folder of third-party EXEs. MIT/BSD components may be embedded in the self-contained build with notices; every parser still returns the DBDR schema, cancellation behavior, coverage status and redacted paths.
