# DBDR Evidence Suite

A consent-based, read-only Windows evidence suite for consistent and reviewable DBDR PC checks.

> **Development status:** v0.3.0 adds a portable module catalog, scoped evidence search, Shannon entropy and bounded YARA file triage. It is not a cheat detector and must not be used as the sole basis for a moderation decision.

## Product shape

The desktop application provides one guided workflow instead of a folder of unrelated forensic utilities:

1. enter the authorized case ID and explicit UTC review window;
2. select the proportionate evidence sources for the case;
3. preserve volatile DBD and process state first;
4. collect slower historical and configuration evidence independently;
5. generate neutral review items and explicit coverage gaps; and
6. export a local evidence bundle and offline report.

Each collector is read-only, independently cancellable and failure-isolated. A failed source does not erase successful evidence from another source.

## v0.3.0 modules

| Module | Current evidence | Important limitation |
| --- | --- | --- |
| Live DBD | Process snapshot, DBD file-backed modules, parent/session identifiers | No process-memory inspection; inaccessible module lists are coverage gaps |
| Executable enrichment | SHA-256, Authenticode, file/version metadata, Shannon entropy, bounded YARA matches and basic identity-stability check | High entropy, unsigned status and rule matches are review leads, not proof |
| Execution timeline | Time-bounded BAM records, Prefetch file metadata, service-install events and Code Integrity warnings/errors | Prefetch last-write time is not represented as a parsed execution time |
| Persistence | Run keys, services, system drivers | Current state does not prove when an entry was created |
| Scheduled tasks | Task path, executable command, enabled/hidden state and trigger classes | Arguments and task principals are intentionally excluded |
| Devices | PnP class, name, manufacturer, service, status and non-unique VID/PID or VEN/DEV model ID | Unique instance IDs/serials are excluded; a model ID does not prove DMA use |
| Findings | Neutral `needsReview` and `coverageGap` observations | No finding is an automated moderation verdict |
| Module catalog | Searchable status and boundaries for the full requested suite | Planned and privacy-gated entries are labeled; they are not fake enabled tools |
| Evidence explorer | Full-field search with an optional module/source/kind scope | Searches normalized records from the current in-memory run only |

The suite does **not** upload evidence. It does not inspect browser history, browser downloads, chats, credentials, clipboard contents, screenshots, personal documents, PowerShell history, raw process memory or memory-derived strings. It does not terminate processes, modify services, install drivers, attach a debugger or clear logs.

See [PRIVACY.md](PRIVACY.md), [the module roadmap](docs/module-roadmap.md), [evidence schema](docs/evidence-schema.md), [source matrix](docs/source-matrix.md), [architecture](docs/architecture.md) and [threat model](docs/threat-model.md).

## Build

Requirements:

- Windows 10 or Windows 11, x64
- .NET 10 SDK

```powershell
dotnet restore .\DbdrPcCheck.slnx
dotnet build .\DbdrPcCheck.slnx --configuration Release
dotnet test .\DbdrPcCheck.slnx --configuration Release
dotnet publish .\src\Dbdr.PcCheck.App\Dbdr.PcCheck.App.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  --output .\artifacts\win-x64
```

## Evidence standard

Reviewers must distinguish:

- a source observation;
- a rule or correlation that needs human review;
- a collection or source-coverage gap;
- an alternative benign explanation; and
- a moderation conclusion made outside the collector.

“No automated review items” must never be represented as “clean.” Memory-only, kernel-level and DMA-based cheating cannot be conclusively excluded by this suite.

## Module roadmap

The requested WinPrefetch, Autoruns, String Explorer, USB, saved-file, PowerShell, path, MFT, kernel dump, journal, crash, browser, BAM, Amcache and SRUM capabilities are tracked individually in the in-app catalog and [module roadmap](docs/module-roadmap.md). Adapters are enabled only after timestamp semantics, performance limits, redaction behavior, privacy purpose and failure tests are complete. Production backend work additionally requires encrypted transport, signed rule distribution, retention controls and an appeal workflow.
