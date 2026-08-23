# DBDR Evidence Suite

A consent-based, read-only Windows evidence suite for consistent and reviewable DBDR PC checks.

> **Development status:** v0.5.0 hardens executable and driver triage with a bounded hostile-input PE parser, section entropy, writable+executable-section detection, import-risk clusters, expanded embedded YARA review rules, persistence-binary inspection, Windows code-integrity/security-posture context, authenticated encrypted case bundles, deterministic detection-profile validation and an actual packaged-app launch smoke test. It is not a cheat detector and must not be used as the sole basis for a moderation decision.

## Product shape

The desktop application provides one guided workflow instead of a folder of unrelated forensic utilities:

1. enter the authorized case ID and explicit UTC review window;
2. select the proportionate evidence sources for the case;
3. preserve volatile DBD and process state first;
4. collect slower historical and configuration evidence independently;
5. generate neutral review items and explicit coverage gaps; and
6. export an authenticated encrypted local evidence bundle and offline report; and
7. reopen a `.dbdr` or legacy ZIP bundle only after bounded archive and manifest verification.

Each collector is read-only, independently cancellable and failure-isolated. A failed source does not erase successful evidence from another source.

## v0.5.0 modules

| Module | Current evidence | Important limitation |
| --- | --- | --- |
| Live DBD | Process snapshot, DBD file-backed modules, parent/session identifiers | No process-memory inspection; inaccessible module lists are coverage gaps |
| Executable enrichment | SHA-256, Authenticode, file/version metadata, whole-file and bounded per-section entropy, PE headers/sections/import clusters/overlay metadata, bounded YARA matches and identity-stability check | Unsigned status, packer-like sections, imports and rule matches are observations; multi-signal review is still not proof |
| Execution timeline | Time-bounded BAM records, parsed Prefetch run times, service-install events and Code Integrity warnings/errors | Prefetch parsing is size-bounded and excludes referenced-file and volume lists from evidence |
| Extended forensic metadata | Opt-in capped Amcache executable inventory, time-bounded Application Error/PowerShell lifecycle events and bounded NTFS executable-change history | Amcache is current inventory, not proof of execution; USN parent paths/file references and event messages, commands, scripts and dumps are excluded |
| Persistence | Run/Winlogon/AppInit/boot/LSA/IFEO locations, Startup/WMI/service/driver state, loaded-driver image paths, plus hash/signature/PE/YARA inspection of resolved executable references | Kernel addresses and sensitive command/script contents are excluded; protected or capped enumeration is explicit |
| Scheduled tasks | Task path, executable command, enabled/hidden state and trigger classes plus bounded enrichment of resolved executable commands | Arguments and task principals are intentionally excluded; definitions and enrichment are capped |
| Devices | PnP class, name, manufacturer, service, status and non-unique VID/PID or VEN/DEV model ID | Unique instance IDs/serials are excluded; a model ID does not prove DMA use |
| System posture | Secure Boot, VBS/memory-integrity, App Control and vulnerable-driver-blocklist state exposed by documented Windows sources | A protection being off is context, not evidence of cheating |
| Findings | Neutral `informational`, `needsReview` and `coverageGap` observations | No finding is an automated moderation verdict |
| Module catalog | Searchable status and boundaries for the full requested suite | Planned and privacy-gated entries are labeled; they are not fake enabled tools |
| Evidence explorer | Compact record/finding/source/module coverage dashboard, full finding rationale, one-click finding scope, full-field search and verified reopening of encrypted `.dbdr` or legacy ZIP cases | Counts describe collected normalized evidence and explicit gaps; they are not a clean/cheating score, and reopening never re-queries the endpoint |

The suite does **not** upload evidence. It does not inspect browser history or downloads, chats, credentials, clipboard contents, screenshots, personal documents, PowerShell commands/scripts/history, crash dumps, raw process or kernel memory, or memory-derived strings. It does not terminate processes, modify services, install drivers, attach a debugger or clear logs.

See [PRIVACY.md](PRIVACY.md), [the module roadmap](docs/module-roadmap.md), [evidence schema](docs/evidence-schema.md), [source matrix](docs/source-matrix.md), [architecture](docs/architecture.md), [detection validation](docs/detection-validation.md), [release signing](docs/signing.md) and [threat model](docs/threat-model.md).

## Build

Runtime requirements:

- Windows 10 or Windows 11, x64
- Administrator approval through the Windows UAC prompt on every launch

The packaged application is self-contained and does not require a separate .NET installation. It embeds `requireAdministrator`; declining the UAC prompt exits before the UI or any collection starts. Elevation improves source coverage but does not replace the in-app case scope and explicit authorization checkbox.

Build requirement: .NET 10 SDK.

```powershell
dotnet restore .\DbdrPcCheck.slnx
dotnet build .\DbdrPcCheck.slnx --configuration Release
dotnet test .\DbdrPcCheck.slnx --configuration Release
dotnet run --project .\src\Dbdr.PcCheck.Validation\Dbdr.PcCheck.Validation.csproj `
  --configuration Release --no-build -- `
  .\validation\fixtures .\artifacts\detection-validation
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

Every CI and signed-build path runs the versioned synthetic fixture corpus and publishes exact-match precision, recall and F1 for the analyzer's rule contract. A fixture metric of 1.0000 means the deterministic expected findings were reproduced with no extras; it is not a real-world accuracy claim. See [detection validation](docs/detection-validation.md).

## Module roadmap

The requested WinPrefetch, Autoruns, String Explorer, USB, saved-file, PowerShell, path, MFT, kernel dump, journal, crash, browser, BAM, Amcache and SRUM capabilities are tracked individually in the in-app catalog and [module roadmap](docs/module-roadmap.md). Prefetch, PowerShell, crash and Amcache use real adapters with explicit minimization; browser collection and memory dumps remain excluded. v0.5.0 compensates with stronger executable, driver, Code Integrity and security-posture evidence plus a CI-gated detection regression corpus, while SRUM minimization, broader Windows source fixtures and signed rule distribution remain staged work.
