# DBDR PC Check Collector

An experimental, consent-based Windows evidence collector intended to make DBDR PC checks consistent and reviewable.

> **Development status:** v0.1 is not a cheat detector and must not be used as the sole basis for moderation decisions.

## v0.1 scope

The first milestone creates a local ZIP containing:

- collector and case metadata;
- non-identifying Windows and runtime metadata;
- a running-process snapshot;
- executable file hashes, version metadata and Authenticode validation status where accessible;
- registry Run-key persistence;
- Windows service and system-driver metadata;
- per-module errors and access failures;
- a human-readable HTML summary; and
- a SHA-256 manifest covering every report file.

The collector does **not** upload data. It does not inspect browser history, chats, credentials, clipboard contents, screenshots, personal documents, raw process memory, or PowerShell history. It does not terminate processes, modify services, install drivers, attach a debugger, or clear logs.

See [PRIVACY.md](PRIVACY.md) for the complete collection boundary.

## Build

Requirements:

- Windows 10 or Windows 11, x64
- .NET 10 SDK

```powershell
dotnet restore .\DbdrPcCheckCollector.slnx
dotnet build .\DbdrPcCheckCollector.slnx --configuration Release
dotnet test .\DbdrPcCheckCollector.slnx --configuration Release
dotnet publish .\src\Collector.App\Collector.App.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  --output .\artifacts\win-x64
```

## Evidence philosophy

The program records observations, provenance and collection failures. Review policy should distinguish:

- direct indicators;
- corroborated indicators;
- contextual anomalies;
- incomplete collection; and
- no evidence flagged by the current review rules.

“No evidence flagged” must never be represented as “clean.” Memory-only, kernel-level and DMA-based cheating cannot be conclusively excluded by this collector.

## Roadmap

1. Validate the v0.1 schema and privacy boundary on clean Windows VMs.
2. Add narrowly time-bounded Windows execution-history and event-log modules.
3. Add encrypted bundle packaging and a separate staff-side analyzer.
4. Introduce code signing and verifiable release provenance.
5. Consider a private, access-controlled case backend only after policy review.
