# Evidence schema 0.5.0

`case.json` contains `evidenceSchemaVersion: "0.5.0"` and `analysisProfileVersion: "0.5.0"`.

The operational UI wraps the ZIP entry set in a `.dbdr` version-1 container using chunked AES-256-GCM and a passphrase-derived PBKDF2-SHA256 key. The outer header contains only format/KDF parameters, random salt and nonce prefix, chunk size and plaintext length; case metadata remains inside the encrypted archive. Every chunk authenticates the complete header, its index and length. The passphrase is not stored. Legacy plaintext ZIP bundles can be reopened for migration, but new UI collections require encrypted output.

| Entry | Purpose |
| --- | --- |
| `case.json` | Case identifier, explicit review window, versions and collection timestamps |
| `evidence.json` | Module results and normalized evidence records |
| `findings.json` | Neutral automated review and coverage observations |
| `collection-log.json` | Module completion, duration, warnings and errors |
| `report.html` | Offline human-readable report |
| `privacy.txt` | Bundle-local collection-boundary reminder |
| `manifest.sha256` | SHA-256 for every other entry in ordinal filename order |

Reopening is performed without archive extraction. The reader rejects nested paths, duplicate or unexpected entries, oversized compressed/decompressed content, incomplete manifests, hash mismatches, unsupported schemas and normalized record counts above fixed limits before exposing evidence to the UI. Manifest verification detects changes to a legacy ZIP but does not prove its author; the authenticated `.dbdr` container additionally prevents modification without the case passphrase.

## Evidence record

Every normalized record contains:

- `module`: collector module that produced the record;
- `kind`: stable record category;
- `source`: Windows source or API used for the observation;
- `collectedAtUtc`: time the normalized record was created;
- `sourceTimestampUtc`: nullable timestamp supplied or directly represented by the source; and
- `fields`: string-keyed properties specific to the record kind.

`collectedAtUtc` and `sourceTimestampUtc` are not interchangeable. For `process.snapshot`, the source timestamp is process creation time. For `execution.prefetch`, it is a parsed Prefetch last-run FILETIME inside the explicit review window. The record retains its timestamp basis, parser version, executable name and run count but excludes referenced-file and volume lists.

Null and unavailable values remain explicit. Module/source failures do not erase successful records.

## Source coverage

`coverage.source` records contain:

- `sourceName`;
- `status`: `available`, `empty`, `unavailable`, `disabled` or `notSupported`;
- `recordCount`; and
- `detail`.

`empty` means the source was readable but produced no records under the collector's filter. It does not mean the checked machine is clean.
An operator-unchecked optional source is still represented with `status: "disabled"`; it never silently disappears from coverage.

## Findings

Each item in `findings.json` contains a stable run-local ID, disposition, title, detail, originating module and optional record kind. Dispositions are:

- `informational`;
- `needsReview`; and
- `coverageGap`.

Findings are deterministic summaries of collected evidence and collection failures. They are not cheating verdicts and do not encode moderation outcomes.

## Binary triage fields

`process.module`, `file.metadata` and `persistence.binary` records may include:

- `entropyBitsPerByte` and `entropyClassification` (`ordinary`, `elevated` or `high`);
- `authenticodeStatus`, `authenticodeVerificationMode`, and embedded-signer subject, issuer, certificate thumbprint and validity interval when Windows exposes them;
- `yaraStatus` (`disabled`, `no-match`, `matched`, `skipped-size-limit` or `unavailable`);
- `yaraMatchCount` and `yaraMatches`, containing rule identifiers only;
- `yaraRulesets` and `yaraRulesetSha256`, which identify the rule material used;
- `yaraRulesetTrust`, mapping each ruleset to `embedded`, `operator-supplied-unverified` or `ecdsa-p256-sha256-verified`; and
- `yaraError`, containing only an exception type when the scan was unavailable; and
- `yaraMaximumFileSizeBytes`, identifying the scan ceiling; and
- `yaraMatchesTruncated`, identifying when the 256-rule-identifier reporting cap was reached.

For PE files these records can also include `peStatus`, `peMachine`, `peFormat`, `peSubsystem`, `peIsManaged`, `peLinkerTimestampUtc`, `peLinkerTimestampBasis`, `peSectionCount`, `peSections`, `peHighEntropySectionCount`, `peWritableExecutableSectionCount`, `peSuspiciousSectionNames`, `peImportDllCount`, `peImportApiCount`, `peImportFingerprintSha256`, `peSuspiciousImports`, `peImportRiskClusters`, `peOverlaySizeBytes`, `peOverlayEntropyBitsPerByte`, `peOverlayEntropyClassification`, `peCertificateTablePresent`, `pePdbFileName` and `peInspectionError`. The import fingerprint hashes the bounded normalized DLL/API-name set for correlation without serializing the full set. Section entropy is sampled at no more than 4 MiB per section and 32 MiB total per file; overlay entropy is sampled at no more than 4 MiB. Import and section counts are capped. `peLinkerTimestampUtc` is explicitly untrusted linker metadata, not a file-system or execution time.

The schema never stores YARA match bytes, offsets, custom rule contents, signed-pack manifests/signatures or a copy of the scanned file. A verified pack is identified as `signed:{packId}@{version}` after exact-container, expiry, profile, SHA-256 and ECDSA P-256/SHA-256 checks; raw operator rules remain explicitly unverified. Production scans run in a killable instance of the same executable with a 20-second per-file timeout; cancellation or timeout terminates that helper. Entropy and YARA results are observations. The analysis profile creates a neutral review item for a YARA match or for the correlation of high entropy with a non-valid signature; neither is a verdict.

## Extended forensic metadata

The opt-in extended source group adds five record kinds:

- `execution.amcache`: current executable application inventory. Fields can include `fileName`, redacted `executablePath`, publisher/product/version data, binary type, size and `linkDate`. `sourceTimestampUtc` is null; `linkDate` is labeled file metadata and is not an execution time. Collection is capped at 5,000 executable records.
- `event.application_crash`: time-bounded Application Error event 1000 metadata. Fields can include application/fault-module name and version, exception code and redacted application/module paths. Message bodies, report identifiers and dumps are absent.
- `event.powershell_engine`: time-bounded Windows PowerShell event 400, 403 or 600 metadata. Fields contain event/provider identifiers, level and a normalized lifecycle value. Event payloads, commands, scripts, script blocks, host arguments and user identities are absent.
- `execution.usn_executable_change`: bounded recent NTFS journal records for execution-capable leaf filenames. Fields contain filename, extension, volume, reason labels and create/delete or rename sequence; parent paths and file references are absent.
- `execution.srum_application`: time-bounded executable application-usage bucket from Microsoft `powercfg /srumutil`. Fields are restricted to `applicationName`, nullable redacted `applicationPath` and `identityForm`; the bucket timestamp is `sourceTimestampUtc`. User IDs, network fields, resource amounts and opaque application identifiers are absent. Collection is capped at a 64 MiB/60-second native export and 5,000 emitted records.

The analyzer can correlate an exact redacted `applicationPath`/`executablePath` across BAM, Amcache or SRUM usage and `process.module`/`persistence.binary` evidence. It emits a review item only when the binary record also has an independent signature, YARA or PE-import signal. The finding preserves no new raw path source and does not resolve links, aliases or parent directories.

## v0.5.0 record kinds

- `system.snapshot`
- `process.snapshot`
- `game.snapshot`
- `process.module`
- `file.metadata`
- `execution.bam`
- `execution.prefetch`
- `execution.amcache`
- `execution.usn_executable_change`
- `execution.srum_application`
- `event.service_install`
- `event.code_integrity`
- `event.application_crash`
- `event.powershell_engine`
- `persistence.run_key`
- `persistence.registry_location`
- `persistence.ifeo_debugger`
- `persistence.startup_file`
- `persistence.wmi_consumer`
- `persistence.service`
- `persistence.driver`
- `persistence.loaded_driver`
- `persistence.binary`
- `persistence.scheduled_task`
- `device.snapshot`
- `coverage.source`

## Collection ordering

The application captures one cached `Win32_Process` snapshot first. It then enumerates file-backed modules for matching live DBD processes, performs optional file enrichment and finally reads slower historical/configuration sources. Each collector remains cancellable and independently failure-isolated.

Schema additions require a documented purpose, privacy update, redaction review and tests before implementation.
