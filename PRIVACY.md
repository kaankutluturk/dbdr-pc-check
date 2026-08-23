# Privacy boundary

## Purpose

DBDR Evidence Suite creates a proportionate system-evidence snapshot for an authorized PC check. The v0.5.0 development build writes the result locally and performs no network upload.

## Always-collected case metadata

- User-entered case identifier and explicit review-window start and end timestamps.
- Collector/schema/analysis versions and collection timestamps.
- Windows/runtime version, architecture, time zone, uptime, whether the collector is elevated and privacy-minimized Windows security posture (Secure Boot, VBS, memory integrity, code-integrity policy and vulnerable-driver-blocklist configuration).
- Module duration, warnings, access failures and source-coverage status.

## Operator-selectable evidence in v0.5.0

- Running process name, process ID, parent process ID, session ID, creation time and redacted executable path where Windows exposes it.
- For accessible executable files already referenced by approved process, module, persistence or task sources: redacted path, size, timestamps, SHA-256, version metadata, WinVerifyTrust status/mode, embedded signer display name/issuer/certificate thumbprint/validity interval where exposed, Shannon entropy and whether basic identity remained stable during inspection. Whole-file inspection has a 2 GiB safety ceiling. Running-process enrichment is capped at 1,024 unique paths, prioritizing DBD and user-writable locations; caps are explicit gaps.
- For that same bounded executable set: hostile-input-bounded PE metadata including architecture, subsystem, managed status, untrusted linker timestamp, section names/permissions/sampled entropy, writable+executable section count, selected import API names/risk-cluster labels and a SHA-256 fingerprint of the bounded normalized import set, overlay size/sampled entropy, certificate-table presence and PDB filename only. Full import sets, full PDB paths and arbitrary binary strings are excluded.
- For that same bounded executable set: YARA scan status, up to 256 matching rule identifiers, truncation state, ruleset labels, ruleset SHA-256 and the enforced file-size ceiling. Matched byte content, offsets and file copies are excluded. An optional self-contained custom rule file is read in place, capped at 4 MiB and not copied into the bundle; include directives are rejected. Scans run in a killable instance of the same executable with a per-file timeout.
- For running processes whose name contains `DeadByDaylight`: file-backed module name and redacted path plus the same file metadata where accessible.
- Time-bounded BAM registry observations.
- Time-bounded parsed Prefetch executable name, version, run count and last-run FILETIMEs. Parsing is local and bounded; referenced-file lists, directory lists, volume identifiers and raw Prefetch bytes are not serialized.
- Time-bounded Service Control Manager service-install events and selected Code Integrity validation/audit/block metadata. Code Integrity fields are restricted to redacted file/process paths, signing-level/verification values, signature count and policy name. Account names, general event messages and non-whitelisted payload fields are excluded.
- Registry Run/RunOnce/Explorer-policy entry name and redacted executable reference; selected Winlogon/boot-execute executable references, AppInit/LSA package values and IFEO image/debugger executable references. Command arguments are excluded, and no referenced file content is opened unless it resolves into the approved executable-enrichment scope.
- Startup-folder file name, extension, redacted path and last-write timestamp. Startup file contents and shortcut targets are excluded.
- WMI permanent event-consumer name and consumer class only. Consumer commands, scripts, queries and payloads are excluded.
- Service and system-driver name, display name, state, start mode and redacted image path. The collector also requests loaded driver image paths through PSAPI but excludes kernel image-base addresses; all-null results on protected Windows versions are an explicit gap. Resolved executable references from loaded/configured drivers, auto-start services, Run/Winlogon/AppInit/IFEO locations and direct Startup-folder executables can receive the same enrichment, capped at 512 unique paths per run.
- Scheduled-task path, redacted executable command, enabled/hidden state, trigger classes, registration timestamp where parseable and definition-file modification time. Task XML is capped at 5,000 definitions and 4 MiB each; up to 256 unique resolved task executables can receive the same enrichment. Arguments and principals remain excluded.
- Plug and Play device name, class, manufacturer, status, service, configuration error code and non-unique USB/PCI model identifier where available.
- When **Extended forensic metadata** is explicitly selected: a capped live Amcache inventory of executable application files, including redacted path, filename, publisher, product/version fields, binary type, size and link-date metadata where present. Amcache inventory is not represented as proof of execution, and its link date is not represented as an execution time.
- When **Extended forensic metadata** is explicitly selected: time-bounded Application Error event 1000 metadata, including the application and fault-module names/versions, exception code and redacted application/module paths. Event messages, report identifiers and dump contents are excluded.
- When **Extended forensic metadata** is explicitly selected: time-bounded Windows PowerShell events 400, 403 and 600. Only event/provider identifiers, level and a normalized engine/provider lifecycle label are retained. Event payloads, commands, scripts, script blocks, host arguments, users and terminal history are excluded.
- When **Extended forensic metadata** is explicitly selected: a read-only tail of each fixed NTFS volume's USN change journal, capped at 64 MiB/250,000 parsed records per volume and 5,000 emitted records. Only execution-capable leaf filenames, extension, volume, change-reason labels, timestamp and create/delete or rename sequence classification inside the review window are emitted. Parent paths, file-reference numbers, document filenames and file contents are excluded.
- Neutral automated review items and explicit coverage gaps derived from the collected records.

Scheduled-task arguments and principal identities are not serialized. Unique Plug and Play instance identifiers and serial-number suffixes are not serialized.

Windows user-directory paths are replaced with `%USERPROFILE%` before serialization, including drive-letter and NT device paths. The suite does not intentionally record the computer name, account name, email address, Steam ID, IP address or hardware serial number.

## Sensitivity and authorization

Executable paths, installed-application inventory, crash facts and lifecycle timestamps can still reveal sensitive activity even after usernames and content are removed. The operator must use a case-specific purpose and review window, select only necessary sources, show the collection boundary before the run and obtain authorization from the person responsible for the checked PC.

The extended metadata option is off by default. Selecting it does not authorize browser reconstruction, credential collection, memory capture or unrelated file review. A source observation identifies an artifact that requires interpretation; it does not by itself prove cheating, account ownership or a subscription.

## Explicit exclusions

The suite does not collect:

- browser history, URLs, page titles, searches, downloads, cookies, sessions, autofill data or saved credentials;
- Discord or other chat contents;
- password-manager data;
- screenshots, webcam or microphone data;
- clipboard contents;
- arbitrary Documents, Desktop or cloud-storage contents;
- DNS cache or general browsing destinations;
- PowerShell commands, scripts, script blocks, event payloads or terminal history;
- scheduled-task arguments or task-principal identities;
- process, kernel or live memory dumps, memory contents or memory-derived strings;
- module base addresses;
- unique device-instance identifiers or serial-number suffixes;
- copies of executables, DLLs or personal files; or
- YARA matched bytes, offsets or custom rule contents; or
- automatic network reputation lookups containing player evidence.

## Local handling

The v0.5.0 ZIP is not encrypted. It may contain sensitive system and application metadata and must be treated as confidential. Do not post bundles in public Discord channels, GitHub issues or other public locations.

Before production use, the organization operating the check must document its controller, purpose, lawful basis, case-scoped access list, retention period, deletion procedure and appeal path. Retain a bundle only as long as the case requires, delete working copies and exports when that period ends, and record any authorized disclosure. Any future upload must use authenticated encryption and explicit case-scoped authorization. A production client must never embed a private signing or decryption key.
