# Privacy boundary

## Purpose

DBDR Evidence Suite creates a proportionate system-evidence snapshot for an authorized PC check. The v0.2.0 development build writes the result locally and performs no network upload.

## Always-collected case metadata

- User-entered case identifier and explicit review-window start and end timestamps.
- Collector/schema/analysis versions and collection timestamps.
- Windows/runtime version, architecture, time zone, uptime and whether the collector is elevated.
- Module duration, warnings, access failures and source-coverage status.

## Operator-selectable evidence in v0.2.0

- Running process name, process ID, parent process ID, session ID, creation time and redacted executable path where Windows exposes it.
- For accessible executable files: redacted path, size, timestamps, SHA-256, version metadata, Authenticode status and whether basic identity remained stable during inspection.
- For running processes whose name contains `DeadByDaylight`: file-backed module name and redacted path plus the same file metadata where accessible.
- Time-bounded BAM registry observations.
- Time-bounded Prefetch **file metadata**. The last-write timestamp is labeled as file metadata and is not presented as a parsed execution timestamp.
- Time-bounded Service Control Manager service-install events and Code Integrity warning/error event metadata. Account names and general event messages are excluded.
- Registry Run-key entry name and redacted value.
- Service and system-driver name, display name, state, start mode and redacted image path.
- Scheduled-task path, redacted executable command, enabled/hidden state, trigger classes, registration timestamp where parseable and definition-file modification time.
- Plug and Play device name, class, manufacturer, status, service, configuration error code and non-unique USB/PCI model identifier where available.
- Neutral automated review items and explicit coverage gaps derived from the collected records.

Scheduled-task arguments and principal identities are not serialized. Unique Plug and Play instance identifiers and serial-number suffixes are not serialized.

Windows user-directory paths are replaced with `%USERPROFILE%` before serialization, including drive-letter and NT device paths. The suite does not intentionally record the computer name, account name, email address, Steam ID, IP address or hardware serial number.

## Explicit exclusions

The suite does not collect:

- browser history, downloads, cookies, sessions or saved credentials;
- Discord or other chat contents;
- password-manager data;
- screenshots, webcam or microphone data;
- clipboard contents;
- arbitrary Documents, Desktop or cloud-storage contents;
- DNS cache or general browsing destinations;
- PowerShell or terminal history;
- scheduled-task arguments or task-principal identities;
- raw process-memory dumps, memory contents or memory-derived strings;
- module base addresses;
- unique device-instance identifiers or serial-number suffixes;
- copies of executables, DLLs or personal files; or
- automatic network reputation lookups containing player evidence.

## Local handling

The v0.2.0 ZIP is not encrypted. It may contain sensitive system metadata and must be treated as confidential. Do not post bundles in public Discord channels, GitHub issues or other public locations.

Production use requires a documented controller, purpose, lawful basis, retention period, access policy, deletion procedure and appeal path. Any future upload must use authenticated encryption and explicit case-scoped authorization. A production client must never embed a private signing or decryption key.
