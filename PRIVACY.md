# Privacy boundary

## Purpose

DBDR PC Check creates a narrowly scoped system-evidence snapshot for an authorized PC check. The development build writes the result locally and performs no network upload.

## Data collected in v0.1

- User-entered case identifier and the selected two-hour review window.
- Collector version, collection timestamps, Windows version, CPU architecture, time zone and uptime.
- Running process name, process ID, parent process ID, creation time and executable path where Windows exposes it.
- For accessible executable files: redacted path, size, timestamps, SHA-256, version metadata and Authenticode validation status.
- Registry Run-key entry name and redacted value.
- Service and system-driver name, display name, state, start mode and redacted image path.
- Module duration, errors and access failures.

Windows usernames are replaced with `%USERPROFILE%` before serialization. The collector does not intentionally record the computer name, account name, email address, Steam ID, IP address or hardware serial number.

## Explicit exclusions

The collector does not collect:

- browser history, cookies, sessions or saved credentials;
- Discord or other chat contents;
- password-manager data;
- screenshots, webcam or microphone data;
- clipboard contents;
- arbitrary Documents, Desktop or cloud-storage contents;
- DNS cache or general browsing destinations;
- PowerShell or terminal history;
- raw process-memory dumps; or
- copies of executables or personal files.

## Local handling

The v0.1 bundle is not encrypted. It may contain sensitive system metadata and should be treated as confidential. Do not post bundles in public Discord channels, GitHub issues or other public locations.

Production use requires a documented controller, purpose, lawful basis, retention period, access policy, deletion procedure and appeal path. A production upload feature must encrypt evidence before transmission and must not be enabled merely by accepting this development notice.
