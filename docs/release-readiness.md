# Release readiness

Signing is the final release-candidate gate, not a substitute for product verification. Development builds remain explicitly unsigned until the acceptance criteria below are complete.

## Automated gates

Every branch build must:

- restore, build and test with warnings treated as errors;
- reproduce the versioned synthetic detection fixture contract;
- publish exactly one self-contained `DBDR.PcCheck.exe`;
- embed `requireAdministrator` in the executable manifest;
- run the published EXE's bounded end-to-end `--self-test`; and
- package the EXE with a SHA-256 transport hash.

The packaged self-test creates only harmless synthetic temporary data. It verifies WPF resource construction, embedded YARA identity, native libyara extraction, same-executable worker startup, an expected baseline rule match, neutral analysis, AES-256-GCM evidence-bundle writing, reopening, entry caps and manifest verification. Its temporary directory is deleted on a best-effort basis. It never invokes a live evidence collector or network path.

## Manual release-candidate matrix

Before signing a release candidate, record a clean-machine pass for each supported client family:

| Environment | Required checks |
| --- | --- |
| Windows 10 22H2 x64 | UAC prompt, cold launch, authorization gate, minimal collection, cancel, encrypted export, reopen, search and clean exit |
| Windows 11 23H2 x64 | Same checks plus display scaling at 100% and 150% |
| Windows 11 24H2 x64 | Same checks plus current Defender/SmartScreen behavior before and after signing |
| Standard-user account | UAC cancellation exits cleanly; approved administrator credentials launch once without installing or persisting the app |
| Offline machine | Launch, collection, YARA baseline, export and reopen work with networking disabled |

GitHub's Windows Server runner validates packaging and runtime integration but is not evidence of Windows 10/11 client compatibility. A release candidate is not ready until the manual client matrix has named tester, date, OS build, EXE SHA-256 and result recorded.

## Final gates

- No open severity-1 or severity-2 defects in launch, cancellation, redaction, evidence integrity or cleanup.
- Privacy notice, evidence schema, source matrix and UI copy match the actual build.
- The production YARA public trust key is provisioned and a signed, versioned pack is accepted; missing, altered, unknown-key and expired packs are rejected.
- The final unchanged EXE is Authenticode-signed and timestamped, then its signature and SHA-256 are verified independently.
- The signed EXE passes the same packaged self-test and manual smoke checks. Any post-signing byte change invalidates the candidate.

Synthetic fixture precision and recall describe the analyzer's deterministic regression contract only. They do not measure real-world cheat-detection accuracy. A successful self-test means the exercised components worked; it does not mean the checked PC is clean.
