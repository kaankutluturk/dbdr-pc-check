# Threat model

## Goals

- Make routine authorized PC-check evidence collection consistent.
- Preserve volatile live-process facts before slower enrichment.
- Correlate narrowly selected Windows sources without overstating them.
- Separate source observations, neutral review items, coverage gaps and moderation conclusions.
- Minimize unrelated personal data.
- Make accidental post-collection modification detectable through a manifest.
- Continue collecting when one source is inaccessible.

## Non-goals

- Proving that a machine is clean.
- Defeating a hostile kernel or compromised operating system.
- Detecting DMA hardware conclusively from device inventory.
- Performing memory forensics or reverse engineering.
- Reconstructing general browsing, chat or command-line activity.
- Replacing staff review, policy or an appeal process.

## Trust boundaries

The suite runs inside the checked Windows installation. A sufficiently privileged adversary can manipulate APIs, files, registry results, logs and timestamps. The SHA-256 manifest detects changes after packaging but does not prove that Windows supplied truthful evidence.

The packaged suite intentionally runs with an elevated token. A compromised release, native dependency, parser or custom rule path would therefore have high impact even though the intended collectors are read-only. Production use depends on Authenticode signing, reviewable build provenance, bounded hostile-input parsers and rules obtained from a trusted case workflow.

The process snapshot is cached before slower module/file inspection. This reduces but cannot eliminate process exit, PID reuse, path replacement and time-of-check/time-of-use races. Basic file identity is compared before and after hashing, but a privileged hostile system can still deceive the collector.

The encrypted `.dbdr` format authenticates content using a case passphrase, but it cannot compensate for a weak, reused, disclosed or lost passphrase. PBKDF2 raises offline-guessing cost but does not make a low-entropy password safe. Plaintext working data can briefly exist in the local temporary directory during packaging or verified reopening; abrupt system failure can defeat best-effort cleanup. Legacy ZIP manifests detect modification only when the expected manifest is trusted and can be recomputed by an attacker.

## Source-specific limitations

- **BAM:** layout and retention vary by Windows version and configuration. A missing key or entry is not proof of absence.
- **Prefetch:** v0.5.0 parses executable name, format version, run count and last-run FILETIMEs under explicit file-count, compressed-input and declared-decompression limits. Referenced-file lists, volume identifiers and raw bytes are not serialized.
- **Event Log:** channels can be disabled, cleared, inaccessible or truncated. The collector caps inspection per configured query and reports coverage.
- **Amcache:** the live inventory is incomplete, version-dependent and not an execution log. A file entry, link date or absent entry does not prove execution, account ownership, installation time or evasion. The collector limits output to executable file types and reports its 5,000-record cap.
- **Application crashes:** Application Error event fields vary with Windows/provider versions. A crash can be benign, and the absence of a crash event can reflect retention or channel access. Dump content is not collected.
- **PowerShell lifecycle:** events 400, 403 and 600 show engine/provider activity, not the command or actor. Legitimate software frequently hosts PowerShell, and payload exclusion intentionally prevents command reconstruction.
- **USN Journal:** the opt-in adapter reads only a bounded recent journal tail and emits execution-capable leaf filenames. The tail can omit older review-window activity on busy volumes, timestamps and journals can be manipulated by a privileged adversary, and the lack of reconstructed parent paths deliberately limits interpretation. A create/delete sequence is a review lead, not proof of evasion.
- **Scheduled tasks:** command arguments and principals are excluded for privacy, so the record is intentionally incomplete.
- **Devices:** only non-unique model identifiers are retained. VID/PID or VEN/DEV values identify a model family, not a particular device or DMA behavior.
- **Module lists:** file-backed modules do not establish the absence of non-file-backed, kernel-level or external manipulation.
- **Loaded drivers:** PSAPI exposes registered loaded image paths, not arbitrary kernel allocations or manual maps. Windows 11 24H2 can return all-null handles when SeDebugPrivilege is not enabled; that condition is reported as a gap. Kernel base addresses are never serialized.
- **Hashes/signatures:** unsigned, unknown or inaccessible files are weak observations and require corroboration.
- **PE structure/imports:** writable+executable sections, packer-like names, overlays and loader-capable APIs also occur in legitimate protectors, launchers, anti-cheat, overlays, accessibility and administration tools. The parser is capped and treats malformed/capped input explicitly. The analysis profile requires path or signature context for structural review findings.
- **Entropy:** packed, compressed and encrypted legitimate software can have high entropy. The analyzer correlates high entropy with signature and structural context but still produces only a review item.
- **YARA:** rule quality, scope and version directly control false positives and false negatives. The suite records ruleset hashes and rule identifiers so a reviewer can reproduce and challenge a match. Because the managed wrapper does not expose YARA's native timeout API, production scans run in a killable same-EXE worker with a 20-second per-file deadline. Inputs and reported matches are capped. A match never creates a verdict.
- **Security posture:** Secure Boot, VBS, memory integrity, driver-blocklist and App Control state describe protection layers, not behavior. Disabled or unavailable protection is not proof of tampering or cheating.

## Abuse cases

- A staff member requests collection without a valid case or consent.
- A broad source exposes unrelated personal data.
- A reviewer infers account ownership or a cheat-site subscription from an application name, path or timestamp without corroboration.
- A malicious fork impersonates an official collector.
- A reviewer treats a weak observation, model identifier, missing artifact or source failure as conclusive.
- A local attacker tampers with evidence before packaging.
- A build workflow, rule pack or signing secret is compromised.
- A custom YARA rule is excessively broad, resource-intensive or misleading.
- A future backend retains evidence indefinitely or exposes it to unauthorized staff.

Mitigations include visible authorization, operator-selectable modules, strict exclusions, source-specific coverage, path/device redaction, deterministic neutral findings, signed releases, reproducible CI, bundle manifests, access control and mandatory human review.
