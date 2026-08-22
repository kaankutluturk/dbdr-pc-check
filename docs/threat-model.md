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

The process snapshot is cached before slower module/file inspection. This reduces but cannot eliminate process exit, PID reuse, path replacement and time-of-check/time-of-use races. Basic file identity is compared before and after hashing, but a privileged hostile system can still deceive the collector.

## Source-specific limitations

- **BAM:** layout and retention vary by Windows version and configuration. A missing key or entry is not proof of absence.
- **Prefetch:** v0.4.0 records file metadata only. File last-write time is not treated as a fully parsed execution timestamp.
- **Event Log:** channels can be disabled, cleared, inaccessible or truncated. The collector caps inspection per configured query and reports coverage.
- **Amcache:** the live inventory is incomplete, version-dependent and not an execution log. A file entry, link date or absent entry does not prove execution, account ownership, installation time or evasion. The collector limits output to executable file types and reports its 5,000-record cap.
- **Application crashes:** Application Error event fields vary with Windows/provider versions. A crash can be benign, and the absence of a crash event can reflect retention or channel access. Dump content is not collected.
- **PowerShell lifecycle:** events 400, 403 and 600 show engine/provider activity, not the command or actor. Legitimate software frequently hosts PowerShell, and payload exclusion intentionally prevents command reconstruction.
- **Scheduled tasks:** command arguments and principals are excluded for privacy, so the record is intentionally incomplete.
- **Devices:** only non-unique model identifiers are retained. VID/PID or VEN/DEV values identify a model family, not a particular device or DMA behavior.
- **Module lists:** file-backed modules do not establish the absence of non-file-backed, kernel-level or external manipulation.
- **Hashes/signatures:** unsigned, unknown or inaccessible files are weak observations and require corroboration.
- **Entropy:** packed, compressed and encrypted legitimate software can have high entropy. The analyzer correlates high entropy with a non-valid signature but still produces only a review item.
- **YARA:** rule quality, scope and version directly control false positives and false negatives. The suite records ruleset hashes and rule identifiers so a reviewer can reproduce and challenge a match. A match never creates a verdict.

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
