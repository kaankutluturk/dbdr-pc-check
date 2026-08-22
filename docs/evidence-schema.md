# Evidence schema 0.3.0

`case.json` contains `evidenceSchemaVersion: "0.3.0"` and `analysisProfileVersion: "0.3.0"`.

| Entry | Purpose |
| --- | --- |
| `case.json` | Case identifier, explicit review window, versions and collection timestamps |
| `evidence.json` | Module results and normalized evidence records |
| `findings.json` | Neutral automated review and coverage observations |
| `collection-log.json` | Module completion, duration, warnings and errors |
| `report.html` | Offline human-readable report |
| `privacy.txt` | Bundle-local collection-boundary reminder |
| `manifest.sha256` | SHA-256 for every other entry in ordinal filename order |

## Evidence record

Every normalized record contains:

- `module`: collector module that produced the record;
- `kind`: stable record category;
- `source`: Windows source or API used for the observation;
- `collectedAtUtc`: time the normalized record was created;
- `sourceTimestampUtc`: nullable timestamp supplied or directly represented by the source; and
- `fields`: string-keyed properties specific to the record kind.

`collectedAtUtc` and `sourceTimestampUtc` are not interchangeable. For `process.snapshot`, the source timestamp is process creation time. For `execution.prefetch`, it is the Prefetch file's last-write time and the record explicitly identifies that timestamp basis; it is not described as a parsed run time.

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

`process.module` and `file.metadata` records may include:

- `entropyBitsPerByte` and `entropyClassification` (`ordinary`, `elevated` or `high`);
- `yaraStatus` (`disabled`, `no-match`, `matched` or `unavailable`);
- `yaraMatchCount` and `yaraMatches`, containing rule identifiers only;
- `yaraRulesets` and `yaraRulesetSha256`, which identify the rule material used; and
- `yaraError`, containing only an exception type when the scan was unavailable.

The schema never stores YARA match bytes, offsets, custom rule contents or a copy of the scanned file. Entropy and YARA results are observations. The analysis profile creates a neutral review item for a YARA match or for the correlation of high entropy with a non-valid signature; neither is a verdict.

## v0.3.0 record kinds

- `system.snapshot`
- `process.snapshot`
- `game.snapshot`
- `process.module`
- `file.metadata`
- `execution.bam`
- `execution.prefetch`
- `event.service_install`
- `event.code_integrity`
- `persistence.run_key`
- `persistence.service`
- `persistence.driver`
- `persistence.scheduled_task`
- `device.snapshot`
- `coverage.source`

## Collection ordering

The application captures one cached `Win32_Process` snapshot first. It then enumerates file-backed modules for matching live DBD processes, performs optional file enrichment and finally reads slower historical/configuration sources. Each collector remains cancellable and independently failure-isolated.

Schema additions require a documented purpose, privacy update, redaction review and tests before implementation.
