# Evidence schema 0.1.1

The v0.1.1 bundle is a ZIP with the following entries. `case.json` contains the explicit `evidenceSchemaVersion` value `0.1.1`.

| Entry                 | Purpose                                                                     |
| --------------------- | --------------------------------------------------------------------------- |
| `case.json`           | Case identifier, review window, collector version and collection timestamps |
| `evidence.json`       | Module results and normalized evidence records                              |
| `collection-log.json` | Module success state, duration, warnings and errors                         |
| `report.html`         | Offline human-readable summary                                              |
| `privacy.txt`         | Reminder of the v0.1 collection boundary                                    |
| `manifest.sha256`     | SHA-256 for every other entry in ordinal filename order                     |

## Evidence record

Every normalized record contains:

- `module`: collector module that produced the record;
- `kind`: stable record category;
- `source`: Windows source or API used for the observation;
- `collectedAtUtc`: timestamp at which the collector created the normalized record;
- `sourceTimestampUtc`: nullable timestamp supplied by the underlying Windows source; and
- `fields`: string-keyed properties specific to the record kind.

`collectedAtUtc` and `sourceTimestampUtc` are not interchangeable. A live-state record can have no source timestamp. For `process.snapshot`, the source timestamp is the process creation time reported by `Win32_Process`; it is not the time at which the collector first observed the process.

Null or unavailable values are represented explicitly. A module-level exception is written to the collection log and does not erase successful results from other modules.

## v0.1.1 record kinds

- `system.snapshot`
- `process.snapshot`
- `game.snapshot`
- `process.module`
- `file.metadata`
- `persistence.run_key`
- `persistence.service`
- `persistence.driver`

### Live-state ordering

`process.snapshot` records are captured before module enumeration and executable hashing. `game.snapshot` records whether matching game processes were present and whether module enumeration succeeded. `process.module` and `file.metadata` records contain an `identityStableDuringInspection` field so a reviewer can identify files whose basic identity changed during hashing and signature inspection.

No record kind is a moderation verdict. Schema additions must be documented before implementation.
