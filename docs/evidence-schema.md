# Evidence schema

The v0.1 bundle is a ZIP with the following entries.

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
- `observedAtUtc`: collection timestamp; and
- `fields`: string-keyed properties specific to the record kind.

Null or unavailable values are represented explicitly. A module-level exception is written to the collection log and does not erase successful results from other modules.

## v0.1 record kinds

- `system.snapshot`
- `process.snapshot`
- `persistence.run_key`
- `persistence.service`
- `persistence.driver`

Schema additions must be documented before implementation.
