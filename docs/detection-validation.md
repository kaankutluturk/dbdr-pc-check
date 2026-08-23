# Detection validation

DBDR's analyzer produces neutral `informational`, `needsReview` and `coverageGap` findings from normalized evidence. The detection-validation harness makes that rule contract repeatable and reviewable without collecting live user data.

## What runs

`Dbdr.PcCheck.Validation` loads the versioned JSON files in `validation/fixtures`, constructs synthetic normalized `CollectionRunResult` objects and invokes the same `EvidenceAnalyzer` used by the desktop application. Each fixture declares the complete expected set of finding identities:

- disposition;
- title;
- module; and
- record kind, where applicable.

Any missing or unexpected finding fails the process. CI writes `detection-validation.json` for machines and `detection-validation.md` for reviewers, then uploads both as a 30-day workflow artifact. The normal and production-signing workflows both gate packaging on this result.

The loader rejects unknown fixture fields, unsupported schema versions, duplicate expectations, oversized files, excessive module/record counts and source timestamps outside the fixture's authorized review window. Fixtures are synthetic, path-redacted metadata only. They never query a Windows endpoint or expand the product's evidence boundary.

## Metrics

The report exposes exact-match true positives, unexpected findings as false positives, missing findings as false negatives, and derived precision, recall and F1. It also counts clean fixtures and expected disposition coverage.

A score of `1.0000` means the current deterministic fixture expectations exactly match the current analyzer output. It does **not** estimate field accuracy, cheat prevalence, unknown-cheat coverage, the probability that a person cheated or the correctness of a moderation decision. Real-world calibration requires separately governed, legally obtained, labeled cases and independent review for bias and alternative explanations.

## Local command

```powershell
dotnet restore .\DbdrPcCheck.slnx
dotnet build .\DbdrPcCheck.slnx --configuration Release --no-restore
dotnet run --project .\src\Dbdr.PcCheck.Validation\Dbdr.PcCheck.Validation.csproj `
  --configuration Release --no-build -- `
  .\validation\fixtures .\artifacts\detection-validation
```

## Fixture maintenance

When an analyzer rule is added or intentionally changed:

1. add or update a minimal synthetic fixture that isolates the behavior;
2. include a benign counterexample when a weak signal could create noise;
3. enumerate every expected finding rather than allowing unspecified extras;
4. preserve neutral language and the correct disposition; and
5. review the generated JSON/Markdown diff before accepting the profile change.

Never tune a fixture merely to make a failure disappear. The code change and expectation change should state why the analyzer contract changed.
