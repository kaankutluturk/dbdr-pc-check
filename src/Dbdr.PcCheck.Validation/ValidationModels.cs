using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Validation;

internal sealed record ValidationFixture(
    string SchemaVersion,
    string Name,
    string Description,
    DateTimeOffset ReviewWindowStartUtc,
    DateTimeOffset ReviewWindowEndUtc,
    IReadOnlyList<ValidationModuleFixture> Modules,
    IReadOnlyList<ValidationFinding> ExpectedFindings);

internal sealed record ValidationModuleFixture(
    string Module,
    bool Completed,
    IReadOnlyList<ValidationRecordFixture> Records,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Errors);

internal sealed record ValidationRecordFixture(
    string Kind,
    string Source,
    DateTimeOffset? SourceTimestampUtc,
    IReadOnlyDictionary<string, string?> Fields);

internal sealed record ValidationFinding(
    FindingDisposition Disposition,
    string Title,
    string Module,
    string? RecordKind);

internal sealed record ValidationFixtureResult(
    string Name,
    string Description,
    bool Passed,
    int ExpectedCount,
    int ActualCount,
    int MatchedCount,
    IReadOnlyList<ValidationFinding> Missing,
    IReadOnlyList<ValidationFinding> Unexpected,
    IReadOnlyList<ValidationFinding> ActualFindings);

internal sealed record DetectionValidationReport(
    string SchemaVersion,
    string AnalysisProfileVersion,
    bool Passed,
    int FixtureCount,
    int PassedFixtureCount,
    int CleanFixtureCount,
    int PassedCleanFixtureCount,
    int ExpectedFindingCount,
    int ActualFindingCount,
    int TruePositiveCount,
    int FalsePositiveCount,
    int FalseNegativeCount,
    double Precision,
    double Recall,
    double F1Score,
    IReadOnlyDictionary<string, int> ExpectedDispositionCoverage,
    IReadOnlyList<ValidationFixtureResult> Fixtures);
