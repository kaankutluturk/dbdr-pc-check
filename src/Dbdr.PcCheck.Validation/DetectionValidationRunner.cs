using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Validation;

internal static class DetectionValidationRunner
{
    public const string FixtureSchemaVersion = "dbdr-detection-fixture/1";
    public const string ReportSchemaVersion = "dbdr-detection-validation/1";
    public const int MaximumFixtureFiles = 256;
    public const long MaximumFixtureBytes = 1024 * 1024;
    public const int MaximumModulesPerFixture = 64;
    public const int MaximumRecordsPerFixture = 2048;

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        MaxDepth = 32,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static async Task<DetectionValidationReport> RunAsync(
        string fixtureDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fixtureDirectory);
        var directory = new DirectoryInfo(fixtureDirectory);
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException($"Detection fixture directory not found: {directory.FullName}");
        }

        var files = directory
            .EnumerateFiles("*.json", SearchOption.TopDirectoryOnly)
            .OrderBy(file => file.Name, StringComparer.Ordinal)
            .ToArray();
        if (files.Length is 0 or > MaximumFixtureFiles)
        {
            throw new InvalidDataException(
                $"Detection fixture directory must contain between 1 and {MaximumFixtureFiles.ToString(CultureInfo.InvariantCulture)} JSON files.");
        }

        var results = new List<ValidationFixtureResult>(files.Length);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (file.Length is <= 0 or > MaximumFixtureBytes)
            {
                throw new InvalidDataException(
                    $"Fixture {file.Name} must be between 1 byte and {MaximumFixtureBytes.ToString(CultureInfo.InvariantCulture)} bytes.");
            }

            await using var stream = new FileStream(
                file.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            ValidationFixture fixture;
            try
            {
                fixture = await JsonSerializer.DeserializeAsync<ValidationFixture>(
                        stream,
                        ReadOptions,
                        cancellationToken)
                    .ConfigureAwait(false)
                    ?? throw new InvalidDataException($"Fixture {file.Name} is empty.");
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException($"Fixture {file.Name} is not valid detection-fixture JSON.", exception);
            }

            ValidateFixture(fixture, file.Name);
            if (!names.Add(fixture.Name))
            {
                throw new InvalidDataException($"Fixture name is duplicated: {fixture.Name}");
            }

            results.Add(Evaluate(fixture));
        }

        var expectedCount = results.Sum(result => result.ExpectedCount);
        var actualCount = results.Sum(result => result.ActualCount);
        var truePositiveCount = results.Sum(result => result.MatchedCount);
        var falsePositiveCount = results.Sum(result => result.Unexpected.Count);
        var falseNegativeCount = results.Sum(result => result.Missing.Count);
        var precision = Ratio(truePositiveCount, truePositiveCount + falsePositiveCount);
        var recall = Ratio(truePositiveCount, truePositiveCount + falseNegativeCount);
        var f1 = precision + recall == 0
            ? 0
            : Math.Round(2 * precision * recall / (precision + recall), 4, MidpointRounding.AwayFromZero);
        var clean = results.Where(result => result.ExpectedCount == 0).ToArray();
        var dispositionCoverage = results
            .SelectMany(result => result.ActualFindings.Where(finding =>
                !result.Unexpected.Contains(finding)))
            .GroupBy(finding => finding.Disposition)
            .OrderBy(group => group.Key)
            .ToDictionary(
                group => group.Key.ToString(),
                group => group.Count(),
                StringComparer.Ordinal);

        return new DetectionValidationReport(
            ReportSchemaVersion,
            EvidenceAnalyzer.AnalysisProfileVersion,
            results.All(result => result.Passed),
            results.Count,
            results.Count(result => result.Passed),
            clean.Length,
            clean.Count(result => result.Passed),
            expectedCount,
            actualCount,
            truePositiveCount,
            falsePositiveCount,
            falseNegativeCount,
            precision,
            recall,
            f1,
            dispositionCoverage,
            results);
    }

    public static async Task WriteReportAsync(
        DetectionValidationReport report,
        string outputDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        Directory.CreateDirectory(outputDirectory);
        var json = JsonSerializer.Serialize(report, WriteOptions) + Environment.NewLine;
        var markdown = RenderMarkdown(report);
        await File.WriteAllTextAsync(
                Path.Combine(outputDirectory, "detection-validation.json"),
                json,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                cancellationToken)
            .ConfigureAwait(false);
        await File.WriteAllTextAsync(
                Path.Combine(outputDirectory, "detection-validation.md"),
                markdown,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static ValidationFixtureResult Evaluate(ValidationFixture fixture)
    {
        var context = new CollectionContext(
            $"validation-{Slug(fixture.Name)}",
            fixture.ReviewWindowStartUtc,
            fixture.ReviewWindowEndUtc,
            fixture.ReviewWindowEndUtc,
            "detection-validation");
        var modules = fixture.Modules.Select(module => new ModuleResult(
                module.Module,
                module.Completed,
                TimeSpan.Zero,
                module.Records.Select(record => new EvidenceRecord(
                        module.Module,
                        record.Kind,
                        record.Source,
                        fixture.ReviewWindowEndUtc,
                        record.SourceTimestampUtc,
                        record.Fields))
                    .ToArray(),
                module.Warnings,
                module.Errors))
            .ToArray();
        var run = new CollectionRunResult(context, fixture.ReviewWindowEndUtc, modules);
        var actual = EvidenceAnalyzer.Analyze(run)
            .Select(finding => new ValidationFinding(
                finding.Disposition,
                finding.Title,
                finding.Module,
                finding.RecordKind))
            .OrderBy(FindingKey, StringComparer.Ordinal)
            .ToArray();
        var expected = fixture.ExpectedFindings
            .OrderBy(FindingKey, StringComparer.Ordinal)
            .ToArray();
        var expectedSet = expected.ToHashSet();
        var actualSet = actual.ToHashSet();
        var missing = expected
            .Where(finding => !actualSet.Contains(finding))
            .ToArray();
        var unexpected = actual
            .Where(finding => !expectedSet.Contains(finding))
            .ToArray();

        return new ValidationFixtureResult(
            fixture.Name,
            fixture.Description,
            missing.Length == 0 && unexpected.Length == 0,
            expected.Length,
            actual.Length,
            expected.Length - missing.Length,
            missing,
            unexpected,
            actual);
    }

    private static void ValidateFixture(ValidationFixture fixture, string fileName)
    {
        if (!string.Equals(fixture.SchemaVersion, FixtureSchemaVersion, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Fixture {fileName} uses unsupported schema {fixture.SchemaVersion ?? "<missing>"}.");
        }

        if (string.IsNullOrWhiteSpace(fixture.Name) || fixture.Name.Length > 120)
        {
            throw new InvalidDataException($"Fixture {fileName} has an invalid name.");
        }

        if (string.IsNullOrWhiteSpace(fixture.Description) || fixture.Description.Length > 500)
        {
            throw new InvalidDataException($"Fixture {fileName} has an invalid description.");
        }

        if (fixture.ReviewWindowStartUtc >= fixture.ReviewWindowEndUtc)
        {
            throw new InvalidDataException($"Fixture {fileName} has an invalid review window.");
        }

        if (fixture.Modules is null || fixture.Modules.Count is 0 or > MaximumModulesPerFixture)
        {
            throw new InvalidDataException($"Fixture {fileName} has an invalid module count.");
        }

        var recordCount = 0;
        foreach (var module in fixture.Modules)
        {
            if (string.IsNullOrWhiteSpace(module.Module)
                || module.Records is null
                || module.Warnings is null
                || module.Errors is null)
            {
                throw new InvalidDataException($"Fixture {fileName} contains an invalid module.");
            }

            recordCount += module.Records.Count;
            foreach (var record in module.Records)
            {
                if (string.IsNullOrWhiteSpace(record.Kind)
                    || string.IsNullOrWhiteSpace(record.Source)
                    || record.Fields is null)
                {
                    throw new InvalidDataException($"Fixture {fileName} contains an invalid evidence record.");
                }

                if (record.SourceTimestampUtc is { } timestamp
                    && (timestamp < fixture.ReviewWindowStartUtc || timestamp > fixture.ReviewWindowEndUtc))
                {
                    throw new InvalidDataException($"Fixture {fileName} contains an out-of-window source timestamp.");
                }
            }
        }

        if (recordCount > MaximumRecordsPerFixture)
        {
            throw new InvalidDataException($"Fixture {fileName} exceeds the record cap.");
        }

        if (fixture.ExpectedFindings is null)
        {
            throw new InvalidDataException($"Fixture {fileName} is missing expectedFindings.");
        }

        var expectedKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var finding in fixture.ExpectedFindings)
        {
            if (string.IsNullOrWhiteSpace(finding.Title)
                || string.IsNullOrWhiteSpace(finding.Module)
                || !expectedKeys.Add(FindingKey(finding)))
            {
                throw new InvalidDataException($"Fixture {fileName} contains an invalid or duplicate expected finding.");
            }
        }
    }

    private static string RenderMarkdown(DetectionValidationReport report)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# DBDR detection validation");
        builder.AppendLine();
        builder.AppendLine($"- Profile: `{report.AnalysisProfileVersion}`");
        builder.AppendLine($"- Result: **{(report.Passed ? "PASS" : "FAIL")}**");
        builder.AppendLine($"- Fixtures: {report.PassedFixtureCount}/{report.FixtureCount} passed");
        builder.AppendLine($"- Exact-match precision / recall / F1: {report.Precision:F4} / {report.Recall:F4} / {report.F1Score:F4}");
        builder.AppendLine($"- Matched / unexpected / missing findings: {report.TruePositiveCount} / {report.FalsePositiveCount} / {report.FalseNegativeCount}");
        builder.AppendLine();
        builder.AppendLine("These deterministic synthetic fixtures are regression and rule-contract tests. They do not estimate real-world cheat prevalence, field accuracy or a moderation verdict.");
        builder.AppendLine();
        builder.AppendLine("| Fixture | Result | Expected | Actual | Missing | Unexpected |");
        builder.AppendLine("| --- | --- | ---: | ---: | ---: | ---: |");
        foreach (var fixture in report.Fixtures)
        {
            builder.AppendLine($"| {EscapeMarkdown(fixture.Name)} | {(fixture.Passed ? "PASS" : "FAIL")} | {fixture.ExpectedCount} | {fixture.ActualCount} | {fixture.Missing.Count} | {fixture.Unexpected.Count} |");
        }

        foreach (var fixture in report.Fixtures.Where(result => !result.Passed))
        {
            builder.AppendLine();
            builder.AppendLine($"## {fixture.Name}");
            foreach (var missing in fixture.Missing)
            {
                builder.AppendLine($"- Missing: `{FindingKey(missing)}`");
            }

            foreach (var unexpected in fixture.Unexpected)
            {
                builder.AppendLine($"- Unexpected: `{FindingKey(unexpected)}`");
            }
        }

        return builder.ToString();
    }

    private static double Ratio(int numerator, int denominator) =>
        denominator == 0
            ? 1
            : Math.Round((double)numerator / denominator, 4, MidpointRounding.AwayFromZero);

    private static string FindingKey(ValidationFinding finding) =>
        $"{finding.Disposition}|{finding.Title}|{finding.Module}|{finding.RecordKind ?? "<none>"}";

    private static string Slug(string value)
    {
        var characters = value
            .ToLowerInvariant()
            .Select(character => char.IsAsciiLetterOrDigit(character) ? character : '-')
            .ToArray();
        return new string(characters).Trim('-');
    }

    private static string EscapeMarkdown(string value) => value.Replace("|", "\\|", StringComparison.Ordinal);
}
