using System.Globalization;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core;

public sealed record EvidenceCoverageSummary(
    int RecordCount,
    int InformationalFindingCount,
    int ReviewFindingCount,
    int CoverageGapCount,
    int ModuleCount,
    int CompletedModuleCount,
    int SourceCount,
    int AvailableSourceCount,
    int LimitedSourceCount,
    int UnavailableSourceCount)
{
    public static EvidenceCoverageSummary Create(CollectionRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var sources = result.Records
            .Where(record => record.Kind == "coverage.source")
            .DistinctBy(record => SourceKey(record), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var available = sources.Count(record => string.Equals(
            Get(record, "status"),
            "available",
            StringComparison.OrdinalIgnoreCase));
        var limited = sources.Count(record => IsLimited(record));
        var unavailable = sources.Count(record => IsUnavailable(Get(record, "status")));

        return new EvidenceCoverageSummary(
            result.Records.Count,
            result.Findings.Count(finding => finding.Disposition == FindingDisposition.Informational),
            result.Findings.Count(finding => finding.Disposition == FindingDisposition.NeedsReview),
            result.Findings.Count(finding => finding.Disposition == FindingDisposition.CoverageGap),
            result.Modules.Count,
            result.Modules.Count(module => module.Completed),
            sources.Length,
            available,
            limited,
            unavailable);
    }

    private static string SourceKey(EvidenceRecord record) =>
        $"{record.Module}\u001f{Get(record, "sourceName") ?? record.Source}";

    private static bool IsLimited(EvidenceRecord record)
    {
        var detail = Get(record, "detail");
        return detail?.Contains("capped=true", StringComparison.OrdinalIgnoreCase) == true
            || detail?.Contains("enumerationCapped=true", StringComparison.OrdinalIgnoreCase) == true
            || HasNonZeroMetric(detail, "parseFailures");
    }

    private static bool IsUnavailable(string? status) =>
        string.Equals(status, "unavailable", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "disabled", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "notSupported", StringComparison.OrdinalIgnoreCase);

    private static bool HasNonZeroMetric(string? detail, string key)
    {
        if (string.IsNullOrWhiteSpace(detail))
        {
            return false;
        }

        foreach (var segment in detail.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var pair = segment.Split('=', 2, StringSplitOptions.TrimEntries);
            if (pair.Length == 2
                && string.Equals(pair[0], key, StringComparison.OrdinalIgnoreCase)
                && int.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value)
                && value > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static string? Get(EvidenceRecord record, string key) =>
        record.Fields.TryGetValue(key, out var value) ? value : null;
}
