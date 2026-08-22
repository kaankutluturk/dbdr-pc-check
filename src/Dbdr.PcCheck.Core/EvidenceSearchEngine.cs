using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core;

public static class EvidenceSearchEngine
{
    public static IReadOnlyList<EvidenceRecord> Search(
        IEnumerable<EvidenceRecord> records,
        string? query,
        string? moduleScope = null)
    {
        var queryTerms = SplitTerms(query);
        var scopeTerms = SplitTerms(moduleScope);

        return records
            .Where(record => scopeTerms.Count == 0 || scopeTerms.All(term => MatchesScope(record, term)))
            .Where(record => queryTerms.Count == 0 || queryTerms.All(term => MatchesRecord(record, term)))
            .OrderByDescending(record => record.SourceTimestampUtc ?? record.CollectedAtUtc)
            .ThenBy(record => record.Module, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.Kind, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<string> SplitTerms(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool MatchesScope(EvidenceRecord record, string term) =>
        Contains(record.Module, term)
        || Contains(record.Kind, term)
        || Contains(record.Source, term);

    private static bool MatchesRecord(EvidenceRecord record, string term) =>
        MatchesScope(record, term)
        || Contains(record.SourceTimestampUtc?.ToString("O"), term)
        || Contains(record.CollectedAtUtc.ToString("O"), term)
        || record.Fields.Any(field => Contains(field.Key, term) || Contains(field.Value, term));

    private static bool Contains(string? value, string term) =>
        value?.Contains(term, StringComparison.OrdinalIgnoreCase) == true;
}
