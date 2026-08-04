using System.Text.RegularExpressions;

namespace Dbdr.PcCheck.Collector.Core;

public static partial class CaseIdValidator
{
    public static bool IsValid(string? caseId) =>
        !string.IsNullOrWhiteSpace(caseId) &&
        caseId.Length <= 64 &&
        ValidCaseId().IsMatch(caseId);

    [GeneratedRegex("^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex ValidCaseId();
}
