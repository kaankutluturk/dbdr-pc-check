using System.Globalization;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core;

public static class EvidenceAnalyzer
{
    public const string AnalysisProfileVersion = "0.2.0";

    public static IReadOnlyList<EvidenceFinding> Analyze(CollectionRunResult result)
    {
        var candidates = new List<FindingCandidate>();

        foreach (var module in result.Modules)
        {
            if (!module.Completed)
            {
                candidates.Add(new FindingCandidate(
                    FindingDisposition.CoverageGap,
                    $"{module.Module} collection incomplete",
                    "The collector could not complete this module. Absence of its records is not a clean finding.",
                    module.Module,
                    null));
            }

            foreach (var error in module.Errors)
            {
                candidates.Add(new FindingCandidate(
                    FindingDisposition.CoverageGap,
                    $"{module.Module} error",
                    error,
                    module.Module,
                    null));
            }

            foreach (var warning in module.Warnings)
            {
                candidates.Add(new FindingCandidate(
                    FindingDisposition.CoverageGap,
                    $"{module.Module} coverage warning",
                    warning,
                    module.Module,
                    null));
            }
        }

        foreach (var record in result.Records)
        {
            AnalyzeCoverage(record, candidates);
            AnalyzeFileInspection(record, candidates);
            AnalyzePersistence(record, candidates);
            AnalyzeCodeIntegrity(record, candidates);
        }

        return candidates
            .DistinctBy(candidate => new
            {
                candidate.Disposition,
                candidate.Title,
                candidate.Detail,
                candidate.Module,
                candidate.RecordKind,
            })
            .Select((candidate, index) => new EvidenceFinding(
                $"F-{(index + 1).ToString("D3", CultureInfo.InvariantCulture)}",
                candidate.Disposition,
                candidate.Title,
                candidate.Detail,
                candidate.Module,
                candidate.RecordKind))
            .ToArray();
    }

    private static void AnalyzeCoverage(EvidenceRecord record, ICollection<FindingCandidate> findings)
    {
        if (record.Kind != "coverage.source")
        {
            return;
        }

        var status = Get(record, "status");
        if (status is not ("unavailable" or "disabled" or "notSupported"))
        {
            return;
        }

        var source = Get(record, "sourceName") ?? record.Source;
        findings.Add(new FindingCandidate(
            FindingDisposition.CoverageGap,
            $"{source} unavailable",
            Get(record, "detail") ?? "The source did not provide evidence for this collection.",
            record.Module,
            record.Kind));
    }

    private static void AnalyzeFileInspection(EvidenceRecord record, ICollection<FindingCandidate> findings)
    {
        if (record.Kind is not ("process.module" or "file.metadata"))
        {
            return;
        }

        var path = Get(record, "modulePath") ?? Get(record, "executablePath");
        var error = Get(record, "fileInspectionError");
        if (!string.IsNullOrWhiteSpace(error))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.CoverageGap,
                "File inspection incomplete",
                $"{path ?? "A referenced file"}: {error}",
                record.Module,
                record.Kind));
        }

        if (string.Equals(Get(record, "identityStableDuringInspection"), "false", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "File changed during inspection",
                $"{path ?? "A referenced file"} changed while it was being hashed and inspected. Corroborate before interpreting the result.",
                record.Module,
                record.Kind));
        }

        if (record.Kind == "process.module" && IsUserWritablePath(path))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Game module loaded from a user-writable location",
                $"{path} was present in the live game module list. Location alone is not proof; review its signer, hash and case context.",
                record.Module,
                record.Kind));
        }
    }

    private static void AnalyzePersistence(EvidenceRecord record, ICollection<FindingCandidate> findings)
    {
        if (record.Kind != "persistence.scheduled_task")
        {
            return;
        }

        var command = Get(record, "command");
        if (!IsUserWritablePath(command))
        {
            return;
        }

        findings.Add(new FindingCandidate(
            FindingDisposition.NeedsReview,
            "Scheduled task launches from a user-writable location",
            $"{Get(record, "taskPath") ?? "A scheduled task"} references {command}. Review the task in context; this is not a verdict.",
            record.Module,
            record.Kind));
    }

    private static void AnalyzeCodeIntegrity(EvidenceRecord record, ICollection<FindingCandidate> findings)
    {
        if (record.Kind != "event.code_integrity")
        {
            return;
        }

        findings.Add(new FindingCandidate(
            FindingDisposition.NeedsReview,
            "Code Integrity event in the review window",
            $"Windows Code Integrity recorded event {Get(record, "eventId") ?? "unknown"}. Interpret it with the event level and surrounding evidence.",
            record.Module,
            record.Kind));
    }

    private static bool IsUserWritablePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.StartsWith("%USERPROFILE%", StringComparison.OrdinalIgnoreCase)
            || value.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase)
            || value.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase)
            || value.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("%TEMP%", StringComparison.OrdinalIgnoreCase);
    }

    private static string? Get(EvidenceRecord record, string key) =>
        record.Fields.TryGetValue(key, out var value) ? value : null;

    private sealed record FindingCandidate(
        FindingDisposition Disposition,
        string Title,
        string Detail,
        string Module,
        string? RecordKind);
}
