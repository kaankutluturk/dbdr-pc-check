using System.Diagnostics;
using System.Globalization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class ProcessFileMetadataCollector(
    ILiveProcessSnapshotProvider snapshotProvider,
    IExecutableFileInspector fileInspector,
    PathRedactor redactor) : IEvidenceCollector
{
    public const int MaximumExecutableFiles = 1024;

    public string Name => "process-files";

    public async Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var snapshot = await snapshotProvider.GetOrCaptureAsync(cancellationToken).ConfigureAwait(false);
        var allGroups = snapshot.Processes
            .Where(process => !string.IsNullOrWhiteSpace(process.ExecutablePath))
            .GroupBy(process => process.ExecutablePath!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Any(process =>
                process.Name.Contains("DeadByDaylight", StringComparison.OrdinalIgnoreCase)))
            .ThenByDescending(group => IsUserWritablePath(group.Key))
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var groups = allGroups.Take(MaximumExecutableFiles).ToArray();
        var records = new List<EvidenceRecord>(groups.Length);
        var inspectionFailures = 0;

        for (var index = 0; index < groups.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var group = groups[index];
            progress?.Report(new CollectionProgress(
                Name,
                $"Inspecting executable {index + 1} of {groups.Length}",
                index + 1,
                groups.Length));

            var evidence = await fileInspector.InspectAsync(group.Key, cancellationToken).ConfigureAwait(false);
            if (evidence.Error is not null)
            {
                inspectionFailures++;
            }

            var processes = group.ToArray();
            var fields = new Dictionary<string, string?>
            {
                ["executablePath"] = redactor.Redact(group.Key),
                ["referencedProcessCount"] = processes.Length.ToString(CultureInfo.InvariantCulture),
                ["processIds"] = string.Join(",", processes.Select(process => process.ProcessId.ToString(CultureInfo.InvariantCulture))),
                ["processNames"] = string.Join(", ", processes.Select(process => process.Name).Distinct(StringComparer.OrdinalIgnoreCase)),
            };
            evidence.AddTo(fields);

            records.Add(new EvidenceRecord(
                Name,
                "file.metadata",
                "running-process executable path and file metadata",
                DateTimeOffset.UtcNow,
                null,
                fields));
        }

        var warnings = new List<string>();
        if (inspectionFailures > 0)
        {
            warnings.Add($"File inspection was incomplete for {inspectionFailures} executable path(s). Review per-record errors.");
        }

        if (allGroups.Length > MaximumExecutableFiles)
        {
            warnings.Add($"Process executable enrichment was capped at {MaximumExecutableFiles.ToString(CultureInfo.InvariantCulture)} of {allGroups.Length.ToString(CultureInfo.InvariantCulture)} unique paths.");
        }

        var metadataRecordCount = records.Count;
        records.Add(new EvidenceRecord(
            Name,
            "coverage.source",
            "running-process executable paths",
            DateTimeOffset.UtcNow,
            null,
            new Dictionary<string, string?>
            {
                ["sourceName"] = "Process executable enrichment",
                ["status"] = metadataRecordCount == 0 ? "empty" : "available",
                ["recordCount"] = metadataRecordCount.ToString(CultureInfo.InvariantCulture),
                ["detail"] = $"Deduplicated by executable path; inspected={groups.Length.ToString(CultureInfo.InvariantCulture)}; "
                    + $"available={allGroups.Length.ToString(CultureInfo.InvariantCulture)}; "
                    + $"failures={inspectionFailures.ToString(CultureInfo.InvariantCulture)}; "
                    + $"capped={(allGroups.Length > MaximumExecutableFiles).ToString().ToLowerInvariant()}",
            }));

        stopwatch.Stop();
        return new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []);
    }

    private static bool IsUserWritablePath(string path) =>
        path.Contains("\\Users\\", StringComparison.OrdinalIgnoreCase)
        || path.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase)
        || path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase)
        || path.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase);
}
