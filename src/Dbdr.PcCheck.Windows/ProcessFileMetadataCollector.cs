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
    public string Name => "process-files";

    public async Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var snapshot = await snapshotProvider.GetOrCaptureAsync(cancellationToken).ConfigureAwait(false);
        var groups = snapshot.Processes
            .Where(process => !string.IsNullOrWhiteSpace(process.ExecutablePath))
            .GroupBy(process => process.ExecutablePath!, StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();
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

        var warnings = inspectionFailures > 0
            ? new[] { $"File inspection was incomplete for {inspectionFailures} executable path(s). Review per-record errors." }
            : Array.Empty<string>();

        stopwatch.Stop();
        return new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []);
    }
}
