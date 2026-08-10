using System.Diagnostics;
using System.Globalization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class ProcessSnapshotCollector(
    ILiveProcessSnapshotProvider snapshotProvider,
    PathRedactor redactor) : IEvidenceCollector
{
    public string Name => "processes";

    public async Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        progress?.Report(new CollectionProgress(Name, "Capturing live process state"));
        var snapshot = await snapshotProvider.GetOrCaptureAsync(cancellationToken).ConfigureAwait(false);
        var records = new List<EvidenceRecord>(snapshot.Processes.Count);

        foreach (var process in snapshot.Processes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            records.Add(new EvidenceRecord(
                Name,
                "process.snapshot",
                "Win32_Process snapshot",
                snapshot.CapturedAtUtc,
                process.CreatedUtc,
                new Dictionary<string, string?>
                {
                    ["processId"] = process.ProcessId.ToString(CultureInfo.InvariantCulture),
                    ["parentProcessId"] = process.ParentProcessId.ToString(CultureInfo.InvariantCulture),
                    ["sessionId"] = process.SessionId?.ToString(CultureInfo.InvariantCulture),
                    ["name"] = process.Name,
                    ["executablePath"] = redactor.Redact(process.ExecutablePath),
                }));
        }

        var warnings = records.Count == 0
            ? new[] { "Win32_Process returned no records." }
            : Array.Empty<string>();

        stopwatch.Stop();
        return new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []);
    }
}
