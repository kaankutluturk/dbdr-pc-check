using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class GameModuleSnapshotCollector(
    ILiveProcessSnapshotProvider snapshotProvider,
    IGameModuleEnumerator moduleEnumerator,
    IExecutableFileInspector fileInspector,
    PathRedactor redactor) : IEvidenceCollector
{
    public string Name => "game-modules";

    public async Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var snapshot = await snapshotProvider.GetOrCaptureAsync(cancellationToken).ConfigureAwait(false);
        var gameProcesses = snapshot.Processes.Where(IsDbdrProcess).ToArray();
        var records = new List<EvidenceRecord>();
        var warnings = new List<string>();
        var fileCache = new Dictionary<string, ExecutableFileEvidence>(StringComparer.OrdinalIgnoreCase);
        var enumerationSucceeded = 0;
        var enumerationFailed = 0;

        foreach (var processInfo in gameProcesses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new CollectionProgress(
                Name,
                $"Capturing modules for {processInfo.Name} (PID {processInfo.ProcessId})"));

            try
            {
                var modules = moduleEnumerator.Enumerate(processInfo.ProcessId);

                foreach (var module in modules)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!fileCache.TryGetValue(module.Path, out var evidence))
                    {
                        evidence = await fileInspector.InspectAsync(module.Path, cancellationToken).ConfigureAwait(false);
                        fileCache[module.Path] = evidence;
                    }

                    var fields = new Dictionary<string, string?>
                    {
                        ["processId"] = processInfo.ProcessId.ToString(CultureInfo.InvariantCulture),
                        ["processName"] = processInfo.Name,
                        ["moduleName"] = module.Name,
                        ["modulePath"] = redactor.Redact(module.Path),
                    };
                    evidence.AddTo(fields);

                    records.Add(new EvidenceRecord(
                        Name,
                        "process.module",
                        "System.Diagnostics.Process.Modules and file metadata",
                        DateTimeOffset.UtcNow,
                        null,
                        fields));
                }

                enumerationSucceeded++;
            }
            catch (Exception exception) when (exception is Win32Exception
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException
                or OverflowException)
            {
                enumerationFailed++;
                warnings.Add(
                    $"{processInfo.Name} (PID {processInfo.ProcessId}): module enumeration failed with {exception.GetType().Name}.");
            }
        }

        if (gameProcesses.Length == 0)
        {
            warnings.Add("No running process with a DeadByDaylight name was present in the captured process snapshot.");
        }

        records.Insert(0, new EvidenceRecord(
            Name,
            "game.snapshot",
            "captured Win32_Process snapshot and module enumeration",
            DateTimeOffset.UtcNow,
            null,
            new Dictionary<string, string?>
            {
                ["matchingProcessCount"] = gameProcesses.Length.ToString(CultureInfo.InvariantCulture),
                ["matchingProcesses"] = string.Join(", ", gameProcesses.Select(process => $"{process.Name} ({process.ProcessId})")),
                ["moduleEnumerationSucceededCount"] = enumerationSucceeded.ToString(CultureInfo.InvariantCulture),
                ["moduleEnumerationFailedCount"] = enumerationFailed.ToString(CultureInfo.InvariantCulture),
                ["moduleRecordCount"] = records.Count.ToString(CultureInfo.InvariantCulture),
            }));

        stopwatch.Stop();
        return new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []);
    }

    internal static bool IsDbdrProcess(LiveProcessInfo process) =>
        process.Name.Contains("DeadByDaylight", StringComparison.OrdinalIgnoreCase);
}
