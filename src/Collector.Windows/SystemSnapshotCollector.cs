using System.Diagnostics;
using System.Runtime.InteropServices;
using Dbdr.PcCheck.Collector.Core;
using Dbdr.PcCheck.Collector.Core.Models;

namespace Dbdr.PcCheck.Collector.Windows;

public sealed class SystemSnapshotCollector : IEvidenceCollector
{
    public string Name => "system";

    public Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var stopwatch = Stopwatch.StartNew();
        progress?.Report(new CollectionProgress(Name, "Reading non-identifying system metadata"));

        var fields = new Dictionary<string, string?>
        {
            ["operatingSystem"] = RuntimeInformation.OSDescription,
            ["osArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
            ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
            ["framework"] = RuntimeInformation.FrameworkDescription,
            ["processorCount"] = Environment.ProcessorCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["timeZoneId"] = TimeZoneInfo.Local.Id,
            ["systemUptimeSeconds"] = (Environment.TickCount64 / 1000).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["is64BitOperatingSystem"] = Environment.Is64BitOperatingSystem.ToString(),
        };

        var record = new EvidenceRecord(
            Name,
            "system.snapshot",
            "System.Runtime.InteropServices.RuntimeInformation",
            DateTimeOffset.UtcNow,
            fields);

        stopwatch.Stop();
        return Task.FromResult(new ModuleResult(Name, true, stopwatch.Elapsed, [record], [], []));
    }
}
