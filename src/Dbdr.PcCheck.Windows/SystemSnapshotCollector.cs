using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

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
        var warnings = new List<string>();
        progress?.Report(new CollectionProgress(Name, "Reading non-identifying system metadata"));

        string? isElevated = null;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            isElevated = new WindowsPrincipal(identity)
                .IsInRole(WindowsBuiltInRole.Administrator)
                .ToString();
        }
        catch (Exception exception) when (exception is SecurityException or UnauthorizedAccessException)
        {
            warnings.Add($"Elevation state unavailable: {exception.GetType().Name}");
        }

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
            ["collectorIsElevated"] = isElevated,
        };

        var collectedAtUtc = DateTimeOffset.UtcNow;
        var record = new EvidenceRecord(
            Name,
            "system.snapshot",
            "System.Runtime.InteropServices.RuntimeInformation",
            collectedAtUtc,
            null,
            fields);

        stopwatch.Stop();
        return Task.FromResult(new ModuleResult(Name, true, stopwatch.Elapsed, [record], warnings, []));
    }
}
