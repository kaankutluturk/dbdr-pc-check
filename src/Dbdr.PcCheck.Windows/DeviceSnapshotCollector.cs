using System.Diagnostics;
using System.Globalization;
using System.Management;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class DeviceSnapshotCollector(IDeviceSnapshotProvider provider) : IEvidenceCollector
{
    public string Name => "devices";

    public Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var records = new List<EvidenceRecord>();
        var warnings = new List<string>();
        var status = "available";
        string? detail = "Unique device-instance identifiers and serial suffixes are excluded.";

        progress?.Report(new CollectionProgress(Name, "Reading privacy-minimized Plug and Play inventory"));
        try
        {
            var devices = provider.Capture(cancellationToken);
            foreach (var device in devices)
            {
                cancellationToken.ThrowIfCancellationRequested();
                records.Add(new EvidenceRecord(
                    Name,
                    "device.snapshot",
                    "Win32_PnPEntity",
                    DateTimeOffset.UtcNow,
                    null,
                    new Dictionary<string, string?>
                    {
                        ["name"] = device.Name,
                        ["pnpClass"] = device.PnpClass,
                        ["manufacturer"] = device.Manufacturer,
                        ["status"] = device.Status,
                        ["service"] = device.Service,
                        ["configManagerErrorCode"] = device.ConfigManagerErrorCode,
                        ["modelIdentifier"] = device.ModelIdentifier,
                    }));
            }

            if (records.Count == 0)
            {
                status = "empty";
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is ManagementException
            or UnauthorizedAccessException
            or System.Security.SecurityException)
        {
            status = "unavailable";
            detail = exception.GetType().Name;
            warnings.Add($"Plug and Play inventory: {exception.GetType().Name}");
        }

        records.Add(new EvidenceRecord(
            Name,
            "coverage.source",
            "Win32_PnPEntity",
            DateTimeOffset.UtcNow,
            null,
            new Dictionary<string, string?>
            {
                ["sourceName"] = "Plug and Play device inventory",
                ["status"] = status,
                ["recordCount"] = records.Count.ToString(CultureInfo.InvariantCulture),
                ["detail"] = detail,
            }));

        stopwatch.Stop();
        return Task.FromResult(new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []));
    }
}
