using System.Globalization;
using System.Management;

namespace Dbdr.PcCheck.Windows;

public sealed record DeviceSnapshotInfo(
    string? Name,
    string? PnpClass,
    string? Manufacturer,
    string? Status,
    string? Service,
    string? ConfigManagerErrorCode,
    string? ModelIdentifier);

public interface IDeviceSnapshotProvider
{
    IReadOnlyList<DeviceSnapshotInfo> Capture(CancellationToken cancellationToken);
}

public sealed class DeviceSnapshotProvider : IDeviceSnapshotProvider
{
    public IReadOnlyList<DeviceSnapshotInfo> Capture(CancellationToken cancellationToken)
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT Name, PNPClass, Manufacturer, Status, Service, ConfigManagerErrorCode, PNPDeviceID FROM Win32_PnPEntity");
        using var collection = searcher.Get();
        var devices = new List<DeviceSnapshotInfo>(collection.Count);

        foreach (ManagementObject item in collection)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var deviceId = Convert.ToString(item["PNPDeviceID"], CultureInfo.InvariantCulture);
                devices.Add(new DeviceSnapshotInfo(
                    Convert.ToString(item["Name"], CultureInfo.InvariantCulture),
                    Convert.ToString(item["PNPClass"], CultureInfo.InvariantCulture),
                    Convert.ToString(item["Manufacturer"], CultureInfo.InvariantCulture),
                    Convert.ToString(item["Status"], CultureInfo.InvariantCulture),
                    Convert.ToString(item["Service"], CultureInfo.InvariantCulture),
                    Convert.ToString(item["ConfigManagerErrorCode"], CultureInfo.InvariantCulture),
                    DeviceIdentifierSanitizer.ExtractModelIdentifier(deviceId)));
            }
            finally
            {
                item.Dispose();
            }
        }

        return devices
            .OrderBy(device => device.PnpClass, StringComparer.OrdinalIgnoreCase)
            .ThenBy(device => device.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
