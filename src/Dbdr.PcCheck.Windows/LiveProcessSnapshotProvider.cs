using System.Globalization;
using System.Management;

namespace Dbdr.PcCheck.Windows;

public sealed record LiveProcessInfo(
    uint ProcessId,
    uint ParentProcessId,
    string Name,
    string? ExecutablePath,
    DateTimeOffset? CreatedUtc,
    uint? SessionId);

public sealed record LiveProcessSnapshot(
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<LiveProcessInfo> Processes);

public interface ILiveProcessSnapshotProvider
{
    Task<LiveProcessSnapshot> GetOrCaptureAsync(CancellationToken cancellationToken);
}

public sealed class LiveProcessSnapshotProvider : ILiveProcessSnapshotProvider
{
    private readonly SemaphoreSlim _captureGate = new(1, 1);
    private LiveProcessSnapshot? _snapshot;

    public async Task<LiveProcessSnapshot> GetOrCaptureAsync(CancellationToken cancellationToken)
    {
        if (_snapshot is not null)
        {
            return _snapshot;
        }

        await _captureGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_snapshot is not null)
            {
                return _snapshot;
            }

            cancellationToken.ThrowIfCancellationRequested();
            _snapshot = Capture(cancellationToken);
            return _snapshot;
        }
        finally
        {
            _captureGate.Release();
        }
    }

    private static LiveProcessSnapshot Capture(CancellationToken cancellationToken)
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate, SessionId FROM Win32_Process");
        using var collection = searcher.Get();
        var capturedAtUtc = DateTimeOffset.UtcNow;
        var processes = new List<LiveProcessInfo>(collection.Count);

        foreach (ManagementObject process in collection)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var processId = ConvertToUInt32(process["ProcessId"]);
                if (!processId.HasValue)
                {
                    continue;
                }

                processes.Add(new LiveProcessInfo(
                    processId.Value,
                    ConvertToUInt32(process["ParentProcessId"]) ?? 0,
                    Convert.ToString(process["Name"], CultureInfo.InvariantCulture) ?? "<unknown>",
                    Convert.ToString(process["ExecutablePath"], CultureInfo.InvariantCulture),
                    ParseWmiDate(process["CreationDate"]),
                    ConvertToUInt32(process["SessionId"])));
            }
            finally
            {
                process.Dispose();
            }
        }

        return new LiveProcessSnapshot(
            capturedAtUtc,
            processes.OrderBy(process => process.ProcessId).ToArray());
    }

    private static uint? ConvertToUInt32(object? value)
    {
        if (value is null)
        {
            return null;
        }

        try
        {
            return Convert.ToUInt32(value, CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
    }

    private static DateTimeOffset? ParseWmiDate(object? value)
    {
        var text = Convert.ToString(value, CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        try
        {
            return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(text).ToUniversalTime());
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
