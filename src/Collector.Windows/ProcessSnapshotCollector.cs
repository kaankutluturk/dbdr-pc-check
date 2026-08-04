using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Security.Cryptography;
using Dbdr.PcCheck.Collector.Core;
using Dbdr.PcCheck.Collector.Core.Models;

namespace Dbdr.PcCheck.Collector.Windows;

public sealed class ProcessSnapshotCollector(PathRedactor redactor) : IEvidenceCollector
{
    public string Name => "processes";

    public async Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var records = new List<EvidenceRecord>();
        var warnings = new List<string>();
        var fileCache = new Dictionary<string, FileEvidence>(StringComparer.OrdinalIgnoreCase);

        using var searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate FROM Win32_Process");
        using var collection = searcher.Get();
        var total = collection.Count;
        var current = 0;

        foreach (ManagementObject process in collection)
        {
            cancellationToken.ThrowIfCancellationRequested();
            current++;

            var processName = Convert.ToString(process["Name"], CultureInfo.InvariantCulture) ?? "<unknown>";
            progress?.Report(new CollectionProgress(Name, $"Inspecting {processName}", current, total));

            var executablePath = Convert.ToString(process["ExecutablePath"], CultureInfo.InvariantCulture);
            FileEvidence? fileEvidence = null;
            if (!string.IsNullOrWhiteSpace(executablePath))
            {
                if (!fileCache.TryGetValue(executablePath, out fileEvidence))
                {
                    fileEvidence = await InspectFileAsync(executablePath, cancellationToken).ConfigureAwait(false);
                    fileCache[executablePath] = fileEvidence;
                }
            }

            var fields = new Dictionary<string, string?>
            {
                ["processId"] = Convert.ToString(process["ProcessId"], CultureInfo.InvariantCulture),
                ["parentProcessId"] = Convert.ToString(process["ParentProcessId"], CultureInfo.InvariantCulture),
                ["name"] = processName,
                ["createdUtc"] = ParseWmiDate(process["CreationDate"]),
                ["executablePath"] = redactor.Redact(executablePath),
                ["fileSizeBytes"] = fileEvidence?.SizeBytes,
                ["fileCreatedUtc"] = fileEvidence?.CreatedUtc,
                ["fileModifiedUtc"] = fileEvidence?.ModifiedUtc,
                ["sha256"] = fileEvidence?.Sha256,
                ["authenticodeStatus"] = fileEvidence?.AuthenticodeStatus,
                ["companyName"] = fileEvidence?.CompanyName,
                ["productName"] = fileEvidence?.ProductName,
                ["originalFileName"] = fileEvidence?.OriginalFileName,
                ["fileInspectionError"] = fileEvidence?.Error,
            };

            records.Add(new EvidenceRecord(
                Name,
                "process.snapshot",
                "Win32_Process and file metadata",
                DateTimeOffset.UtcNow,
                fields));
        }

        if (records.Count == 0)
        {
            warnings.Add("Win32_Process returned no records.");
        }

        stopwatch.Stop();
        return new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []);
    }

    private static string? ParseWmiDate(object? value)
    {
        var text = Convert.ToString(value, CultureInfo.InvariantCulture);
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        try
        {
            return ManagementDateTimeConverter.ToDateTime(text).ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static async Task<FileEvidence> InspectFileAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                return new FileEvidence(null, null, null, null, "unavailable", null, null, null, "File no longer exists.");
            }

            string hash;
            await using (var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                81920,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
            }

            var version = FileVersionInfo.GetVersionInfo(path);

            return new FileEvidence(
                file.Length.ToString(CultureInfo.InvariantCulture),
                file.CreationTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                file.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                hash,
                AuthenticodeVerifier.GetStatus(path),
                version.CompanyName,
                version.ProductName,
                version.OriginalFilename,
                null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return new FileEvidence(null, null, null, null, "unavailable", null, null, null, exception.GetType().Name);
        }
    }

    private sealed record FileEvidence(
        string? SizeBytes,
        string? CreatedUtc,
        string? ModifiedUtc,
        string? Sha256,
        string AuthenticodeStatus,
        string? CompanyName,
        string? ProductName,
        string? OriginalFileName,
        string? Error);
}
