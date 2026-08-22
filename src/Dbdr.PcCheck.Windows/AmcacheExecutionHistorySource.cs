using System.Globalization;
using System.Security;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Microsoft.Win32;

namespace Dbdr.PcCheck.Windows;

public sealed class AmcacheExecutionHistorySource(PathRedactor redactor) : IExecutionHistorySource
{
    private const int MaximumRecords = 5000;
    private const string InventoryPath = @"AMCACHE\Root\InventoryApplicationFile";

    public string Name => "Amcache application inventory";

    public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken)
    {
        _ = context;

        try
        {
            using var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var inventory = localMachine.OpenSubKey(InventoryPath, writable: false);
            if (inventory is null)
            {
                return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], "The live Amcache inventory key was not present.");
            }

            var records = new List<EvidenceRecord>();
            var wasCapped = false;
            foreach (var subkeyName in inventory.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (records.Count >= MaximumRecords)
                {
                    wasCapped = true;
                    break;
                }

                using var entry = inventory.OpenSubKey(subkeyName, writable: false);
                if (entry is null)
                {
                    continue;
                }

                var fields = ReadFields(entry);
                if (!IsExecutableArtifact(fields))
                {
                    continue;
                }

                records.Add(CreateRecord(redactor, fields));
            }

            var ordered = records
                .OrderBy(record => record.Fields["fileName"], StringComparer.OrdinalIgnoreCase)
                .ThenBy(record => record.Fields["executablePath"], StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var detail = wasCapped
                ? $"Current application inventory only; no execution timestamp. Output capped at {MaximumRecords.ToString(CultureInfo.InvariantCulture)} executable records."
                : "Current application inventory only; no execution timestamp. Non-executable inventory entries are excluded.";

            return new EvidenceSourceResult(
                Name,
                ordered.Length == 0 ? EvidenceSourceStatus.Empty : EvidenceSourceStatus.Available,
                ordered,
                detail);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException or IOException)
        {
            return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], exception.GetType().Name);
        }
    }

    public static EvidenceRecord CreateRecord(
        PathRedactor redactor,
        IReadOnlyDictionary<string, string?> fields) => new(
        "execution-history",
        "execution.amcache",
        "Registry:Amcache/InventoryApplicationFile",
        DateTimeOffset.UtcNow,
        null,
        new Dictionary<string, string?>
        {
            ["fileName"] = Value(fields, "Name") ?? Path.GetFileName(Value(fields, "LowerCaseLongPath")),
            ["executablePath"] = redactor.Redact(Value(fields, "LowerCaseLongPath")),
            ["publisher"] = Value(fields, "Publisher"),
            ["productName"] = Value(fields, "ProductName"),
            ["productVersion"] = Value(fields, "ProductVersion"),
            ["fileVersion"] = Value(fields, "BinFileVersion") ?? Value(fields, "Version"),
            ["binaryType"] = Value(fields, "BinaryType"),
            ["fileSizeBytes"] = Value(fields, "Size"),
            ["linkDate"] = Value(fields, "LinkDate"),
            ["timestampBasis"] = "No source timestamp; LinkDate is file metadata and is not an execution time",
        });

    private static IReadOnlyDictionary<string, string?> ReadFields(RegistryKey entry)
    {
        var fields = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var valueName in new[]
                 {
                     "Name", "LowerCaseLongPath", "Publisher", "ProductName", "ProductVersion",
                     "BinFileVersion", "Version", "BinaryType", "Size", "LinkDate",
                 })
        {
            fields[valueName] = Convert.ToString(entry.GetValue(valueName), CultureInfo.InvariantCulture);
        }

        return fields;
    }

    private static bool IsExecutableArtifact(IReadOnlyDictionary<string, string?> fields)
    {
        var candidate = Value(fields, "Name") ?? Value(fields, "LowerCaseLongPath");
        var extension = Path.GetExtension(candidate ?? string.Empty);
        return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".sys", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".scr", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".com", StringComparison.OrdinalIgnoreCase);
    }

    private static string? Value(IReadOnlyDictionary<string, string?> fields, string key) =>
        fields.TryGetValue(key, out var value) ? value : null;
}
