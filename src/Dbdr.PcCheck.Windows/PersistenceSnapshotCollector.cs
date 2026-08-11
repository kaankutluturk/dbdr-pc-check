using System.Diagnostics;
using System.Globalization;
using System.Management;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Microsoft.Win32;

namespace Dbdr.PcCheck.Windows;

public sealed class PersistenceSnapshotCollector(PathRedactor redactor) : IEvidenceCollector
{
    private static readonly string[] RunKeyPaths =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    public string Name => "persistence";

    public Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var records = new List<EvidenceRecord>();
        var warnings = new List<string>();

        progress?.Report(new CollectionProgress(Name, "Reading registry Run keys"));
        CollectRunKeys(records, warnings, cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Reading Windows services"));
        CollectManagementClass("Win32_Service", "persistence.service", records, warnings, cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Reading Windows system drivers"));
        CollectManagementClass("Win32_SystemDriver", "persistence.driver", records, warnings, cancellationToken);

        var persistenceRecordCount = records.Count;
        records.Add(new EvidenceRecord(
            Name,
            "coverage.source",
            "Registry Run keys, Win32_Service and Win32_SystemDriver",
            DateTimeOffset.UtcNow,
            null,
            new Dictionary<string, string?>
            {
                ["sourceName"] = "Persistence inventory",
                ["status"] = persistenceRecordCount == 0 ? "empty" : "available",
                ["recordCount"] = persistenceRecordCount.ToString(CultureInfo.InvariantCulture),
                ["detail"] = warnings.Count > 0 ? "One or more persistence sub-sources reported warnings." : null,
            }));

        stopwatch.Stop();
        return Task.FromResult(new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []));
    }

    private void CollectRunKeys(
        ICollection<EvidenceRecord> records,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                foreach (var keyPath in RunKeyPaths)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                        using var key = baseKey.OpenSubKey(keyPath, writable: false);
                        if (key is null)
                        {
                            continue;
                        }

                        foreach (var valueName in key.GetValueNames())
                        {
                            records.Add(new EvidenceRecord(
                                Name,
                                "persistence.run_key",
                                $"Registry:{hive}:{view}:{keyPath}",
                                DateTimeOffset.UtcNow,
                                null,
                                new Dictionary<string, string?>
                                {
                                    ["entryName"] = valueName,
                                    ["value"] = redactor.Redact(Convert.ToString(key.GetValue(valueName), CultureInfo.InvariantCulture)),
                                    ["valueKind"] = key.GetValueKind(valueName).ToString(),
                                }));
                        }
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                    {
                        warnings.Add($"{hive}/{view}/{keyPath}: {exception.GetType().Name}");
                    }
                }
            }
        }
    }

    private void CollectManagementClass(
        string className,
        string kind,
        ICollection<EvidenceRecord> records,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name, DisplayName, State, StartMode, PathName FROM {className}");
            using var collection = searcher.Get();

            foreach (ManagementObject item in collection)
            {
                cancellationToken.ThrowIfCancellationRequested();
                records.Add(new EvidenceRecord(
                    Name,
                    kind,
                    className,
                    DateTimeOffset.UtcNow,
                    null,
                    new Dictionary<string, string?>
                    {
                        ["name"] = Convert.ToString(item["Name"], CultureInfo.InvariantCulture),
                        ["displayName"] = Convert.ToString(item["DisplayName"], CultureInfo.InvariantCulture),
                        ["state"] = Convert.ToString(item["State"], CultureInfo.InvariantCulture),
                        ["startMode"] = Convert.ToString(item["StartMode"], CultureInfo.InvariantCulture),
                        ["imagePath"] = redactor.Redact(Convert.ToString(item["PathName"], CultureInfo.InvariantCulture)),
                    }));
            }
        }
        catch (ManagementException exception)
        {
            warnings.Add($"{className}: {exception.GetType().Name}");
        }
    }
}
