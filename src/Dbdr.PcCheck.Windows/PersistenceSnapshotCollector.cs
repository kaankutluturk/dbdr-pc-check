using System.Diagnostics;
using System.Globalization;
using System.Management;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Microsoft.Win32;

namespace Dbdr.PcCheck.Windows;

public sealed class PersistenceSnapshotCollector(
    PathRedactor redactor,
    IExecutableFileInspector? fileInspector = null) : IEvidenceCollector
{
    private static readonly string[] RunKeyPaths =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    public string Name => "persistence";

    public async Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var records = new List<EvidenceRecord>();
        var warnings = new List<string>();
        var binaryReferences = new List<ReferencedBinary>();

        progress?.Report(new CollectionProgress(Name, "Reading registry Run keys"));
        CollectRunKeys(records, warnings, cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Reading Windows services"));
        CollectManagementClass(
            "Win32_Service",
            "persistence.service",
            records,
            binaryReferences,
            warnings,
            cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Reading Windows system drivers"));
        CollectManagementClass(
            "Win32_SystemDriver",
            "persistence.driver",
            records,
            binaryReferences,
            warnings,
            cancellationToken);

        if (fileInspector is not null)
        {
            await CollectBinaryEvidenceAsync(
                binaryReferences,
                records,
                warnings,
                progress,
                cancellationToken).ConfigureAwait(false);
        }

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
        return new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []);
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
        ICollection<ReferencedBinary> binaryReferences,
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
                var name = Convert.ToString(item["Name"], CultureInfo.InvariantCulture);
                var startMode = Convert.ToString(item["StartMode"], CultureInfo.InvariantCulture);
                var rawImagePath = Convert.ToString(item["PathName"], CultureInfo.InvariantCulture);
                records.Add(new EvidenceRecord(
                    Name,
                    kind,
                    className,
                    DateTimeOffset.UtcNow,
                    null,
                    new Dictionary<string, string?>
                    {
                        ["name"] = name,
                        ["displayName"] = Convert.ToString(item["DisplayName"], CultureInfo.InvariantCulture),
                        ["state"] = Convert.ToString(item["State"], CultureInfo.InvariantCulture),
                        ["startMode"] = startMode,
                        ["imagePath"] = redactor.Redact(rawImagePath),
                    }));

                var resolvedPath = ReferencedBinaryPathResolver.TryResolve(rawImagePath);
                if (resolvedPath is not null
                    && (kind == "persistence.driver"
                        || string.Equals(startMode, "Auto", StringComparison.OrdinalIgnoreCase)))
                {
                    binaryReferences.Add(new ReferencedBinary(kind, name, startMode, resolvedPath));
                }
            }
        }
        catch (ManagementException exception)
        {
            warnings.Add($"{className}: {exception.GetType().Name}");
        }
    }

    private async Task CollectBinaryEvidenceAsync(
        IEnumerable<ReferencedBinary> references,
        ICollection<EvidenceRecord> records,
        ICollection<string> warnings,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        const int maximumBinaries = 512;
        var groups = references
            .GroupBy(reference => reference.ResolvedPath, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Any(reference => reference.ReferenceKind == "persistence.driver"))
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Take(maximumBinaries)
            .ToArray();
        var failures = 0;

        for (var index = 0; index < groups.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var group = groups[index];
            progress?.Report(new CollectionProgress(
                Name,
                $"Inspecting persistence binary {index + 1} of {groups.Length}",
                index + 1,
                groups.Length));
            var evidence = await fileInspector!
                .InspectAsync(group.Key, cancellationToken)
                .ConfigureAwait(false);
            if (evidence.Error is not null)
            {
                failures++;
            }

            var referenceList = group.ToArray();
            var fields = new Dictionary<string, string?>
            {
                ["executablePath"] = redactor.Redact(group.Key),
                ["referenceKinds"] = string.Join(", ", referenceList.Select(item => item.ReferenceKind).Distinct(StringComparer.Ordinal)),
                ["referenceNames"] = string.Join(", ", referenceList.Select(item => item.Name).Where(name => !string.IsNullOrWhiteSpace(name)).Distinct(StringComparer.OrdinalIgnoreCase)),
                ["startModes"] = string.Join(", ", referenceList.Select(item => item.StartMode).Where(mode => !string.IsNullOrWhiteSpace(mode)).Distinct(StringComparer.OrdinalIgnoreCase)),
            };
            evidence.AddTo(fields);
            records.Add(new EvidenceRecord(
                Name,
                "persistence.binary",
                "resolved auto-start service and driver image paths",
                DateTimeOffset.UtcNow,
                null,
                fields));
        }

        var totalUnique = references
            .Select(reference => reference.ResolvedPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        if (totalUnique > maximumBinaries)
        {
            warnings.Add($"Persistence binary inspection was capped at {maximumBinaries.ToString(CultureInfo.InvariantCulture)} of {totalUnique.ToString(CultureInfo.InvariantCulture)} unique paths.");
        }

        if (failures > 0)
        {
            warnings.Add($"Persistence binary inspection was incomplete for {failures.ToString(CultureInfo.InvariantCulture)} path(s). Review per-record errors.");
        }
    }

    private sealed record ReferencedBinary(
        string ReferenceKind,
        string? Name,
        string? StartMode,
        string ResolvedPath);
}

internal static class ReferencedBinaryPathResolver
{
    private static readonly string[] ExecutableExtensions = [".exe", ".sys", ".dll"];

    public static string? TryResolve(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(commandLine.Trim());
        if (expanded.StartsWith("\\??\\", StringComparison.Ordinal))
        {
            expanded = expanded[4..];
        }

        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (expanded.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
        {
            expanded = Path.Combine(windowsDirectory, expanded[12..]);
        }
        else if (expanded.StartsWith("System32\\", StringComparison.OrdinalIgnoreCase))
        {
            expanded = Path.Combine(windowsDirectory, expanded);
        }

        string candidate;
        if (expanded.StartsWith('"'))
        {
            var closingQuote = expanded.IndexOf('"', 1);
            if (closingQuote <= 1)
            {
                return null;
            }

            candidate = expanded[1..closingQuote];
        }
        else
        {
            var end = -1;
            foreach (var extension in ExecutableExtensions)
            {
                var extensionIndex = expanded.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
                if (extensionIndex >= 0)
                {
                    var proposedEnd = extensionIndex + extension.Length;
                    end = end < 0 ? proposedEnd : Math.Min(end, proposedEnd);
                }
            }

            candidate = end > 0 ? expanded[..end] : expanded;
        }

        try
        {
            var fullPath = Path.GetFullPath(candidate.Trim());
            return File.Exists(fullPath) ? fullPath : null;
        }
        catch (Exception exception) when (exception is ArgumentException
            or NotSupportedException
            or PathTooLongException
            or System.Security.SecurityException)
        {
            return null;
        }
    }
}
