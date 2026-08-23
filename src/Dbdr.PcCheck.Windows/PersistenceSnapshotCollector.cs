using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
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
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ];

    private static readonly RegistryValueLocation[] RegistryValueLocations =
    [
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "winlogon", ["Shell", "Userinit", "Taskman"]),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Windows", "appinit", ["AppInit_DLLs", "LoadAppInit_DLLs", "RequireSignedAppInit_DLLs"]),
        new(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager", "boot-execute", ["BootExecute"]),
        new(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "lsa-package", ["Authentication Packages", "Security Packages", "Notification Packages"]),
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
        CollectRunKeys(records, binaryReferences, warnings, cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Reading additional autorun registry locations"));
        CollectRegistryValueLocations(records, binaryReferences, warnings, cancellationToken);
        CollectIfeoDebuggers(records, binaryReferences, warnings, cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Reading Startup folders"));
        CollectStartupFolders(records, binaryReferences, warnings, cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Reading WMI event-subscription identities"));
        CollectWmiSubscriptions(records, warnings, cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Reading Windows services"));
        CollectManagementClass(
            "Win32_Service",
            "persistence.service",
            records,
            binaryReferences,
            warnings,
            cancellationToken);

        progress?.Report(new CollectionProgress(Name, "Enumerating loaded driver image paths"));
        CollectLoadedDriverImages(records, binaryReferences, warnings, cancellationToken);

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
            "Selected autorun registry locations, Startup folders, WMI subscription identities, Win32_Service, Win32_SystemDriver and PSAPI loaded drivers",
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

    private void CollectRegistryValueLocations(
        ICollection<EvidenceRecord> records,
        ICollection<ReferencedBinary> binaryReferences,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        foreach (var location in RegistryValueLocations)
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(location.Hive, view);
                    using var key = baseKey.OpenSubKey(location.KeyPath, writable: false);
                    if (key is null)
                    {
                        continue;
                    }

                    foreach (var valueName in location.ValueNames)
                    {
                        var value = key.GetValue(valueName);
                        if (value is null)
                        {
                            continue;
                        }

                        records.Add(new EvidenceRecord(
                            Name,
                            "persistence.registry_location",
                            $"Registry:{location.Hive}:{view}:{location.KeyPath}",
                            DateTimeOffset.UtcNow,
                            null,
                            new Dictionary<string, string?>
                            {
                                ["locationType"] = location.LocationType,
                                ["entryName"] = valueName,
                                ["value"] = redactor.Redact(location.LocationType is "appinit" or "lsa-package"
                                    ? FormatRegistryValue(value)
                                    : FormatCommandReferences(value)),
                                ["valueKind"] = key.GetValueKind(valueName).ToString(),
                                ["argumentBoundary"] = location.LocationType is "appinit" or "lsa-package"
                                    ? "not a command-line field"
                                    : "command arguments excluded",
                            }));
                        AddResolvedReference(
                            value,
                            $"persistence.{location.LocationType}",
                            valueName,
                            null,
                            binaryReferences);
                    }
                }
                catch (Exception exception) when (exception is IOException
                    or UnauthorizedAccessException
                    or System.Security.SecurityException)
                {
                    warnings.Add($"{location.Hive}/{view}/{location.KeyPath}: {exception.GetType().Name}");
                }
            }
        }
    }

    private void CollectIfeoDebuggers(
        ICollection<EvidenceRecord> records,
        ICollection<ReferencedBinary> binaryReferences,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        const string keyPath = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        const int maximumSubkeys = 2048;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var root = baseKey.OpenSubKey(keyPath, writable: false);
                if (root is null)
                {
                    continue;
                }

                var subkeyNames = root.GetSubKeyNames();
                foreach (var imageName in subkeyNames.Take(maximumSubkeys))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using var imageKey = root.OpenSubKey(imageName, writable: false);
                    var debugger = imageKey?.GetValue("Debugger");
                    if (debugger is null)
                    {
                        continue;
                    }

                    records.Add(new EvidenceRecord(
                        Name,
                        "persistence.ifeo_debugger",
                        $"Registry:LocalMachine:{view}:{keyPath}",
                        DateTimeOffset.UtcNow,
                        null,
                        new Dictionary<string, string?>
                        {
                            ["imageName"] = imageName,
                            ["debugger"] = redactor.Redact(FormatCommandReferences(debugger)),
                            ["argumentBoundary"] = "debugger arguments excluded",
                        }));
                    AddResolvedReference(
                        debugger,
                        "persistence.ifeo_debugger",
                        imageName,
                        null,
                        binaryReferences);
                }

                if (subkeyNames.Length > maximumSubkeys)
                {
                    warnings.Add($"{view} IFEO inspection was capped at {maximumSubkeys.ToString(CultureInfo.InvariantCulture)} of {subkeyNames.Length.ToString(CultureInfo.InvariantCulture)} image keys.");
                }
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException)
            {
                warnings.Add($"LocalMachine/{view}/{keyPath}: {exception.GetType().Name}");
            }
        }
    }

    private void CollectStartupFolders(
        ICollection<EvidenceRecord> records,
        ICollection<ReferencedBinary> binaryReferences,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        const int maximumFilesPerFolder = 512;
        foreach (var folderType in new[] { Environment.SpecialFolder.Startup, Environment.SpecialFolder.CommonStartup })
        {
            var folder = Environment.GetFolderPath(folderType);
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            {
                continue;
            }

            try
            {
                var files = Directory.EnumerateFiles(folder, "*", SearchOption.TopDirectoryOnly)
                    .Take(maximumFilesPerFolder + 1)
                    .ToArray();
                foreach (var path in files.Take(maximumFilesPerFolder))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var info = new FileInfo(path);
                    records.Add(new EvidenceRecord(
                        Name,
                        "persistence.startup_file",
                        $"Windows {folderType} folder metadata",
                        DateTimeOffset.UtcNow,
                        new DateTimeOffset(info.LastWriteTimeUtc),
                        new Dictionary<string, string?>
                        {
                            ["folderType"] = folderType.ToString(),
                            ["fileName"] = info.Name,
                            ["extension"] = info.Extension,
                            ["path"] = redactor.Redact(info.FullName),
                            ["modifiedUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                        }));
                    if (ReferencedBinaryPathResolver.IsExecutablePath(info.FullName))
                    {
                        binaryReferences.Add(new ReferencedBinary(
                            "persistence.startup_file",
                            info.Name,
                            null,
                            info.FullName));
                    }
                }

                if (files.Length > maximumFilesPerFolder)
                {
                    warnings.Add($"{folderType} inspection was capped at {maximumFilesPerFolder.ToString(CultureInfo.InvariantCulture)} files.");
                }
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException)
            {
                warnings.Add($"{folderType}: {exception.GetType().Name}");
            }
        }
    }

    private static void CollectWmiSubscriptions(
        ICollection<EvidenceRecord> records,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        const int maximumRecords = 512;
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            using var consumers = new ManagementObjectSearcher(
                scope,
                new ObjectQuery("SELECT Name, __CLASS FROM __EventConsumer"));
            using var consumerCollection = consumers.Get();
            var count = 0;
            foreach (ManagementObject consumer in consumerCollection)
            {
                using (consumer)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (count >= maximumRecords)
                    {
                        warnings.Add($"WMI event-consumer inspection was capped at {maximumRecords.ToString(CultureInfo.InvariantCulture)} records.");
                        break;
                    }

                    records.Add(new EvidenceRecord(
                        "persistence",
                        "persistence.wmi_consumer",
                        @"WMI:root\subscription:__EventConsumer identity only",
                        DateTimeOffset.UtcNow,
                        null,
                        new Dictionary<string, string?>
                        {
                            ["name"] = Convert.ToString(consumer["Name"], CultureInfo.InvariantCulture),
                            ["consumerClass"] = Convert.ToString(consumer["__CLASS"], CultureInfo.InvariantCulture),
                            ["detailBoundary"] = "Consumer command, script, query and payload fields excluded",
                        }));
                    count++;
                }
            }
        }
        catch (Exception exception) when (exception is ManagementException
            or UnauthorizedAccessException
            or System.Security.SecurityException
            or System.Runtime.InteropServices.COMException)
        {
            warnings.Add($"WMI permanent event subscriptions: {exception.GetType().Name}");
        }
    }

    private static string? FormatRegistryValue(object? value) => value switch
    {
        null => null,
        string[] strings => string.Join(", ", strings),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture),
    };

    private static string? FormatCommandReferences(object? value) => value switch
    {
        null => null,
        string[] strings => string.Join(", ", strings.Select(ExtractCommandReference)),
        _ => ExtractCommandReference(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty),
    };

    private static string ExtractCommandReference(string value)
    {
        var text = value.Trim();
        if (text.Length == 0)
        {
            return text;
        }

        if (text.StartsWith('"'))
        {
            var closingQuote = text.IndexOf('"', 1);
            return closingQuote > 1 ? text[1..closingQuote] : text;
        }

        var end = -1;
        foreach (var extension in ExecutableExtensionsForCommands)
        {
            var index = text.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                var proposedEnd = index + extension.Length;
                end = end < 0 ? proposedEnd : Math.Min(end, proposedEnd);
            }
        }

        if (end > 0)
        {
            return text[..end];
        }

        var firstWhitespace = text.IndexOfAny([' ', '\t']);
        return firstWhitespace > 0 ? text[..firstWhitespace] : text;
    }

    private static readonly string[] ExecutableExtensionsForCommands =
        [".exe", ".com", ".cmd", ".bat", ".ps1", ".vbs", ".js"];

    private void CollectRunKeys(
        ICollection<EvidenceRecord> records,
        ICollection<ReferencedBinary> binaryReferences,
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
                            var rawValue = key.GetValue(valueName);
                            records.Add(new EvidenceRecord(
                                Name,
                                "persistence.run_key",
                                $"Registry:{hive}:{view}:{keyPath}",
                                DateTimeOffset.UtcNow,
                                null,
                                new Dictionary<string, string?>
                                {
                                    ["entryName"] = valueName,
                                    ["value"] = redactor.Redact(FormatCommandReferences(rawValue)),
                                    ["valueKind"] = key.GetValueKind(valueName).ToString(),
                                    ["argumentBoundary"] = "command arguments excluded",
                                }));
                            AddResolvedReference(
                                rawValue,
                                "persistence.run_key",
                                valueName,
                                null,
                                binaryReferences);
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

    private void CollectLoadedDriverImages(
        ICollection<EvidenceRecord> records,
        ICollection<ReferencedBinary> binaryReferences,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        const int initialCapacity = 1024;
        const int maximumDrivers = 4096;
        try
        {
            var imageBases = new IntPtr[initialCapacity];
            if (!EnumDeviceDrivers(
                    imageBases,
                    checked((uint)(imageBases.Length * IntPtr.Size)),
                    out var bytesNeeded))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            var requiredCount = checked((int)Math.Min(
                bytesNeeded / (uint)IntPtr.Size,
                maximumDrivers));
            if (requiredCount > imageBases.Length)
            {
                imageBases = new IntPtr[requiredCount];
                if (!EnumDeviceDrivers(
                        imageBases,
                        checked((uint)(imageBases.Length * IntPtr.Size)),
                        out bytesNeeded))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            var returnedCount = Math.Min(
                imageBases.Length,
                checked((int)(bytesNeeded / (uint)IntPtr.Size)));
            if (returnedCount > 0 && imageBases.Take(returnedCount).All(value => value == IntPtr.Zero))
            {
                warnings.Add("PSAPI loaded-driver enumeration returned only null image handles. Windows 11 24H2 requires SeDebugPrivilege to expose valid values; no absence inference was made.");
                return;
            }

            var uniquePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var imageBase in imageBases.Take(returnedCount))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (imageBase == IntPtr.Zero)
                {
                    continue;
                }

                var buffer = new StringBuilder(1024);
                var length = GetDeviceDriverFileName(imageBase, buffer, buffer.Capacity);
                if (length == 0 || length >= buffer.Capacity)
                {
                    continue;
                }

                var reportedPath = buffer.ToString();
                var resolvedPath = ReferencedBinaryPathResolver.TryResolve(reportedPath);
                var evidencePath = resolvedPath ?? reportedPath;
                if (!uniquePaths.Add(evidencePath))
                {
                    continue;
                }

                records.Add(new EvidenceRecord(
                    Name,
                    "persistence.loaded_driver",
                    "PSAPI EnumDeviceDrivers/GetDeviceDriverFileName",
                    DateTimeOffset.UtcNow,
                    null,
                    new Dictionary<string, string?>
                    {
                        ["fileName"] = Path.GetFileName(evidencePath),
                        ["imagePath"] = redactor.Redact(evidencePath),
                        ["pathResolvedForInspection"] = (resolvedPath is not null).ToString().ToLowerInvariant(),
                        ["addressBoundary"] = "Kernel image base intentionally excluded",
                    }));
                if (resolvedPath is not null)
                {
                    binaryReferences.Add(new ReferencedBinary(
                        "persistence.loaded_driver",
                        Path.GetFileName(resolvedPath),
                        "Loaded",
                        resolvedPath));
                }
            }

            if (bytesNeeded / (uint)IntPtr.Size > maximumDrivers)
            {
                warnings.Add($"Loaded-driver enumeration was capped at {maximumDrivers.ToString(CultureInfo.InvariantCulture)} entries.");
            }
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception
            or OverflowException
            or ArgumentException
            or System.Security.SecurityException)
        {
            warnings.Add($"PSAPI loaded-driver enumeration: {exception.GetType().Name}");
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
            .OrderBy(group => ReferencePriority(group.Select(reference => reference.ReferenceKind)))
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
                "resolved persistence executable references",
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

    private static void AddResolvedReference(
        object? value,
        string kind,
        string? name,
        string? startMode,
        ICollection<ReferencedBinary> references)
    {
        var values = value is string[] strings
            ? strings
            : [Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty];
        foreach (var candidate in values)
        {
            var resolvedPath = ReferencedBinaryPathResolver.TryResolve(candidate);
            if (resolvedPath is not null)
            {
                references.Add(new ReferencedBinary(kind, name, startMode, resolvedPath));
            }
        }
    }

    private static int ReferencePriority(IEnumerable<string> kinds)
    {
        var values = kinds.ToArray();
        if (values.Contains("persistence.driver", StringComparer.Ordinal))
        {
            return 0;
        }

        if (values.Contains("persistence.loaded_driver", StringComparer.Ordinal))
        {
            return 0;
        }

        if (values.Contains("persistence.ifeo_debugger", StringComparer.Ordinal))
        {
            return 1;
        }

        if (values.Contains("persistence.service", StringComparer.Ordinal))
        {
            return 2;
        }

        return 3;
    }

    private sealed record ReferencedBinary(
        string ReferenceKind,
        string? Name,
        string? StartMode,
        string ResolvedPath);

    private sealed record RegistryValueLocation(
        RegistryHive Hive,
        string KeyPath,
        string LocationType,
        IReadOnlyList<string> ValueNames);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDeviceDrivers(
        [Out] IntPtr[] imageBase,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetDeviceDriverFileName(
        IntPtr imageBase,
        StringBuilder fileName,
        int size);
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

    public static bool IsExecutablePath(string path) =>
        ExecutableExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase)
        && File.Exists(path);
}
