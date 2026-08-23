using System.Diagnostics;
using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class ScheduledTaskCollector(
    PathRedactor redactor,
    string? taskDirectory = null,
    IExecutableFileInspector? fileInspector = null) : IEvidenceCollector
{
    public const int MaximumTaskDefinitions = 5_000;
    public const long MaximumTaskDefinitionBytes = 4L * 1024 * 1024;
    private readonly string _taskDirectory = taskDirectory
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");

    public string Name => "scheduled-tasks";

    public async Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var records = new List<EvidenceRecord>();
        var warnings = new List<string>();
        var binaryReferences = new List<ScheduledTaskBinaryReference>();
        var status = "available";
        string? detail = null;

        progress?.Report(new CollectionProgress(Name, "Reading Windows scheduled task definitions"));
        if (!Directory.Exists(_taskDirectory))
        {
            status = "unavailable";
            detail = "Scheduled task directory was not present.";
            warnings.Add(detail);
        }
        else
        {
            try
            {
                var paths = Directory.EnumerateFiles(_taskDirectory, "*", SearchOption.AllDirectories)
                    .Take(MaximumTaskDefinitions + 1)
                    .ToArray();
                foreach (var path in paths.Take(MaximumTaskDefinitions))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        var parsed = ParseTask(path);
                        records.Add(parsed.Record);
                        if (parsed.ResolvedExecutablePath is not null)
                        {
                            binaryReferences.Add(new ScheduledTaskBinaryReference(
                                parsed.TaskPath,
                                parsed.ResolvedExecutablePath));
                        }
                    }
                    catch (Exception exception) when (exception is IOException
                        or UnauthorizedAccessException
                        or System.Security.SecurityException
                        or XmlException
                        or InvalidOperationException)
                    {
                        var taskPath = Path.GetRelativePath(_taskDirectory, path);
                        warnings.Add($"{taskPath}: {exception.GetType().Name}");
                    }
                }

                if (paths.Length > MaximumTaskDefinitions)
                {
                    warnings.Add($"Scheduled task enumeration was capped at {MaximumTaskDefinitions.ToString(CultureInfo.InvariantCulture)} definitions.");
                }

                if (records.Count == 0)
                {
                    status = "empty";
                    detail = "No readable scheduled task definitions were found.";
                }
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException)
            {
                status = "unavailable";
                detail = exception.GetType().Name;
                warnings.Add($"Scheduled task enumeration: {exception.GetType().Name}");
            }
        }

        if (fileInspector is not null && binaryReferences.Count > 0)
        {
            await CollectBinaryEvidenceAsync(
                binaryReferences,
                records,
                warnings,
                progress,
                cancellationToken).ConfigureAwait(false);
        }

        records.Add(new EvidenceRecord(
            Name,
            "coverage.source",
            "Windows scheduled task definitions",
            DateTimeOffset.UtcNow,
            null,
            new Dictionary<string, string?>
            {
                ["sourceName"] = "Windows scheduled task definitions",
                ["status"] = status,
                ["recordCount"] = records.Count.ToString(CultureInfo.InvariantCulture),
                ["detail"] = detail,
            }));

        stopwatch.Stop();
        return new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []);
    }

    private ParsedScheduledTask ParseTask(string path)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (file.Length > MaximumTaskDefinitionBytes)
        {
            throw new InvalidDataException("The scheduled task definition exceeds the 4 MiB parser limit.");
        }

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumTaskDefinitionBytes,
            MaxCharactersFromEntities = 0,
        };
        using var reader = XmlReader.Create(path, settings);
        var document = XDocument.Load(reader, LoadOptions.None);
        var root = document.Root ?? throw new XmlException("Scheduled task XML has no root element.");
        var xmlNamespace = root.Name.Namespace;
        var taskPath = Path.GetRelativePath(_taskDirectory, path).Replace(Path.DirectorySeparatorChar, '\\');
        var registrationDate = ParseTimestamp(root
            .Element(xmlNamespace + "RegistrationInfo")?
            .Element(xmlNamespace + "Date")?
            .Value);
        var command = root
            .Element(xmlNamespace + "Actions")?
            .Elements(xmlNamespace + "Exec")
            .Select(action => action.Element(xmlNamespace + "Command")?.Value)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        var settingsElement = root.Element(xmlNamespace + "Settings");
        var triggers = root
            .Element(xmlNamespace + "Triggers")?
            .Elements()
            .Select(trigger => trigger.Name.LocalName)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray() ?? [];

        return new ParsedScheduledTask(
            new EvidenceRecord(
                Name,
                "persistence.scheduled_task",
                "Windows scheduled task XML",
                DateTimeOffset.UtcNow,
                registrationDate,
                new Dictionary<string, string?>
                {
                    ["taskPath"] = taskPath,
                    ["command"] = redactor.Redact(command),
                    ["enabled"] = ParseBoolean(settingsElement?.Element(xmlNamespace + "Enabled")?.Value, defaultValue: true),
                    ["hidden"] = ParseBoolean(settingsElement?.Element(xmlNamespace + "Hidden")?.Value, defaultValue: false),
                    ["triggerTypes"] = string.Join(", ", triggers),
                    ["fileModifiedUtc"] = file.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                }),
            taskPath,
            ReferencedBinaryPathResolver.TryResolve(command));
    }

    private async Task CollectBinaryEvidenceAsync(
        IEnumerable<ScheduledTaskBinaryReference> references,
        ICollection<EvidenceRecord> records,
        ICollection<string> warnings,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        const int maximumBinaries = 256;
        var groups = references
            .GroupBy(reference => reference.ResolvedPath, StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Take(maximumBinaries)
            .ToArray();
        var failures = 0;
        for (var index = 0; index < groups.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var group = groups[index];
            progress?.Report(new CollectionProgress(
                Name,
                $"Inspecting scheduled-task binary {index + 1} of {groups.Length}",
                index + 1,
                groups.Length));
            var evidence = await fileInspector!
                .InspectAsync(group.Key, cancellationToken)
                .ConfigureAwait(false);
            if (evidence.Error is not null)
            {
                failures++;
            }

            var fields = new Dictionary<string, string?>
            {
                ["executablePath"] = redactor.Redact(group.Key),
                ["referenceKinds"] = "persistence.scheduled_task",
                ["referenceNames"] = string.Join(
                    ", ",
                    group.Select(reference => reference.TaskPath)
                        .Distinct(StringComparer.OrdinalIgnoreCase)),
            };
            evidence.AddTo(fields);
            records.Add(new EvidenceRecord(
                Name,
                "persistence.binary",
                "resolved scheduled-task executable references",
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
            warnings.Add($"Scheduled-task binary inspection was capped at {maximumBinaries.ToString(CultureInfo.InvariantCulture)} of {totalUnique.ToString(CultureInfo.InvariantCulture)} unique paths.");
        }

        if (failures > 0)
        {
            warnings.Add($"Scheduled-task binary inspection was incomplete for {failures.ToString(CultureInfo.InvariantCulture)} path(s). Review per-record errors.");
        }
    }

    private static DateTimeOffset? ParseTimestamp(string? value)
    {
        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            return null;
        }

        return parsed.ToUniversalTime();
    }

    private static string ParseBoolean(string? value, bool defaultValue) =>
        (bool.TryParse(value, out var parsed) ? parsed : defaultValue) ? "true" : "false";

    private sealed record ParsedScheduledTask(
        EvidenceRecord Record,
        string TaskPath,
        string? ResolvedExecutablePath);

    private sealed record ScheduledTaskBinaryReference(string TaskPath, string ResolvedPath);
}
