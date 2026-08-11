using System.Diagnostics;
using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class ScheduledTaskCollector(
    PathRedactor redactor,
    string? taskDirectory = null) : IEvidenceCollector
{
    private readonly string _taskDirectory = taskDirectory
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");

    public string Name => "scheduled-tasks";

    public Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var records = new List<EvidenceRecord>();
        var warnings = new List<string>();
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
                foreach (var path in Directory.EnumerateFiles(_taskDirectory, "*", SearchOption.AllDirectories))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        records.Add(ParseTask(path));
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
        return Task.FromResult(new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []));
    }

    private EvidenceRecord ParseTask(string path)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
        };
        using var reader = XmlReader.Create(path, settings);
        var document = XDocument.Load(reader, LoadOptions.None);
        var root = document.Root ?? throw new XmlException("Scheduled task XML has no root element.");
        var xmlNamespace = root.Name.Namespace;
        var taskPath = Path.GetRelativePath(_taskDirectory, path).Replace(Path.DirectorySeparatorChar, '\\');
        var file = new FileInfo(path);
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

        return new EvidenceRecord(
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
            });
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
}
