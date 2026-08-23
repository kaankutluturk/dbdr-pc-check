using System.Diagnostics;
using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class SrumApplicationUsageSource(PathRedactor redactor) : IExecutionHistorySource
{
    public const long MaximumPowerCfgExportBytes = 64L * 1024 * 1024;
    public const int MaximumEmittedRecords = 5_000;
    public static readonly TimeSpan ExportTimeout = TimeSpan.FromSeconds(60);

    public string Name => "SRUM application usage";

    public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new EvidenceSourceResult(Name, EvidenceSourceStatus.NotSupported, [], "Windows source");
        }

        var temporaryDirectory = Path.Combine(Path.GetTempPath(), $"dbdr-srum-{Guid.NewGuid():N}");
        var exportPath = Path.Combine(temporaryDirectory, "srum.xml");
        try
        {
            Directory.CreateDirectory(temporaryDirectory);
            var powerCfgPath = Path.Combine(Environment.SystemDirectory, "powercfg.exe");
            if (!File.Exists(powerCfgPath))
            {
                return new EvidenceSourceResult(Name, EvidenceSourceStatus.NotSupported, [], "powercfg.exe unavailable");
            }

            using var process = new Process
            {
                StartInfo = CreateStartInfo(powerCfgPath, exportPath),
            };
            if (!process.Start())
            {
                return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], "powercfg start failed");
            }

            var deadline = DateTimeOffset.UtcNow + ExportTimeout;
            while (!process.WaitForExit(250))
            {
                var growingExport = new FileInfo(exportPath);
                growingExport.Refresh();
                if (growingExport.Exists && growingExport.Length > MaximumPowerCfgExportBytes)
                {
                    TryTerminate(process);
                    return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], "powercfg export size cap reached");
                }

                if (cancellationToken.IsCancellationRequested || DateTimeOffset.UtcNow >= deadline)
                {
                    TryTerminate(process);
                    cancellationToken.ThrowIfCancellationRequested();
                    return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], "powercfg timeout");
                }
            }

            if (process.ExitCode != 0)
            {
                return new EvidenceSourceResult(
                    Name,
                    EvidenceSourceStatus.Unavailable,
                    [],
                    $"powercfg exitCode={process.ExitCode.ToString(CultureInfo.InvariantCulture)}");
            }

            var export = new FileInfo(exportPath);
            export.Refresh();
            if (!export.Exists || export.Length is <= 0 or > MaximumPowerCfgExportBytes)
            {
                var length = export.Exists ? export.Length.ToString(CultureInfo.InvariantCulture) : "missing";
                return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], $"invalid export bytes={length}");
            }

            using var stream = new FileStream(
                export.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.SequentialScan);
            var parsed = SrumApplicationUsageParser.Parse(
                stream,
                context,
                redactor,
                DateTimeOffset.UtcNow,
                cancellationToken,
                MaximumEmittedRecords);
            var detail = $"recognizedRows={parsed.RecognizedRowCount.ToString(CultureInfo.InvariantCulture)}; "
                + $"emitted={parsed.Records.Count.ToString(CultureInfo.InvariantCulture)}; "
                + $"droppedIdentity={parsed.DroppedIdentityCount.ToString(CultureInfo.InvariantCulture)}; "
                + $"outOfWindow={parsed.OutOfWindowCount.ToString(CultureInfo.InvariantCulture)}; "
                + $"capped={parsed.Capped.ToString().ToLowerInvariant()}; "
                + $"temporaryExportBytes={export.Length.ToString(CultureInfo.InvariantCulture)}";
            if (parsed.RecognizedRowCount > 0 && parsed.RecognizedIdentityCount == 0)
            {
                return new EvidenceSourceResult(
                    Name,
                    EvidenceSourceStatus.Unavailable,
                    [],
                    $"application identities could not be minimized from this powercfg schema; {detail}");
            }

            return new EvidenceSourceResult(
                Name,
                parsed.Records.Count == 0 ? EvidenceSourceStatus.Empty : EvidenceSourceStatus.Available,
                parsed.Records,
                detail);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or XmlException
            or InvalidOperationException
            or System.ComponentModel.Win32Exception)
        {
            return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], exception.GetType().Name);
        }
        finally
        {
            TryDeleteTemporaryDirectory(temporaryDirectory);
        }
    }

    private static ProcessStartInfo CreateStartInfo(string powerCfgPath, string exportPath)
    {
        var startInfo = new ProcessStartInfo(powerCfgPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("/srumutil");
        startInfo.ArgumentList.Add("/output");
        startInfo.ArgumentList.Add(exportPath);
        startInfo.ArgumentList.Add("/xml");
        return startInfo;
    }

    private static void TryTerminate(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException
            or System.ComponentModel.Win32Exception
            or NotSupportedException)
        {
        }
    }

    private static void TryDeleteTemporaryDirectory(string temporaryDirectory)
    {
        try
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}

public sealed record SrumApplicationUsageParseResult(
    IReadOnlyList<EvidenceRecord> Records,
    int RecognizedRowCount,
    int RecognizedIdentityCount,
    int DroppedIdentityCount,
    int OutOfWindowCount,
    bool Capped);

public static class SrumApplicationUsageParser
{
    public const long MaximumXmlCharacters = SrumApplicationUsageSource.MaximumPowerCfgExportBytes;
    public const int MaximumCandidateElements = 250_000;

    private static readonly string[] TimestampFields =
    [
        "TimeStamp",
        "Timestamp",
        "EventTimestamp",
        "StartTime",
        "DateTime",
    ];

    private static readonly string[] ApplicationFields =
    [
        "ExeInfo",
        "ImagePath",
        "ApplicationPath",
        "ExecutablePath",
        "ApplicationName",
        "Application",
        "AppId",
    ];

    private static readonly string[] ExecutionExtensions =
    [
        ".exe",
        ".dll",
        ".sys",
        ".com",
        ".scr",
        ".ps1",
        ".bat",
        ".cmd",
    ];

    public static SrumApplicationUsageParseResult Parse(
        Stream stream,
        CollectionContext context,
        PathRedactor redactor,
        DateTimeOffset collectedAtUtc,
        CancellationToken cancellationToken,
        int maximumRecords = SrumApplicationUsageSource.MaximumEmittedRecords)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(redactor);
        if (!stream.CanRead)
        {
            throw new ArgumentException("The SRUM XML stream is not readable.", nameof(stream));
        }

        if (maximumRecords is <= 0 or > SrumApplicationUsageSource.MaximumEmittedRecords)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumXmlCharacters,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
        };
        using var reader = XmlReader.Create(stream, settings);
        var document = XDocument.Load(reader, LoadOptions.None);
        var records = new List<EvidenceRecord>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var recognizedRows = 0;
        var recognizedIdentities = 0;
        var droppedIdentities = 0;
        var outOfWindow = 0;
        var candidates = 0;
        var capped = false;

        foreach (var element in document.Descendants().Where(IsScalarContainer))
        {
            if (++candidates > MaximumCandidateElements)
            {
                capped = true;
                break;
            }

            if ((candidates & 0xFF) == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            var values = ReadScalarValues(element);
            if (!TryReadTimestamp(values, out var timestamp))
            {
                continue;
            }

            recognizedRows++;
            if (!TryReadApplicationIdentity(values, out var identity))
            {
                droppedIdentities++;
                continue;
            }

            recognizedIdentities++;
            if (timestamp < context.ReviewWindowStartUtc || timestamp > context.ReviewWindowEndUtc)
            {
                outOfWindow++;
                continue;
            }

            var redacted = redactor.Redact(identity)?.Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(redacted))
            {
                droppedIdentities++;
                continue;
            }

            var applicationName = GetFileName(redacted);
            var hasPath = redacted.Contains('\\') || redacted.Contains('/');
            var deduplicationKey = $"{redacted}\u001f{timestamp:O}";
            if (!seen.Add(deduplicationKey))
            {
                continue;
            }

            records.Add(new EvidenceRecord(
                "execution-history",
                "execution.srum_application",
                "Windows powercfg /srumutil",
                collectedAtUtc,
                timestamp,
                new Dictionary<string, string?>
                {
                    ["applicationName"] = applicationName,
                    ["applicationPath"] = hasPath ? redacted : null,
                    ["identityForm"] = hasPath ? "redacted-path" : "file-name",
                }));
            if (records.Count >= maximumRecords)
            {
                capped = true;
                break;
            }
        }

        return new SrumApplicationUsageParseResult(
            records,
            recognizedRows,
            recognizedIdentities,
            droppedIdentities,
            outOfWindow,
            capped);
    }

    private static bool IsScalarContainer(XElement element)
    {
        var children = element.Elements().ToArray();
        return children.Length > 0 && children.All(child => !child.HasElements);
    }

    private static Dictionary<string, string> ReadScalarValues(XElement element)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var attribute in element.Attributes())
        {
            values.TryAdd(attribute.Name.LocalName, attribute.Value);
        }

        foreach (var child in element.Elements())
        {
            var scalarValue = string.IsNullOrWhiteSpace(child.Value)
                ? child.Attributes().FirstOrDefault(attribute => string.Equals(
                    attribute.Name.LocalName,
                    "value",
                    StringComparison.OrdinalIgnoreCase))?.Value
                : child.Value;
            if (!string.IsNullOrWhiteSpace(scalarValue))
            {
                values.TryAdd(child.Name.LocalName, scalarValue);
                var namedKey = child.Attributes().FirstOrDefault(attribute =>
                    string.Equals(attribute.Name.LocalName, "name", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(attribute.Name.LocalName, "key", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(attribute.Name.LocalName, "column", StringComparison.OrdinalIgnoreCase))?.Value;
                if (!string.IsNullOrWhiteSpace(namedKey))
                {
                    values.TryAdd(namedKey, scalarValue);
                }
            }

            foreach (var attribute in child.Attributes())
            {
                values.TryAdd(attribute.Name.LocalName, attribute.Value);
            }
        }

        return values;
    }

    private static bool TryReadTimestamp(
        IReadOnlyDictionary<string, string> values,
        out DateTimeOffset timestamp)
    {
        foreach (var field in TimestampFields)
        {
            if (values.TryGetValue(field, out var value)
                && DateTimeOffset.TryParse(
                    value,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out timestamp))
            {
                return true;
            }
        }

        timestamp = default;
        return false;
    }

    private static bool TryReadApplicationIdentity(
        IReadOnlyDictionary<string, string> values,
        out string identity)
    {
        foreach (var field in ApplicationFields)
        {
            if (values.TryGetValue(field, out var value) && LooksExecutionCapable(value))
            {
                identity = value.Trim();
                return true;
            }
        }

        identity = string.Empty;
        return false;
    }

    private static bool LooksExecutionCapable(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 2048
            || value.Any(char.IsControl)
            || long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
        {
            return false;
        }

        var candidate = value.Trim().Trim('"');
        return ExecutionExtensions.Any(extension =>
            candidate.EndsWith(extension, StringComparison.OrdinalIgnoreCase));
    }

    private static string GetFileName(string value)
    {
        var separator = Math.Max(value.LastIndexOf('\\'), value.LastIndexOf('/'));
        return separator >= 0 && separator + 1 < value.Length ? value[(separator + 1)..] : value;
    }
}
