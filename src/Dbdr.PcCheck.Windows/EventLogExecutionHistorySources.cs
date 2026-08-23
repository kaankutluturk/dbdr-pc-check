using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml.Linq;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class ServiceInstallEventSource(PathRedactor redactor) : EventLogExecutionHistorySource
{
    public override string Name => "Service Control Manager installation events";

    protected override string LogName => "System";

    protected override string Query => "*[System[(EventID=7045)]]";

    protected override EvidenceRecord CreateRecord(EventRecord record, DateTimeOffset timestampUtc)
    {
        var properties = record.Properties;
        return new EvidenceRecord(
            "execution-history",
            "event.service_install",
            "Windows Event Log:System/7045",
            DateTimeOffset.UtcNow,
            timestampUtc,
            new Dictionary<string, string?>
            {
                ["eventId"] = record.Id.ToString(CultureInfo.InvariantCulture),
                ["recordId"] = record.RecordId?.ToString(CultureInfo.InvariantCulture),
                ["provider"] = record.ProviderName,
                ["serviceName"] = ValueAt(properties, 0),
                ["imagePath"] = redactor.Redact(ValueAt(properties, 1)),
                ["serviceType"] = ValueAt(properties, 2),
                ["startType"] = ValueAt(properties, 3),
            });
    }
}

public sealed class CodeIntegrityEventSource(PathRedactor redactor) : EventLogExecutionHistorySource
{
    public override string Name => "Windows Code Integrity validation and block events";

    protected override string LogName => "Microsoft-Windows-CodeIntegrity/Operational";

    protected override string Query => "*[System[(EventID=3001 or EventID=3004 or EventID=3023 or EventID=3033 or EventID=3034 or EventID=3064 or EventID=3065 or EventID=3074 or EventID=3076 or EventID=3077 or EventID=3079 or EventID=3080 or EventID=3081 or EventID=3089)]]";

    protected override EvidenceRecord CreateRecord(EventRecord record, DateTimeOffset timestampUtc)
    {
        var data = EventDataFieldReader.Read(record);
        return new EvidenceRecord(
            "execution-history",
            "event.code_integrity",
            "Windows Event Log:CodeIntegrity/Operational selected validation metadata",
            DateTimeOffset.UtcNow,
            timestampUtc,
            new Dictionary<string, string?>
            {
                ["eventId"] = record.Id.ToString(CultureInfo.InvariantCulture),
                ["recordId"] = record.RecordId?.ToString(CultureInfo.InvariantCulture),
                ["provider"] = record.ProviderName,
                ["level"] = record.Level?.ToString(CultureInfo.InvariantCulture),
                ["classification"] = Classify(record.Id),
                ["filePath"] = redactor.Redact(data.GetValueOrDefault("FileName") ?? data.GetValueOrDefault("FilePath")),
                ["processPath"] = redactor.Redact(data.GetValueOrDefault("ProcessName")),
                ["requestedSigningLevel"] = data.GetValueOrDefault("RequestedSigningLevel"),
                ["validatedSigningLevel"] = data.GetValueOrDefault("ValidatedSigningLevel"),
                ["verificationError"] = data.GetValueOrDefault("VerificationError"),
                ["signatureType"] = data.GetValueOrDefault("SignatureType"),
                ["totalSignatureCount"] = data.GetValueOrDefault("TotalSignatureCount"),
                ["policyName"] = data.GetValueOrDefault("PolicyName"),
                ["timestampBasis"] = "Code Integrity event creation time; message and non-whitelisted payload fields excluded",
            });
    }

    private static string Classify(int eventId) => eventId switch
    {
        3001 => "unsigned-driver-load-attempt",
        3004 => "signature-validation-failure",
        3023 => "driver-policy-requirement-failure",
        3033 or 3065 or 3077 or 3079 or 3081 => "blocked-or-signing-requirement-failure",
        3034 or 3064 or 3076 or 3080 => "audit-would-block",
        3074 => "page-hash-failure-with-memory-integrity",
        3089 => "correlated-signature-information",
        _ => "selected-validation-event",
    };
}

public sealed class ApplicationCrashEventSource(PathRedactor redactor) : EventLogExecutionHistorySource
{
    public override string Name => "Application Error crash metadata";

    protected override string LogName => "Application";

    protected override string Query => "*[System[Provider[@Name='Application Error'] and (EventID=1000)]]";

    protected override EvidenceRecord CreateRecord(EventRecord record, DateTimeOffset timestampUtc)
    {
        var properties = record.Properties;
        return new EvidenceRecord(
            "execution-history",
            "event.application_crash",
            "Windows Event Log:Application Error/1000",
            DateTimeOffset.UtcNow,
            timestampUtc,
            new Dictionary<string, string?>
            {
                ["eventId"] = record.Id.ToString(CultureInfo.InvariantCulture),
                ["recordId"] = record.RecordId?.ToString(CultureInfo.InvariantCulture),
                ["provider"] = record.ProviderName,
                ["applicationName"] = ValueAt(properties, 0),
                ["applicationVersion"] = ValueAt(properties, 1),
                ["faultModuleName"] = ValueAt(properties, 3),
                ["faultModuleVersion"] = ValueAt(properties, 4),
                ["exceptionCode"] = ValueAt(properties, 6),
                ["applicationPath"] = redactor.Redact(ValueAt(properties, 10)),
                ["faultModulePath"] = redactor.Redact(ValueAt(properties, 11)),
                ["timestampBasis"] = "Application Error event creation time",
            });
    }
}

public sealed class PowerShellEngineEventSource : EventLogExecutionHistorySource
{
    public override string Name => "PowerShell engine and provider lifecycle";

    protected override string LogName => "Windows PowerShell";

    protected override string Query => "*[System[(EventID=400 or EventID=403 or EventID=600)]]";

    protected override EvidenceRecord CreateRecord(EventRecord record, DateTimeOffset timestampUtc) => new(
        "execution-history",
        "event.powershell_engine",
        "Windows Event Log:Windows PowerShell metadata",
        DateTimeOffset.UtcNow,
        timestampUtc,
        new Dictionary<string, string?>
        {
            ["eventId"] = record.Id.ToString(CultureInfo.InvariantCulture),
            ["recordId"] = record.RecordId?.ToString(CultureInfo.InvariantCulture),
            ["provider"] = record.ProviderName,
            ["level"] = record.Level?.ToString(CultureInfo.InvariantCulture),
            ["lifecycle"] = record.Id switch
            {
                400 => "engine-start",
                403 => "engine-stop",
                600 => "provider-lifecycle",
                _ => "selected-metadata",
            },
            ["timestampBasis"] = "PowerShell event creation time; event payload excluded",
        });
}

public abstract class EventLogExecutionHistorySource : IExecutionHistorySource
{
    private const int MaximumEventsToInspect = 2000;

    public abstract string Name { get; }

    protected abstract string LogName { get; }

    protected abstract string Query { get; }

    public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken)
    {
        try
        {
            var query = new EventLogQuery(LogName, PathType.LogName, Query)
            {
                ReverseDirection = true,
                TolerateQueryErrors = false,
            };
            using var reader = new EventLogReader(query);
            var records = new List<EvidenceRecord>();
            var inspected = 0;

            while (inspected < MaximumEventsToInspect)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null)
                {
                    break;
                }

                inspected++;
                if (!record.TimeCreated.HasValue)
                {
                    continue;
                }

                var timestampUtc = new DateTimeOffset(record.TimeCreated.Value.ToUniversalTime());
                if (timestampUtc > context.ReviewWindowEndUtc)
                {
                    continue;
                }

                if (timestampUtc < context.ReviewWindowStartUtc)
                {
                    break;
                }

                records.Add(CreateRecord(record, timestampUtc));
            }

            var ordered = records.OrderBy(record => record.SourceTimestampUtc).ToArray();
            return new EvidenceSourceResult(
                Name,
                ordered.Length == 0 ? EvidenceSourceStatus.Empty : EvidenceSourceStatus.Available,
                ordered,
                $"Filtered to the explicit review window; inspected at most {MaximumEventsToInspect.ToString(CultureInfo.InvariantCulture)} matching events.");
        }
        catch (Exception exception) when (exception is EventLogException
            or UnauthorizedAccessException
            or System.Security.SecurityException)
        {
            return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], exception.GetType().Name);
        }
    }

    protected abstract EvidenceRecord CreateRecord(EventRecord record, DateTimeOffset timestampUtc);

    protected static string? ValueAt(IList<EventProperty> properties, int index) =>
        index >= 0 && index < properties.Count
            ? Convert.ToString(properties[index].Value, CultureInfo.InvariantCulture)
            : null;
}

internal static class EventDataFieldReader
{
    private static readonly HashSet<string> AllowedNames = new(StringComparer.Ordinal)
    {
        "FileName",
        "FilePath",
        "ProcessName",
        "RequestedSigningLevel",
        "ValidatedSigningLevel",
        "VerificationError",
        "SignatureType",
        "TotalSignatureCount",
        "PolicyName",
    };

    public static IReadOnlyDictionary<string, string?> Read(EventRecord record)
    {
        try
        {
            var document = XDocument.Parse(record.ToXml(), LoadOptions.None);
            return document
                .Descendants()
                .Where(element => element.Name.LocalName == "Data")
                .Select(element => new
                {
                    Name = element.Attribute("Name")?.Value,
                    Value = element.Value,
                })
                .Where(item => item.Name is not null && AllowedNames.Contains(item.Name))
                .GroupBy(item => item.Name!, StringComparer.Ordinal)
                .ToDictionary(
                    group => group.Key,
                    group => (string?)group.First().Value,
                    StringComparer.Ordinal);
        }
        catch (Exception exception) when (exception is EventLogException
            or System.Xml.XmlException
            or InvalidOperationException)
        {
            return new Dictionary<string, string?>(StringComparer.Ordinal);
        }
    }
}
