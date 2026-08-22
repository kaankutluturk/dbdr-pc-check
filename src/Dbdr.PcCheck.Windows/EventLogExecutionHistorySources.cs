using System.Diagnostics.Eventing.Reader;
using System.Globalization;
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

public sealed class CodeIntegrityEventSource : EventLogExecutionHistorySource
{
    public override string Name => "Windows Code Integrity warnings and errors";

    protected override string LogName => "Microsoft-Windows-CodeIntegrity/Operational";

    protected override string Query => "*[System[(Level=2 or Level=3)]]";

    protected override EvidenceRecord CreateRecord(EventRecord record, DateTimeOffset timestampUtc) => new(
        "execution-history",
        "event.code_integrity",
        "Windows Event Log:CodeIntegrity/Operational",
        DateTimeOffset.UtcNow,
        timestampUtc,
        new Dictionary<string, string?>
        {
            ["eventId"] = record.Id.ToString(CultureInfo.InvariantCulture),
            ["recordId"] = record.RecordId?.ToString(CultureInfo.InvariantCulture),
            ["provider"] = record.ProviderName,
            ["level"] = record.Level?.ToString(CultureInfo.InvariantCulture),
        });
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
