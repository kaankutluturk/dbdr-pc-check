using System.Diagnostics;
using System.Globalization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class ExecutionHistoryCollector(IEnumerable<IExecutionHistorySource> sources) : IEvidenceCollector
{
    private readonly IReadOnlyList<IExecutionHistorySource> _sources = sources.ToArray();

    public string Name => "execution-history";

    public Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var records = new List<EvidenceRecord>();
        var warnings = new List<string>();

        for (var index = 0; index < _sources.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = _sources[index];
            progress?.Report(new CollectionProgress(
                Name,
                $"Reading {source.Name}",
                index + 1,
                _sources.Count));

            EvidenceSourceResult result;
            try
            {
                result = source.Collect(context, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                result = new EvidenceSourceResult(
                    source.Name,
                    EvidenceSourceStatus.Unavailable,
                    [],
                    exception.GetType().Name);
            }

            records.AddRange(result.Records);
            records.Add(CreateCoverageRecord(result));

            if (result.Status is EvidenceSourceStatus.Unavailable
                or EvidenceSourceStatus.Disabled
                or EvidenceSourceStatus.NotSupported)
            {
                warnings.Add($"{result.SourceName}: {StatusText(result.Status)}{FormatDetail(result.Detail)}");
            }
        }

        stopwatch.Stop();
        return Task.FromResult(new ModuleResult(Name, true, stopwatch.Elapsed, records, warnings, []));
    }

    private EvidenceRecord CreateCoverageRecord(EvidenceSourceResult result) => new(
        Name,
        "coverage.source",
        result.SourceName,
        DateTimeOffset.UtcNow,
        null,
        new Dictionary<string, string?>
        {
            ["sourceName"] = result.SourceName,
            ["status"] = StatusText(result.Status),
            ["recordCount"] = result.Records.Count.ToString(CultureInfo.InvariantCulture),
            ["detail"] = result.Detail,
        });

    private static string StatusText(EvidenceSourceStatus status) => status switch
    {
        EvidenceSourceStatus.Available => "available",
        EvidenceSourceStatus.Empty => "empty",
        EvidenceSourceStatus.Unavailable => "unavailable",
        EvidenceSourceStatus.Disabled => "disabled",
        EvidenceSourceStatus.NotSupported => "notSupported",
        _ => "unavailable",
    };

    private static string FormatDetail(string? detail) =>
        string.IsNullOrWhiteSpace(detail) ? string.Empty : $" ({detail})";
}
