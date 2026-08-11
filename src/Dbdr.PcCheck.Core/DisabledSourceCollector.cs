using System.Diagnostics;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core;

public sealed class DisabledSourceCollector(IEnumerable<string> sourceNames) : IEvidenceCollector
{
    private readonly IReadOnlyList<string> _sourceNames = sourceNames
        .Where(sourceName => !string.IsNullOrWhiteSpace(sourceName))
        .Distinct(StringComparer.Ordinal)
        .OrderBy(sourceName => sourceName, StringComparer.Ordinal)
        .ToArray();

    public string Name => "operator-selection";

    public Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var stopwatch = Stopwatch.StartNew();
        progress?.Report(new CollectionProgress(Name, "Recording disabled evidence sources"));

        var records = _sourceNames
            .Select(sourceName => new EvidenceRecord(
                Name,
                "coverage.source",
                "operator selection",
                DateTimeOffset.UtcNow,
                null,
                new Dictionary<string, string?>
                {
                    ["sourceName"] = sourceName,
                    ["status"] = "disabled",
                    ["recordCount"] = "0",
                    ["detail"] = "Disabled by the operator before collection.",
                }))
            .ToArray();

        stopwatch.Stop();
        return Task.FromResult(new ModuleResult(Name, true, stopwatch.Elapsed, records, [], []));
    }
}
