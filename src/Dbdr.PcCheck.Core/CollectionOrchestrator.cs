using System.Diagnostics;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core;

public sealed class CollectionOrchestrator(IEnumerable<IEvidenceCollector> collectors)
{
    private readonly IReadOnlyList<IEvidenceCollector> _collectors = collectors.ToArray();

    public async Task<CollectionRunResult> RunAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var results = new List<ModuleResult>(_collectors.Count);

        foreach (var collector in _collectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new CollectionProgress(collector.Name, "Starting module"));
            var stopwatch = Stopwatch.StartNew();

            try
            {
                var result = await collector
                    .CollectAsync(context, progress, cancellationToken)
                    .ConfigureAwait(false);
                results.Add(result);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                results.Add(new ModuleResult(
                    collector.Name,
                    false,
                    stopwatch.Elapsed,
                    [],
                    [],
                    [$"{exception.GetType().Name}: {exception.Message}"]));
            }
            finally
            {
                stopwatch.Stop();
            }
        }

        return new CollectionRunResult(context, DateTimeOffset.UtcNow, results);
    }
}
