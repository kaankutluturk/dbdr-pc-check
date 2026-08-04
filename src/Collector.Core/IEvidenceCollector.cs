using Dbdr.PcCheck.Collector.Core.Models;

namespace Dbdr.PcCheck.Collector.Core;

public interface IEvidenceCollector
{
    string Name { get; }

    Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken);
}
