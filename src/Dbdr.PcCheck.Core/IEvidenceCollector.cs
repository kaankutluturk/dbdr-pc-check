using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core;

public interface IEvidenceCollector
{
    string Name { get; }

    Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken);
}
