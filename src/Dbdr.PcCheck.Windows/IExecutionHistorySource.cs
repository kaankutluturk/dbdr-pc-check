using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public interface IExecutionHistorySource
{
    string Name { get; }

    EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken);
}
