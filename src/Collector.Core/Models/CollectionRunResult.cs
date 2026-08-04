namespace Dbdr.PcCheck.Collector.Core.Models;

public sealed record CollectionRunResult(
    CollectionContext Context,
    DateTimeOffset CompletedUtc,
    IReadOnlyList<ModuleResult> Modules)
{
    public IReadOnlyList<EvidenceRecord> Records => Modules.SelectMany(module => module.Records).ToArray();
}
