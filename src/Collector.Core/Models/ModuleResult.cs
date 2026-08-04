namespace Dbdr.PcCheck.Collector.Core.Models;

public sealed record ModuleResult(
    string Module,
    bool Completed,
    TimeSpan Duration,
    IReadOnlyList<EvidenceRecord> Records,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Errors);
