namespace Dbdr.PcCheck.Collector.Core.Models;

public sealed record EvidenceRecord(
    string Module,
    string Kind,
    string Source,
    DateTimeOffset ObservedAtUtc,
    IReadOnlyDictionary<string, string?> Fields);
