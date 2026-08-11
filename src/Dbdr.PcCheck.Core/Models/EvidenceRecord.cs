namespace Dbdr.PcCheck.Core.Models;

public sealed record EvidenceRecord(
    string Module,
    string Kind,
    string Source,
    DateTimeOffset CollectedAtUtc,
    DateTimeOffset? SourceTimestampUtc,
    IReadOnlyDictionary<string, string?> Fields);
