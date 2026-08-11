namespace Dbdr.PcCheck.Core.Models;

public enum EvidenceSourceStatus
{
    Available,
    Empty,
    Unavailable,
    Disabled,
    NotSupported,
}

public sealed record EvidenceSourceResult(
    string SourceName,
    EvidenceSourceStatus Status,
    IReadOnlyList<EvidenceRecord> Records,
    string? Detail = null);
