namespace Dbdr.PcCheck.Core.Models;

public enum FindingDisposition
{
    Informational,
    NeedsReview,
    CoverageGap,
}

public sealed record EvidenceFinding(
    string Id,
    FindingDisposition Disposition,
    string Title,
    string Detail,
    string Module,
    string? RecordKind);
