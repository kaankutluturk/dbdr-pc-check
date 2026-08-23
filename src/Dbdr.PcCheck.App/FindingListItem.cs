using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.App;

public sealed record FindingListItem(
    string Id,
    FindingDisposition Disposition,
    string Title,
    string Detail,
    string Module,
    string? RecordKind)
{
    public string DispositionLabel => Disposition switch
    {
        FindingDisposition.NeedsReview => "NEEDS REVIEW",
        FindingDisposition.CoverageGap => "COVERAGE GAP",
        _ => "INFORMATIONAL",
    };

    public string ContextLabel => RecordKind is null ? Module : $"{Module}  ·  {RecordKind}";
}
