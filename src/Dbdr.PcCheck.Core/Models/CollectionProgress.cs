namespace Dbdr.PcCheck.Core.Models;

public sealed record CollectionProgress(
    string Module,
    string Message,
    int? Current = null,
    int? Total = null);
