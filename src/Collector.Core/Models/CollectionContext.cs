namespace Dbdr.PcCheck.Collector.Core.Models;

public sealed record CollectionContext(
    string CaseId,
    DateTimeOffset ReviewWindowStartUtc,
    DateTimeOffset ReviewWindowEndUtc,
    DateTimeOffset CollectionStartedUtc,
    string CollectorVersion);
