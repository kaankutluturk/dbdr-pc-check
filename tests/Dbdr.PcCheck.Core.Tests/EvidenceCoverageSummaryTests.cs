using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class EvidenceCoverageSummaryTests
{
    [Fact]
    public void SummarizesModulesSourcesAndFindingDispositions()
    {
        var now = new DateTimeOffset(2026, 8, 23, 10, 0, 0, TimeSpan.Zero);
        var module = new ModuleResult(
            "execution-history",
            true,
            TimeSpan.Zero,
            [
                Source("Prefetch", "available", "parsed=10; parseFailures=0"),
                Source("USN", "available", "parsed=20; parseFailures=1; enumerationCapped=true"),
                Source("BAM", "unavailable", "Access denied"),
                Source("BAM", "unavailable", "Duplicate normalized source status"),
            ],
            [],
            []);
        var result = new CollectionRunResult(
            new CollectionContext("case-summary", now.AddHours(-2), now, now, "test"),
            now,
            [module, new ModuleResult("devices", false, TimeSpan.Zero, [], [], [])])
        {
            Findings =
            [
                Finding("F-001", FindingDisposition.Informational),
                Finding("F-002", FindingDisposition.NeedsReview),
                Finding("F-003", FindingDisposition.CoverageGap),
            ],
        };

        var summary = EvidenceCoverageSummary.Create(result);

        Assert.Equal(4, summary.RecordCount);
        Assert.Equal(1, summary.InformationalFindingCount);
        Assert.Equal(1, summary.ReviewFindingCount);
        Assert.Equal(1, summary.CoverageGapCount);
        Assert.Equal(2, summary.ModuleCount);
        Assert.Equal(1, summary.CompletedModuleCount);
        Assert.Equal(3, summary.SourceCount);
        Assert.Equal(2, summary.AvailableSourceCount);
        Assert.Equal(1, summary.LimitedSourceCount);
        Assert.Equal(1, summary.UnavailableSourceCount);

        EvidenceRecord Source(string name, string status, string detail) => new(
            "execution-history",
            "coverage.source",
            "unit-test",
            now,
            null,
            new Dictionary<string, string?>
            {
                ["sourceName"] = name,
                ["status"] = status,
                ["detail"] = detail,
            });

        static EvidenceFinding Finding(string id, FindingDisposition disposition) =>
            new(id, disposition, "Title", "Detail", "test", null);
    }
}
