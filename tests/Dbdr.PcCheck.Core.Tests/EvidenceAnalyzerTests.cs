using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class EvidenceAnalyzerTests
{
    [Fact]
    public void ProducesNeutralReviewAndCoverageFindings()
    {
        var now = new DateTimeOffset(2026, 8, 11, 18, 0, 0, TimeSpan.Zero);
        var records = new EvidenceRecord[]
        {
            new(
                "game-modules",
                "process.module",
                "unit-test",
                now,
                null,
                new Dictionary<string, string?>
                {
                    ["modulePath"] = @"%USERPROFILE%\AppData\Local\module.dll",
                    ["identityStableDuringInspection"] = "false",
                    ["fileInspectionError"] = null,
                    ["entropyClassification"] = "high",
                    ["entropyBitsPerByte"] = "7.9000",
                    ["authenticodeStatus"] = "unsigned",
                    ["yaraStatus"] = "matched",
                    ["yaraMatchCount"] = "1",
                    ["yaraMatches"] = "baseline:DBDR_Test_Rule",
                }),
            new(
                "execution-history",
                "coverage.source",
                "unit-test",
                now,
                null,
                new Dictionary<string, string?>
                {
                    ["sourceName"] = "Test source",
                    ["status"] = "unavailable",
                    ["detail"] = "Access denied",
                }),
        };
        var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");
        var result = new CollectionRunResult(
            context,
            now,
            [new ModuleResult("test", true, TimeSpan.Zero, records, [], [])]);

        var findings = EvidenceAnalyzer.Analyze(result);

        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("user-writable", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("changed", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("YARA", StringComparison.Ordinal));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("entropy", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.CoverageGap
            && finding.Title.Contains("Test source", StringComparison.Ordinal));
        Assert.DoesNotContain(findings, finding => finding.Title.Contains("cheater", StringComparison.OrdinalIgnoreCase));
    }
}
