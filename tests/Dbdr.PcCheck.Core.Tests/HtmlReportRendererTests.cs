using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Packaging;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class HtmlReportRendererTests
{
    [Fact]
    public void RendersEvidenceSectionsAndEncodesUntrustedValues()
    {
        var now = DateTimeOffset.Parse("2026-08-10T14:30:00Z", System.Globalization.CultureInfo.InvariantCulture);
        var context = new CollectionContext("case-1", now.AddMinutes(-30), now.AddMinutes(30), now, "test");
        var records = new EvidenceRecord[]
        {
            new(
                "processes",
                "process.snapshot",
                "unit-test",
                now,
                now.AddMinutes(-1),
                new Dictionary<string, string?>
                {
                    ["processId"] = "42",
                    ["parentProcessId"] = "1",
                    ["sessionId"] = "2",
                    ["name"] = "<script>alert(1)</script>",
                    ["executablePath"] = @"%USERPROFILE%\safe.exe",
                }),
            new(
                "game-modules",
                "game.snapshot",
                "unit-test",
                now,
                null,
                new Dictionary<string, string?>
                {
                    ["matchingProcessCount"] = "1",
                    ["matchingProcesses"] = "DeadByDaylight (42)",
                    ["moduleEnumerationSucceededCount"] = "1",
                    ["moduleEnumerationFailedCount"] = "0",
                    ["moduleRecordCount"] = "0",
                }),
        };
        var result = new CollectionRunResult(
            context,
            now.AddSeconds(2),
            [new ModuleResult("test", true, TimeSpan.FromSeconds(1), records, ["<warning>"], [])])
        {
            Findings =
            [
                new EvidenceFinding(
                    "F-001",
                    FindingDisposition.NeedsReview,
                    "Review <this>",
                    "Neutral finding",
                    "test",
                    "process.snapshot"),
            ],
        };

        var html = HtmlReportRenderer.Render(result);

        Assert.Contains("Review-window timeline", html, StringComparison.Ordinal);
        Assert.Contains("Live DBD state", html, StringComparison.Ordinal);
        Assert.Contains("Review queue", html, StringComparison.Ordinal);
        Assert.Contains("Review &lt;this&gt;", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("&lt;warning&gt;", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script>alert(1)</script>", html, StringComparison.Ordinal);
    }
}
