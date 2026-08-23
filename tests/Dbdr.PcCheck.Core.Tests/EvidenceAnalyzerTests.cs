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
                    ["yaraMatchesTruncated"] = "true",
                    ["peStatus"] = "valid",
                    ["peWritableExecutableSectionCount"] = "1",
                    ["peSuspiciousSectionNames"] = ".vmp0",
                    ["peImportRiskClusters"] = "remote-process",
                    ["peOverlaySizeBytes"] = "1048576",
                    ["peOverlayEntropyBitsPerByte"] = "7.9900",
                    ["peOverlayEntropyClassification"] = "high",
                    ["peCertificateTablePresent"] = "true",
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
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.Informational
            && finding.Title.Contains("unsigned", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("writable", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("import", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("packed", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("overlay", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("certificate table", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.CoverageGap
            && finding.Title.Contains("Test source", StringComparison.Ordinal));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.CoverageGap
            && finding.Title.Contains("YARA match reporting cap", StringComparison.Ordinal));
        Assert.DoesNotContain(findings, finding => finding.Title.Contains("cheater", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SecurityPostureCreatesContextNotVerdict()
    {
        var now = new DateTimeOffset(2026, 8, 22, 18, 0, 0, TimeSpan.Zero);
        var record = new EvidenceRecord(
            "system",
            "system.snapshot",
            "unit-test",
            now,
            null,
            new Dictionary<string, string?>
            {
                ["securityServicesConfigured"] = "memory-integrity",
                ["securityServicesRunning"] = string.Empty,
                ["vulnerableDriverBlocklistRegistryEnabled"] = "false",
                ["secureBootEnabled"] = "false",
            });
        var result = new CollectionRunResult(
            new CollectionContext("case-1", now.AddHours(-2), now, now, "test"),
            now,
            [new ModuleResult("system", true, TimeSpan.Zero, [record], [], [])]);

        var findings = EvidenceAnalyzer.Analyze(result);

        Assert.Equal(3, findings.Count(finding => finding.Disposition == FindingDisposition.Informational));
        Assert.DoesNotContain(findings, finding => finding.Disposition == FindingDisposition.NeedsReview);
    }

    [Fact]
    public void CorrelatesGameParentAndPersistenceWithoutCreatingVerdict()
    {
        var now = new DateTimeOffset(2026, 8, 22, 18, 0, 0, TimeSpan.Zero);
        var records = new EvidenceRecord[]
        {
            Record("processes", "process.snapshot", new Dictionary<string, string?>
            {
                ["processId"] = "100",
                ["parentProcessId"] = "50",
                ["name"] = "DeadByDaylight-Win64-Shipping.exe",
            }),
            Record("processes", "process.snapshot", new Dictionary<string, string?>
            {
                ["processId"] = "50",
                ["parentProcessId"] = "1",
                ["name"] = "launcher.exe",
            }),
            Record("process-files", "file.metadata", new Dictionary<string, string?>
            {
                ["processIds"] = "50",
                ["executablePath"] = @"%USERPROFILE%\AppData\Local\launcher.exe",
                ["authenticodeStatus"] = "unsigned",
                ["peImportRiskClusters"] = "remote-process",
            }),
            Record("game-modules", "process.module", new Dictionary<string, string?>
            {
                ["processId"] = "100",
                ["modulePath"] = @"%USERPROFILE%\AppData\Local\shared.dll",
                ["sha256"] = "ABC123",
                ["authenticodeStatus"] = "unsigned",
                ["peImportFingerprintSha256"] = "IMPORT-FP",
                ["peImportRiskClusters"] = "remote-process",
            }),
            Record("persistence", "persistence.binary", new Dictionary<string, string?>
            {
                ["executablePath"] = @"%USERPROFILE%\AppData\Local\shared.dll",
                ["sha256"] = "ABC123",
                ["authenticodeStatus"] = "unsigned",
                ["peImportFingerprintSha256"] = "IMPORT-FP",
            }),
            Record("persistence", "persistence.binary", new Dictionary<string, string?>
            {
                ["executablePath"] = @"%USERPROFILE%\AppData\Local\related.dll",
                ["sha256"] = "DEF456",
                ["authenticodeStatus"] = "unsigned",
                ["peImportFingerprintSha256"] = "IMPORT-FP",
            }),
        };
        var result = new CollectionRunResult(
            new CollectionContext("case-1", now.AddHours(-2), now, now, "test"),
            now,
            [new ModuleResult("test", true, TimeSpan.Zero, records, [], [])]);

        var findings = EvidenceAnalyzer.Analyze(result);

        Assert.Contains(findings, finding => finding.Module == "correlation"
            && finding.Title.Contains("parent", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Module == "correlation"
            && finding.Title.Contains("persistence", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Module == "correlation"
            && finding.Title.Contains("import profile", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(findings, finding => finding.Title.Contains("verdict", StringComparison.OrdinalIgnoreCase));

        EvidenceRecord Record(string module, string kind, IReadOnlyDictionary<string, string?> fields) =>
            new(module, kind, "unit-test", now, null, fields);
    }

    [Fact]
    public void CreatedAndDeletedUsnSequenceIsAReviewLead()
    {
        var now = new DateTimeOffset(2026, 8, 22, 18, 0, 0, TimeSpan.Zero);
        var records = new EvidenceRecord[]
        {
            new(
                "execution-history",
                "execution.usn_executable_change",
                "unit-test",
                now,
                now.AddMinutes(-10),
                new Dictionary<string, string?>
                {
                    ["fileName"] = "temporary-loader.exe",
                    ["reasons"] = "file-delete",
                    ["sequence"] = "created-and-deleted",
                }),
            new(
                "execution-history",
                "execution.prefetch",
                "unit-test",
                now,
                now.AddMinutes(-11),
                new Dictionary<string, string?>
                {
                    ["executableName"] = "TEMPORARY-LOADER.EXE",
                }),
        };
        var result = new CollectionRunResult(
            new CollectionContext("case-1", now.AddHours(-2), now, now, "test"),
            now,
            [new ModuleResult("execution-history", true, TimeSpan.Zero, records, [], [])]);

        var findings = EvidenceAnalyzer.Analyze(result);

        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.NeedsReview
            && finding.Title.Contains("created and deleted", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Module == "correlation"
            && finding.Title.Contains("execution artifact", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PartialSourceCapsAndParseFailuresAreCoverageGaps()
    {
        var now = new DateTimeOffset(2026, 8, 22, 18, 0, 0, TimeSpan.Zero);
        var record = new EvidenceRecord(
            "execution-history",
            "coverage.source",
            "unit-test",
            now,
            null,
            new Dictionary<string, string?>
            {
                ["sourceName"] = "Prefetch",
                ["status"] = "available",
                ["detail"] = "parsed=10; parseFailures=2; enumerationCapped=true",
            });
        var result = new CollectionRunResult(
            new CollectionContext("case-1", now.AddHours(-2), now, now, "test"),
            now,
            [new ModuleResult("execution-history", true, TimeSpan.Zero, [record], [], [])]);

        var findings = EvidenceAnalyzer.Analyze(result);

        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.CoverageGap
            && finding.Title.Contains("cap", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Disposition == FindingDisposition.CoverageGap
            && finding.Title.Contains("parse", StringComparison.OrdinalIgnoreCase));
    }
}
