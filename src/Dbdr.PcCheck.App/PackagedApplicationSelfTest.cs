using System.Text;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Packaging;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.App;

internal static class PackagedApplicationSelfTest
{
    private const string ExpectedYaraMatch = "baseline:DBDR_Remote_Process_API_Cluster";
    private const string BundlePassphrase = "DBDR packaged release self-test";

    public static async Task RunAsync(CancellationToken cancellationToken)
    {
        _ = YaraRulePackVerifier.LoadEmbeddedTrustKeys();
        var baselineHashes = YaraFileScanner.CalculateRulesetHashes();
        if (!baselineHashes.TryGetValue("baseline", out var baselineHash) || !IsSha256(baselineHash))
        {
            throw Failure("embedded YARA baseline identity is unavailable");
        }

        var workingDirectory = Path.Combine(
            Path.GetTempPath(),
            "DBDR-PC-Check",
            "self-test",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workingDirectory);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var syntheticPath = Path.Combine(workingDirectory, "synthetic-yara-input.bin");
            var syntheticBytes = Encoding.ASCII.GetBytes(
                "MZ\0OpenProcess\0WriteProcessMemory\0VirtualAllocEx\0CreateRemoteThread\0");
            await File.WriteAllBytesAsync(syntheticPath, syntheticBytes, cancellationToken).ConfigureAwait(false);

            YaraScanEvidence scan;
            using (var scanner = new IsolatedYaraFileScanner(scanTimeout: TimeSpan.FromSeconds(15)))
            {
                scan = await scanner.ScanAsync(syntheticPath, cancellationToken).ConfigureAwait(false);
            }

            if (!string.Equals(scan.Status, "matched", StringComparison.Ordinal)
                || !scan.Matches.Contains(ExpectedYaraMatch, StringComparer.Ordinal)
                || !scan.RulesetHashes.TryGetValue("baseline", out var workerBaselineHash)
                || !string.Equals(workerBaselineHash, baselineHash, StringComparison.Ordinal))
            {
                throw Failure($"isolated YARA worker returned {scan.Status} ({scan.Error ?? "no error"})");
            }

            var result = CreateSyntheticResult(scan);
            result = result with { Findings = EvidenceAnalyzer.Analyze(result) };
            if (!result.Findings.Any(finding =>
                    string.Equals(finding.Title, "YARA rule match on a referenced file", StringComparison.Ordinal)))
            {
                throw Failure("neutral analyzer did not preserve the synthetic YARA review lead");
            }

            var bundlePath = await new EvidenceBundleWriter()
                .WriteEncryptedAsync(result, workingDirectory, BundlePassphrase, cancellationToken)
                .ConfigureAwait(false);
            var reopened = await new EvidenceBundleReader()
                .ReadAsync(bundlePath, BundlePassphrase, cancellationToken)
                .ConfigureAwait(false);
            VerifyRoundTrip(result, reopened);
        }
        finally
        {
            TryDeleteDirectory(workingDirectory);
        }
    }

    private static CollectionRunResult CreateSyntheticResult(YaraScanEvidence scan)
    {
        var collectedAt = DateTimeOffset.UtcNow;
        var fields = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["executablePath"] = @"%TEMP%\synthetic-yara-input.bin",
        };
        scan.AddTo(fields);
        var record = new EvidenceRecord(
            "release-self-test",
            "file.metadata",
            "packaged-self-test",
            collectedAt,
            collectedAt,
            fields);
        var module = new ModuleResult(
            "release-self-test",
            true,
            TimeSpan.Zero,
            [record],
            [],
            []);
        var context = new CollectionContext(
            "release-self-test",
            collectedAt.AddMinutes(-5),
            collectedAt,
            collectedAt,
            typeof(App).Assembly.GetName().Version?.ToString() ?? "unknown");
        return new CollectionRunResult(context, collectedAt.AddMilliseconds(1), [module]);
    }

    private static void VerifyRoundTrip(
        CollectionRunResult expected,
        EvidenceBundleReadResult reopened)
    {
        if (!reopened.Verification.Encrypted
            || !string.Equals(
                reopened.Verification.EvidenceSchemaVersion,
                EvidenceBundleWriter.EvidenceSchemaVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                reopened.Verification.AnalysisProfileVersion,
                EvidenceAnalyzer.AnalysisProfileVersion,
                StringComparison.Ordinal)
            || reopened.Verification.VerifiedEntryCount != 6
            || reopened.Verification.DecompressedBytes <= 0
            || reopened.Result.Context != expected.Context
            || reopened.Result.CompletedUtc != expected.CompletedUtc
            || reopened.Result.Records.Count != 1
            || reopened.Result.Findings.Count != expected.Findings.Count
            || !string.Equals(
                reopened.Result.Records[0].Fields["yaraStatus"],
                "matched",
                StringComparison.Ordinal)
            || !string.Equals(
                reopened.Result.Records[0].Fields["yaraMatches"],
                ExpectedYaraMatch,
                StringComparison.Ordinal))
        {
            throw Failure("encrypted evidence bundle did not survive verified round-trip reopening");
        }
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9'
                or >= 'A' and <= 'F'
                or >= 'a' and <= 'f');

    private static InvalidOperationException Failure(string detail) =>
        new($"Packaged application self-test failed: {detail}.");

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The directory contains synthetic data only; security software can briefly retain it.
        }
    }
}
