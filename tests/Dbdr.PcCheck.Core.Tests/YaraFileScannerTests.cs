using System.Text;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class YaraFileScannerTests
{
    [Fact]
    public async Task EmbeddedBaselineReportsRuleIdentifierWithoutMatchedBytes()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-yara-test-{Guid.NewGuid():N}.bin");
        try
        {
            var sample = Encoding.ASCII.GetBytes(
                "MZ\0\0OpenProcess\0WriteProcessMemory\0VirtualAllocEx\0CreateRemoteThread\0");
            await File.WriteAllBytesAsync(path, sample);
            using var scanner = new YaraFileScanner();

            var evidence = await scanner.ScanAsync(path, CancellationToken.None);

            Assert.Equal("matched", evidence.Status);
            Assert.Contains(
                evidence.Matches,
                match => match == "baseline:DBDR_Remote_Process_API_Cluster");
            Assert.Single(evidence.RulesetHashes);
            Assert.Null(evidence.Error);
            var fields = new Dictionary<string, string?>();
            evidence.AddTo(fields);
            Assert.Equal("baseline=embedded", fields["yaraRulesetTrust"]);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task CustomRuleIncludesAreRejectedBeforeCompilation()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-yara-rules-{Guid.NewGuid():N}.yar");
        try
        {
            await File.WriteAllTextAsync(path, "include \"another-rule.yar\"");

            var exception = Assert.Throws<InvalidDataException>(() => new YaraFileScanner(path));

            Assert.Contains("include", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task CustomRuleIncludesAfterLeadingCommentAreRejectedBeforeCompilation()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-yara-rules-{Guid.NewGuid():N}.yar");
        try
        {
            await File.WriteAllTextAsync(path, "/* misleading header */ include \"another-rule.yar\"");

            var exception = Assert.Throws<InvalidDataException>(() => YaraFileScanner.ValidateCustomRulePath(path));

            Assert.Contains("include", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void EmbeddedRulesetHashIsAvailableWithoutStartingNativeScanner()
    {
        var hashes = YaraFileScanner.CalculateRulesetHashes();

        var hash = Assert.Single(hashes);
        Assert.Equal("baseline", hash.Key);
        Assert.Equal(64, hash.Value.Length);
        Assert.All(hash.Value, character => Assert.True(Uri.IsHexDigit(character)));
    }

    [Fact]
    public async Task CustomRulePathRejectsUnsupportedExtensions()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-yara-rules-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(path, "rule DBDR_Test { condition: true }");

            var exception = Assert.Throws<InvalidDataException>(() => YaraFileScanner.ValidateCustomRulePath(path));

            Assert.Contains(".dbdrrules", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void RulesetEvidenceDistinguishesSignedAndUnverifiedRules()
    {
        var evidence = new YaraScanEvidence(
            "no-match",
            [],
            new Dictionary<string, string>
            {
                ["custom"] = new string('A', 64),
                ["signed:dbdr-production@1.2.3"] = new string('B', 64),
            },
            null);
        var fields = new Dictionary<string, string?>();

        evidence.AddTo(fields);

        Assert.Equal(
            "custom=operator-supplied-unverified, signed:dbdr-production@1.2.3=ecdsa-p256-sha256-verified",
            fields["yaraRulesetTrust"]);
    }
}
