using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class YaraRulePackVerifierTests
{
    [Fact]
    public void VerifiesVersionedProfileBoundRulePack()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = new DateTimeOffset(2026, 8, 23, 10, 0, 0, TimeSpan.Zero);
        var path = CreatePack(key, now, now.AddDays(30));
        try
        {
            var trustedKeys = new Dictionary<string, string>
            {
                ["test-key-1"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
            };

            var verified = YaraRulePackVerifier.Verify(path, trustedKeys, now);

            Assert.Equal("signed:dbdr-test@1.2.3", verified.RuleSetId);
            Assert.Equal("1.2.3", verified.Manifest.Version);
            Assert.Equal(EvidenceAnalyzer.AnalysisProfileVersion, verified.Manifest.AnalysisProfileVersion);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(verified.Rules)), verified.RulesSha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RejectsTamperingAndUntrustedKeys()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = new DateTimeOffset(2026, 8, 23, 10, 0, 0, TimeSpan.Zero);
        var path = CreatePack(key, now, now.AddDays(30));
        var trustedKeys = new Dictionary<string, string>
        {
            ["test-key-1"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        };
        try
        {
            var untrusted = Assert.Throws<InvalidDataException>(() =>
                YaraRulePackVerifier.Verify(path, new Dictionary<string, string>(), now));
            Assert.Contains("not trusted", untrusted.Message, StringComparison.OrdinalIgnoreCase);

            using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
            {
                archive.GetEntry("rules.yar")!.Delete();
                var replacement = archive.CreateEntry("rules.yar", CompressionLevel.Optimal);
                using var writer = new StreamWriter(replacement.Open(), new UTF8Encoding(false));
                writer.Write("rule Tampered { condition: true }");
            }

            var tampered = Assert.Throws<InvalidDataException>(() =>
                YaraRulePackVerifier.Verify(path, trustedKeys, now));
            Assert.Contains("hash", tampered.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RejectsExpiredPackAndUnexpectedArchiveEntry()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = new DateTimeOffset(2026, 8, 23, 10, 0, 0, TimeSpan.Zero);
        var expiredPath = CreatePack(key, now.AddDays(-10), now.AddDays(-1));
        var trustedKeys = new Dictionary<string, string>
        {
            ["test-key-1"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        };
        try
        {
            var expired = Assert.Throws<InvalidDataException>(() =>
                YaraRulePackVerifier.Verify(expiredPath, trustedKeys, now));
            Assert.Contains("validity", expired.Message, StringComparison.OrdinalIgnoreCase);

            using (var archive = ZipFile.Open(expiredPath, ZipArchiveMode.Update))
            {
                archive.CreateEntry("nested/extra.txt");
            }

            var unexpected = Assert.Throws<InvalidDataException>(() =>
                YaraRulePackVerifier.Verify(expiredPath, trustedKeys, now.AddDays(-2)));
            Assert.Contains("only", unexpected.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(expiredPath);
        }
    }

    [Fact]
    public void RejectsSignatureTampering()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = new DateTimeOffset(2026, 8, 23, 10, 0, 0, TimeSpan.Zero);
        var path = CreatePack(key, now, now.AddDays(30));
        var trustedKeys = new Dictionary<string, string>
        {
            ["test-key-1"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        };
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
            {
                var entry = archive.GetEntry("signature.p1363")!;
                byte[] signature;
                using (var input = entry.Open())
                using (var output = new MemoryStream())
                {
                    input.CopyTo(output);
                    signature = output.ToArray();
                }

                entry.Delete();
                signature[0] ^= 0x80;
                WriteEntry(archive, "signature.p1363", signature);
            }

            var invalid = Assert.Throws<InvalidDataException>(() =>
                YaraRulePackVerifier.Verify(path, trustedKeys, now));
            Assert.Contains("signature", invalid.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RejectsWrongAnalysisProfileAndRuleIncludes()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = new DateTimeOffset(2026, 8, 23, 10, 0, 0, TimeSpan.Zero);
        var wrongProfilePath = CreatePack(key, now, now.AddDays(30), analysisProfileVersion: "0.4.0");
        var includePath = CreatePack(
            key,
            now,
            now.AddDays(30),
            rulesText: "/* header */ include \"other.yar\"");
        var trustedKeys = new Dictionary<string, string>
        {
            ["test-key-1"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        };
        try
        {
            var wrongProfile = Assert.Throws<InvalidDataException>(() =>
                YaraRulePackVerifier.Verify(wrongProfilePath, trustedKeys, now));
            Assert.Contains("analysis profile", wrongProfile.Message, StringComparison.OrdinalIgnoreCase);

            var include = Assert.Throws<InvalidDataException>(() =>
                YaraRulePackVerifier.Verify(includePath, trustedKeys, now));
            Assert.Contains("include", include.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(wrongProfilePath);
            File.Delete(includePath);
        }
    }

    private static string CreatePack(
        ECDsa key,
        DateTimeOffset createdUtc,
        DateTimeOffset expiresUtc,
        string? analysisProfileVersion = null,
        string? rulesText = null)
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-rules-{Guid.NewGuid():N}.dbdrrules");
        var rules = Encoding.UTF8.GetBytes(
            rulesText ?? "rule DBDR_Signed_Test { strings: $a = \"signed-test\" condition: $a }");
        var manifest = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = YaraRulePackVerifier.SchemaVersion,
            packId = "dbdr-test",
            version = "1.2.3",
            keyId = "test-key-1",
            createdUtc,
            expiresUtc,
            analysisProfileVersion = analysisProfileVersion ?? EvidenceAnalyzer.AnalysisProfileVersion,
            rulesSha256 = Convert.ToHexString(SHA256.HashData(rules)),
        });
        var payload = YaraRulePackVerifier.CreateSignedPayload(manifest, rules);
        var signature = key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        WriteEntry(archive, "manifest.json", manifest);
        WriteEntry(archive, "rules.yar", rules);
        WriteEntry(archive, "signature.p1363", signature);
        return path;
    }

    private static void WriteEntry(ZipArchive archive, string name, byte[] content)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var stream = entry.Open();
        stream.Write(content);
    }
}
