using System.IO.Compression;
using System.Text;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Packaging;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class EvidenceBundleReaderTests
{
    [Fact]
    public async Task ReopensVerifiedBundleIntoNormalizedResult()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var expected = CreateResult();
            var path = await new EvidenceBundleWriter().WriteAsync(expected, directory, CancellationToken.None);

            var reopened = await new EvidenceBundleReader().ReadAsync(path, CancellationToken.None);

            Assert.False(reopened.Verification.Encrypted);
            Assert.Equal(EvidenceBundleWriter.EvidenceSchemaVersion, reopened.Verification.EvidenceSchemaVersion);
            Assert.Equal(6, reopened.Verification.VerifiedEntryCount);
            Assert.True(reopened.Verification.DecompressedBytes > 0);
            Assert.Equal(expected.Context, reopened.Result.Context);
            Assert.Equal(expected.CompletedUtc, reopened.Result.CompletedUtc);
            var module = Assert.Single(reopened.Result.Modules);
            Assert.Equal("test", module.Module);
            Assert.True(module.Completed);
            var record = Assert.Single(module.Records);
            Assert.Equal("test.record", record.Kind);
            Assert.Equal("safe", record.Fields["value"]);
            Assert.Equal(expected.Findings, reopened.Result.Findings);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RejectsContentModifiedAfterManifestCreation()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var path = await new EvidenceBundleWriter().WriteAsync(CreateResult(), directory, CancellationToken.None);
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
            {
                archive.GetEntry("evidence.json")!.Delete();
                var replacement = archive.CreateEntry("evidence.json");
                await using var stream = replacement.Open();
                await stream.WriteAsync(Encoding.UTF8.GetBytes("[]"));
            }

            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => new EvidenceBundleReader().ReadAsync(path, CancellationToken.None));

            Assert.Contains("failed SHA-256 verification", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RejectsNestedArchiveEntryBeforeExtraction()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var path = Path.Combine(directory, "unsafe.zip");
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                archive.CreateEntry("../case.json");
            }

            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => new EvidenceBundleReader().ReadAsync(path, CancellationToken.None));

            Assert.Contains("unsafe archive entry", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task WritesAndReopensAuthenticatedEncryptedBundle()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            const string passphrase = "correct horse battery staple";
            var path = await new EvidenceBundleWriter().WriteEncryptedAsync(
                CreateResult(),
                directory,
                passphrase,
                CancellationToken.None);

            Assert.Equal(".dbdr", Path.GetExtension(path));
            var missingPassphrase = await Assert.ThrowsAsync<InvalidDataException>(
                () => new EvidenceBundleReader().ReadAsync(path, CancellationToken.None));
            Assert.Contains("requires its case passphrase", missingPassphrase.Message, StringComparison.Ordinal);

            var reopened = await new EvidenceBundleReader().ReadAsync(path, passphrase, CancellationToken.None);

            Assert.True(reopened.Verification.Encrypted);
            Assert.Equal("case-verified", reopened.Result.Context.CaseId);
            Assert.Single(reopened.Result.Records);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RejectsWrongPassphraseOrModifiedCiphertext()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            const string passphrase = "correct horse battery staple";
            var path = await new EvidenceBundleWriter().WriteEncryptedAsync(
                CreateResult(),
                directory,
                passphrase,
                CancellationToken.None);

            var wrongPassphrase = await Assert.ThrowsAsync<InvalidDataException>(
                () => new EvidenceBundleReader().ReadAsync(path, "incorrect passphrase value", CancellationToken.None));
            Assert.Contains("incorrect or the encrypted bundle was modified", wrongPassphrase.Message, StringComparison.Ordinal);

            var bytes = await File.ReadAllBytesAsync(path);
            bytes[^32] ^= 0x5A;
            await File.WriteAllBytesAsync(path, bytes);
            var modified = await Assert.ThrowsAsync<InvalidDataException>(
                () => new EvidenceBundleReader().ReadAsync(path, passphrase, CancellationToken.None));
            Assert.Contains("incorrect or the encrypted bundle was modified", modified.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static CollectionRunResult CreateResult()
    {
        var now = new DateTimeOffset(2026, 8, 23, 8, 0, 0, TimeSpan.Zero);
        var context = new CollectionContext("case-verified", now.AddHours(-2), now, now, "test-collector");
        var record = new EvidenceRecord(
            "test",
            "test.record",
            "unit-test",
            now,
            now.AddMinutes(-1),
            new Dictionary<string, string?> { ["value"] = "safe" });
        return new CollectionRunResult(
            context,
            now.AddSeconds(2),
            [new ModuleResult("test", true, TimeSpan.FromMilliseconds(5), [record], ["warning"], [])])
        {
            Findings =
            [
                new EvidenceFinding(
                    "F-001",
                    FindingDisposition.Informational,
                    "Verified finding",
                    "Context only",
                    "test",
                    "test.record"),
            ],
        };
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "DbdrPcCheckTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
