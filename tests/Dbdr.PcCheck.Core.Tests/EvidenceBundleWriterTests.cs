using System.IO.Compression;
using System.Security.Cryptography;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Packaging;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class EvidenceBundleWriterTests
{
    [Fact]
    public async Task WritesExpectedEntriesAndValidManifest()
    {
        var outputDirectory = Path.Combine(Path.GetTempPath(), "DbdrPcCheckTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputDirectory);

        try
        {
            var now = DateTimeOffset.UtcNow;
            var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");
            var record = new EvidenceRecord(
                "test",
                "test.record",
                "unit-test",
                now,
                new Dictionary<string, string?> { ["value"] = "safe" });
            var result = new CollectionRunResult(
                context,
                now,
                [new ModuleResult("test", true, TimeSpan.FromMilliseconds(1), [record], [], [])]);

            var bundlePath = await new EvidenceBundleWriter().WriteAsync(result, outputDirectory, CancellationToken.None);

            using var archive = ZipFile.OpenRead(bundlePath);
            var entries = archive.Entries.Select(entry => entry.FullName).Order(StringComparer.Ordinal).ToArray();
            Assert.Equal(
                ["case.json", "collection-log.json", "evidence.json", "manifest.sha256", "privacy.txt", "report.html"],
                entries);

            var manifestEntry = Assert.Single(archive.Entries, entry => entry.FullName == "manifest.sha256");
            using var reader = new StreamReader(manifestEntry.Open());
            var manifestLines = (await reader.ReadToEndAsync()).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(5, manifestLines.Length);

            foreach (var line in manifestLines)
            {
                var components = line.Split("  ", 2, StringSplitOptions.None);
                Assert.Equal(2, components.Length);
                var entry = Assert.Single(archive.Entries, candidate => candidate.FullName == components[1]);
                using var entryStream = entry.Open();
                var actualHash = Convert.ToHexString(await SHA256.HashDataAsync(entryStream));
                Assert.Equal(components[0], actualHash);
            }
        }
        finally
        {
            if (Directory.Exists(outputDirectory))
            {
                Directory.Delete(outputDirectory, recursive: true);
            }
        }
    }
}
