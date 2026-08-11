using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class PrefetchExecutionHistorySourceTests
{
    [Fact]
    public void FiltersFileMetadataToExplicitReviewWindow()
    {
        var prefetchDirectory = Path.Combine(Path.GetTempPath(), "DbdrPrefetchTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(prefetchDirectory);

        try
        {
            var now = new DateTimeOffset(2026, 8, 11, 18, 0, 0, TimeSpan.Zero);
            var includedPath = Path.Combine(prefetchDirectory, "INCLUDED.EXE-12345678.pf");
            var excludedPath = Path.Combine(prefetchDirectory, "EXCLUDED.EXE-12345678.pf");
            File.WriteAllBytes(includedPath, [1, 2, 3]);
            File.WriteAllBytes(excludedPath, [4, 5, 6]);
            File.SetLastWriteTimeUtc(includedPath, now.AddMinutes(-30).UtcDateTime);
            File.SetLastWriteTimeUtc(excludedPath, now.AddHours(-3).UtcDateTime);

            var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");
            var source = new PrefetchExecutionHistorySource(new PathRedactor(), prefetchDirectory);

            var result = source.Collect(context, CancellationToken.None);

            Assert.Equal(EvidenceSourceStatus.Available, result.Status);
            var record = Assert.Single(result.Records);
            Assert.Equal("INCLUDED.EXE-12345678.pf", record.Fields["prefetchFile"]);
            Assert.Equal("Prefetch file last-write time; not a parsed run time", record.Fields["timestampBasis"]);
        }
        finally
        {
            Directory.Delete(prefetchDirectory, recursive: true);
        }
    }
}
