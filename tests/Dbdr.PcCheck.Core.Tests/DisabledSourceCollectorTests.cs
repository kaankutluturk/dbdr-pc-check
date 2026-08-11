using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class DisabledSourceCollectorTests
{
    [Fact]
    public async Task RecordsDisabledSourcesWithoutCollectingEvidence()
    {
        var now = new DateTimeOffset(2026, 8, 11, 18, 0, 0, TimeSpan.Zero);
        var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");
        var collector = new DisabledSourceCollector(["Windows Prefetch", "Windows Prefetch", "BAM"]);

        var result = await collector.CollectAsync(context, null, CancellationToken.None);

        Assert.True(result.Completed);
        Assert.Equal(2, result.Records.Count);
        Assert.All(result.Records, record =>
        {
            Assert.Equal("coverage.source", record.Kind);
            Assert.Equal("disabled", record.Fields["status"]);
            Assert.Equal("0", record.Fields["recordCount"]);
        });
    }
}
