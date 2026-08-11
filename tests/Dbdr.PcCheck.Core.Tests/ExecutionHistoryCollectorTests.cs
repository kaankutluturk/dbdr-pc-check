using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class ExecutionHistoryCollectorTests
{
    [Fact]
    public async Task PreservesSuccessfulSourceWhenAnotherSourceFails()
    {
        var now = new DateTimeOffset(2026, 8, 11, 18, 0, 0, TimeSpan.Zero);
        var collector = new ExecutionHistoryCollector(
        [
            new SuccessfulSource(now),
            new ThrowingSource(),
        ]);
        var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");

        var result = await collector.CollectAsync(context, null, CancellationToken.None);

        Assert.True(result.Completed);
        Assert.Contains(result.Records, record => record.Kind == "execution.test");
        var coverage = result.Records.Where(record => record.Kind == "coverage.source").ToArray();
        Assert.Equal(2, coverage.Length);
        Assert.Contains(coverage, record => record.Fields["status"] == "available");
        Assert.Contains(coverage, record => record.Fields["status"] == "unavailable");
        Assert.Single(result.Warnings);
    }

    private sealed class SuccessfulSource(DateTimeOffset timestamp) : IExecutionHistorySource
    {
        public string Name => "successful";

        public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken) => new(
            Name,
            EvidenceSourceStatus.Available,
            [new EvidenceRecord(
                "execution-history",
                "execution.test",
                "unit-test",
                timestamp,
                timestamp,
                new Dictionary<string, string?>())]);
    }

    private sealed class ThrowingSource : IExecutionHistorySource
    {
        public string Name => "throwing";

        public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken) =>
            throw new UnauthorizedAccessException("Expected test failure");
    }
}
