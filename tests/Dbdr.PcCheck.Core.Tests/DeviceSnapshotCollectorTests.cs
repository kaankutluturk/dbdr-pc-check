using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class DeviceSnapshotCollectorTests
{
    [Fact]
    public async Task ReportsUnavailableCoverageWhenProviderCannotBeRead()
    {
        var now = new DateTimeOffset(2026, 8, 11, 18, 0, 0, TimeSpan.Zero);
        var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");
        var collector = new DeviceSnapshotCollector(new UnavailableProvider());

        var result = await collector.CollectAsync(context, null, CancellationToken.None);

        Assert.True(result.Completed);
        var coverage = Assert.Single(result.Records);
        Assert.Equal("coverage.source", coverage.Kind);
        Assert.Equal("unavailable", coverage.Fields["status"]);
        Assert.Single(result.Warnings);
    }

    private sealed class UnavailableProvider : IDeviceSnapshotProvider
    {
        public IReadOnlyList<DeviceSnapshotInfo> Capture(CancellationToken cancellationToken) =>
            throw new UnauthorizedAccessException("Expected test failure");
    }
}
