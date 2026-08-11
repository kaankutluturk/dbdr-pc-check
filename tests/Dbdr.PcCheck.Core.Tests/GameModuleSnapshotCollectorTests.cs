using System.ComponentModel;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class GameModuleSnapshotCollectorTests
{
    private static readonly DateTimeOffset CapturedAtUtc = new(2026, 8, 10, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task ReportsBlockedEnumerationAsCoverageGap()
    {
        var collector = new GameModuleSnapshotCollector(
            SnapshotProvider(),
            new ThrowingModuleEnumerator(),
            new FakeFileInspector(),
            new PathRedactor(@"C:\Users\Alice"));

        var result = await collector.CollectAsync(Context(), null, CancellationToken.None);

        Assert.True(result.Completed);
        var warning = Assert.Single(result.Warnings);
        Assert.Contains("Win32Exception", warning);

        var status = Assert.Single(result.Records.Where(record => record.Kind == "game.snapshot"));
        Assert.Equal("game.snapshot", status.Kind);
        Assert.Equal("1", status.Fields["matchingProcessCount"]);
        Assert.Equal("0", status.Fields["moduleEnumerationSucceededCount"]);
        Assert.Equal("1", status.Fields["moduleEnumerationFailedCount"]);
        Assert.Equal("0", status.Fields["moduleRecordCount"]);
        var coverage = Assert.Single(result.Records.Where(record => record.Kind == "coverage.source"));
        Assert.Equal("unavailable", coverage.Fields["status"]);
    }

    [Fact]
    public async Task RedactsModulePathAndIncludesFileEvidence()
    {
        var collector = new GameModuleSnapshotCollector(
            SnapshotProvider(),
            new SuccessfulModuleEnumerator(),
            new FakeFileInspector(),
            new PathRedactor(@"C:\Users\Alice"));

        var result = await collector.CollectAsync(Context(), null, CancellationToken.None);

        Assert.Empty(result.Warnings);
        var module = Assert.Single(result.Records.Where(record => record.Kind == "process.module"));
        Assert.Equal(@"%USERPROFILE%\test.dll", module.Fields["modulePath"]);
        Assert.Equal("ABC123", module.Fields["sha256"]);
        Assert.Equal("Valid", module.Fields["authenticodeStatus"]);

        var status = Assert.Single(result.Records.Where(record => record.Kind == "game.snapshot"));
        Assert.Equal("1", status.Fields["moduleEnumerationSucceededCount"]);
        Assert.Equal("0", status.Fields["moduleEnumerationFailedCount"]);
        Assert.Equal("1", status.Fields["moduleRecordCount"]);
    }

    private static CollectionContext Context() => new(
        "case-1",
        CapturedAtUtc.AddHours(-2),
        CapturedAtUtc,
        CapturedAtUtc,
        "test");

    private static ILiveProcessSnapshotProvider SnapshotProvider() => new FakeSnapshotProvider(
        new LiveProcessSnapshot(
            CapturedAtUtc,
            [new LiveProcessInfo(
                42,
                1,
                "DeadByDaylight-Win64-Shipping.exe",
                @"C:\Games\DBD.exe",
                CapturedAtUtc.AddMinutes(-30),
                1)]));

    private sealed class FakeSnapshotProvider(LiveProcessSnapshot snapshot) : ILiveProcessSnapshotProvider
    {
        public Task<LiveProcessSnapshot> GetOrCaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(snapshot);
    }

    private sealed class ThrowingModuleEnumerator : IGameModuleEnumerator
    {
        public IReadOnlyList<LoadedModuleInfo> Enumerate(uint processId) =>
            throw new Win32Exception("Expected test failure");
    }

    private sealed class SuccessfulModuleEnumerator : IGameModuleEnumerator
    {
        public IReadOnlyList<LoadedModuleInfo> Enumerate(uint processId) =>
            [new LoadedModuleInfo("test.dll", @"C:\Users\Alice\test.dll")];
    }

    private sealed class FakeFileInspector : IExecutableFileInspector
    {
        public Task<ExecutableFileEvidence> InspectAsync(string path, CancellationToken cancellationToken) =>
            Task.FromResult(new ExecutableFileEvidence(
                "123",
                "2026-08-10T09:00:00.0000000Z",
                "2026-08-10T09:30:00.0000000Z",
                "ABC123",
                "Valid",
                "Example Company",
                "Example Product",
                "test.dll",
                "true",
                null));
    }
}
