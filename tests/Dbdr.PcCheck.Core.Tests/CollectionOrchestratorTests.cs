using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class CollectionOrchestratorTests
{
    [Fact]
    public async Task ContinuesAfterModuleFailure()
    {
        var context = new CollectionContext("case-1", DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, "test");
        var orchestrator = new CollectionOrchestrator([new ThrowingCollector(), new SuccessfulCollector()]);

        var result = await orchestrator.RunAsync(context, null, CancellationToken.None);

        Assert.Equal(2, result.Modules.Count);
        Assert.False(result.Modules[0].Completed);
        Assert.True(result.Modules[1].Completed);
        Assert.Single(result.Modules[1].Records);
    }

    private sealed class ThrowingCollector : IEvidenceCollector
    {
        public string Name => "throwing";

        public Task<ModuleResult> CollectAsync(CollectionContext context, IProgress<CollectionProgress>? progress, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Expected test failure");
    }

    private sealed class SuccessfulCollector : IEvidenceCollector
    {
        public string Name => "successful";

        public Task<ModuleResult> CollectAsync(CollectionContext context, IProgress<CollectionProgress>? progress, CancellationToken cancellationToken)
        {
            var record = new EvidenceRecord(
                Name,
                "test.record",
                "test",
                DateTimeOffset.UtcNow,
                null,
                new Dictionary<string, string?>());
            return Task.FromResult(new ModuleResult(Name, true, TimeSpan.Zero, [record], [], []));
        }
    }
}
