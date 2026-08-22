using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class EvidenceSearchEngineTests
{
    [Fact]
    public void SearchesWithinAnIndividualSource()
    {
        var now = new DateTimeOffset(2026, 8, 22, 9, 0, 0, TimeSpan.Zero);
        var records = new EvidenceRecord[]
        {
            New("execution-history", "execution.bam", "BAM", now, "executablePath", @"%USERPROFILE%\Tools\example.exe"),
            New("execution-history", "execution.prefetch", "Prefetch", now.AddMinutes(-1), "prefetchFile", "OTHER.EXE.pf"),
            New("devices", "device.snapshot", "PnP", now.AddMinutes(-2), "name", "Example USB device"),
        };

        var results = EvidenceSearchEngine.Search(records, "example", "bam");

        var result = Assert.Single(results);
        Assert.Equal("execution.bam", result.Kind);
    }

    private static EvidenceRecord New(
        string module,
        string kind,
        string source,
        DateTimeOffset timestamp,
        string field,
        string value) =>
        new(module, kind, source, timestamp, timestamp, new Dictionary<string, string?> { [field] = value });
}
