using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Windows;
using System.Buffers.Binary;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class PrefetchExecutionHistorySourceTests
{
    [Fact]
    public void FiltersParsedRunTimesToExplicitReviewWindow()
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

            var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");
            var parser = new FakePrefetchParser(new Dictionary<string, ParsedPrefetch>(StringComparer.OrdinalIgnoreCase)
            {
                [includedPath] = new("INCLUDED.EXE", 30, 5, [now.AddHours(-3), now.AddMinutes(-30)]),
                [excludedPath] = new("EXCLUDED.EXE", 30, 2, [now.AddHours(-3)]),
            });
            var source = new PrefetchExecutionHistorySource(new PathRedactor(), prefetchDirectory, parser);

            var result = source.Collect(context, CancellationToken.None);

            Assert.Equal(EvidenceSourceStatus.Available, result.Status);
            var record = Assert.Single(result.Records);
            Assert.Equal("INCLUDED.EXE-12345678.pf", record.Fields["prefetchFile"]);
            Assert.Equal("INCLUDED.EXE", record.Fields["executableName"]);
            Assert.Equal("Parsed Prefetch last-run FILETIME", record.Fields["timestampBasis"]);
            Assert.Equal(now.AddMinutes(-30), record.SourceTimestampUtc);
            Assert.Contains("parsed=2", result.Detail ?? string.Empty, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(prefetchDirectory, recursive: true);
        }
    }

    [Fact]
    public void ReportsAllParseFailuresAsUnavailable()
    {
        var prefetchDirectory = Path.Combine(Path.GetTempPath(), "DbdrPrefetchTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(prefetchDirectory);

        try
        {
            var path = Path.Combine(prefetchDirectory, "BROKEN.EXE-12345678.pf");
            File.WriteAllBytes(path, [1, 2, 3]);
            var parser = new ThrowingPrefetchParser();
            var now = new DateTimeOffset(2026, 8, 11, 18, 0, 0, TimeSpan.Zero);
            var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");
            var source = new PrefetchExecutionHistorySource(new PathRedactor(), prefetchDirectory, parser);

            var result = source.Collect(context, CancellationToken.None);

            Assert.Equal(EvidenceSourceStatus.Unavailable, result.Status);
            Assert.Empty(result.Records);
            Assert.Contains("parseFailures=1", result.Detail ?? string.Empty, StringComparison.Ordinal);
            Assert.Contains("BROKEN.EXE-12345678.pf=InvalidDataException", result.Detail ?? string.Empty, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(prefetchDirectory, recursive: true);
        }
    }

    [Fact]
    public void RejectsOversizedDeclaredDecompressionBeforeParserAllocation()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-prefetch-{Guid.NewGuid():N}.pf");
        try
        {
            var header = new byte[8];
            "MAM"u8.CopyTo(header);
            BinaryPrimitives.WriteUInt32LittleEndian(
                header.AsSpan(4, 4),
                BoundedPrefetchParser.MaximumDecompressedFileSizeBytes + 1);
            File.WriteAllBytes(path, header);

            Assert.Throws<InvalidDataException>(() => new BoundedPrefetchParser().Parse(path));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private sealed class FakePrefetchParser(IReadOnlyDictionary<string, ParsedPrefetch> values) : IPrefetchParser
    {
        public ParsedPrefetch Parse(string path) => values[path];
    }

    private sealed class ThrowingPrefetchParser : IPrefetchParser
    {
        public ParsedPrefetch Parse(string path) => throw new InvalidDataException("test");
    }
}
