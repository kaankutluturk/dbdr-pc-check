using System.Buffers.Binary;
using System.Globalization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed record ParsedPrefetch(
    string ExecutableName,
    int Version,
    int RunCount,
    IReadOnlyList<DateTimeOffset> LastRunTimes);

public interface IPrefetchParser
{
    ParsedPrefetch Parse(string path);
}

public sealed class BoundedPrefetchParser : IPrefetchParser
{
    public const long MaximumCompressedFileSizeBytes = 16L * 1024 * 1024;
    public const uint MaximumDecompressedFileSizeBytes = 64U * 1024 * 1024;

    public ParsedPrefetch Parse(string path)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (!file.Exists)
        {
            throw new FileNotFoundException("The Prefetch file no longer exists.", path);
        }

        if (file.Length < 8)
        {
            throw new InvalidDataException("The Prefetch file is shorter than its fixed header.");
        }

        if (file.Length > MaximumCompressedFileSizeBytes)
        {
            throw new InvalidDataException("The Prefetch file exceeds the 16 MiB parser limit.");
        }

        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            4096,
            FileOptions.RandomAccess);
        Span<byte> header = stackalloc byte[8];
        stream.ReadExactly(header);

        if (header[0] == (byte)'M' && header[1] == (byte)'A' && header[2] == (byte)'M')
        {
            var decompressedSize = BinaryPrimitives.ReadUInt32LittleEndian(header[4..]);
            if (decompressedSize is 0 or > MaximumDecompressedFileSizeBytes)
            {
                throw new InvalidDataException("The declared Prefetch decompressed size is outside the parser limits.");
            }
        }

        stream.Position = 0;
        try
        {
            var parsed = Prefetch.PrefetchFile.Open(stream, file.Name);
            if (parsed.ParsingError)
            {
                throw new InvalidDataException("The Prefetch parser reported an incomplete result.");
            }

            return new ParsedPrefetch(
                parsed.Header.ExecutableFilename,
                (int)parsed.Header.Version,
                parsed.RunCount,
                parsed.LastRunTimes
                    .Where(timestamp => timestamp != DateTimeOffset.MinValue)
                    .Distinct()
                    .OrderBy(timestamp => timestamp)
                    .ToArray());
        }
        catch (Exception exception) when (exception is not OperationCanceledException
            and not OutOfMemoryException
            and not StackOverflowException)
        {
            throw new InvalidDataException("The Prefetch artifact could not be parsed safely.", exception);
        }
    }
}

public sealed class PrefetchExecutionHistorySource : IExecutionHistorySource
{
    public const int MaximumPrefetchFiles = 4096;
    private readonly PathRedactor _redactor;
    private readonly string _prefetchDirectory;
    private readonly IPrefetchParser _parser;

    public PrefetchExecutionHistorySource(
        PathRedactor redactor,
        string? prefetchDirectory = null,
        IPrefetchParser? parser = null)
    {
        _redactor = redactor;
        _prefetchDirectory = prefetchDirectory
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        _parser = parser ?? new BoundedPrefetchParser();
    }

    public string Name => "Windows Prefetch";

    public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(_prefetchDirectory))
        {
            return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], "Prefetch directory was not present.");
        }

        var records = new List<EvidenceRecord>();
        var failures = new List<string>();
        var inspectedCount = 0;
        var parsedCount = 0;
        var paths = Directory
            .EnumerateFiles(_prefetchDirectory, "*.pf", SearchOption.TopDirectoryOnly)
            .Take(MaximumPrefetchFiles + 1)
            .ToArray();
        var enumerationCapped = paths.Length > MaximumPrefetchFiles;

        foreach (var path in paths.Take(MaximumPrefetchFiles))
        {
            cancellationToken.ThrowIfCancellationRequested();
            inspectedCount++;
            try
            {
                var file = new FileInfo(path);
                file.Refresh();
                var parsed = _parser.Parse(path);
                parsedCount++;
                var runTimes = parsed.LastRunTimes
                    .Where(timestamp => timestamp >= context.ReviewWindowStartUtc
                        && timestamp <= context.ReviewWindowEndUtc)
                    .OrderBy(timestamp => timestamp)
                    .ToArray();

                for (var index = 0; index < runTimes.Length; index++)
                {
                    records.Add(new EvidenceRecord(
                        "execution-history",
                        "execution.prefetch",
                        "Windows Prefetch parsed header",
                        DateTimeOffset.UtcNow,
                        runTimes[index],
                        new Dictionary<string, string?>
                        {
                            ["prefetchFile"] = file.Name,
                            ["prefetchPath"] = _redactor.Redact(file.FullName),
                            ["fileSizeBytes"] = file.Length.ToString(CultureInfo.InvariantCulture),
                            ["executableName"] = parsed.ExecutableName,
                            ["prefetchVersion"] = parsed.Version.ToString(CultureInfo.InvariantCulture),
                            ["runCount"] = parsed.RunCount.ToString(CultureInfo.InvariantCulture),
                            ["parsedRunOrdinal"] = (index + 1).ToString(CultureInfo.InvariantCulture),
                            ["parsedRunTimeCount"] = parsed.LastRunTimes.Count.ToString(CultureInfo.InvariantCulture),
                            ["timestampBasis"] = "Parsed Prefetch last-run FILETIME",
                        }));
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidDataException
                or NotSupportedException
                or System.Security.SecurityException)
            {
                if (failures.Count < 8)
                {
                    failures.Add($"{Path.GetFileName(path)}={exception.GetType().Name}");
                }
            }
        }

        var ordered = records.OrderBy(record => record.SourceTimestampUtc).ToArray();
        var detail = $"inspected={inspectedCount.ToString(CultureInfo.InvariantCulture)}; "
            + $"parsed={parsedCount.ToString(CultureInfo.InvariantCulture)}; "
            + $"parseFailures={(inspectedCount - parsedCount).ToString(CultureInfo.InvariantCulture)}; "
            + $"reviewWindowRecords={ordered.Length.ToString(CultureInfo.InvariantCulture)}; "
            + $"enumerationCapped={enumerationCapped.ToString().ToLowerInvariant()}"
            + (failures.Count == 0 ? string.Empty : $"; sampleFailures={string.Join(",", failures)}");
        var status = inspectedCount > 0 && parsedCount == 0
            ? EvidenceSourceStatus.Unavailable
            : ordered.Length == 0
                ? EvidenceSourceStatus.Empty
                : EvidenceSourceStatus.Available;
        return new EvidenceSourceResult(
            Name,
            status,
            ordered,
            detail);
    }
}
