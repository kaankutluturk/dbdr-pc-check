using System.Globalization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Windows;

public sealed class PrefetchExecutionHistorySource(
    PathRedactor redactor,
    string? prefetchDirectory = null) : IExecutionHistorySource
{
    private readonly string _prefetchDirectory = prefetchDirectory
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

    public string Name => "Windows Prefetch";

    public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(_prefetchDirectory))
        {
            return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], "Prefetch directory was not present.");
        }

        var records = new List<EvidenceRecord>();
        foreach (var path in Directory.EnumerateFiles(_prefetchDirectory, "*.pf", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var file = new FileInfo(path);
            file.Refresh();
            var modifiedUtc = new DateTimeOffset(file.LastWriteTimeUtc);
            if (modifiedUtc < context.ReviewWindowStartUtc || modifiedUtc > context.ReviewWindowEndUtc)
            {
                continue;
            }

            records.Add(new EvidenceRecord(
                "execution-history",
                "execution.prefetch",
                "Windows Prefetch file metadata",
                DateTimeOffset.UtcNow,
                modifiedUtc,
                new Dictionary<string, string?>
                {
                    ["prefetchFile"] = file.Name,
                    ["prefetchPath"] = redactor.Redact(file.FullName),
                    ["fileSizeBytes"] = file.Length.ToString(CultureInfo.InvariantCulture),
                    ["timestampBasis"] = "Prefetch file last-write time; not a parsed run time",
                }));
        }

        var ordered = records.OrderBy(record => record.SourceTimestampUtc).ToArray();
        return new EvidenceSourceResult(
            Name,
            ordered.Length == 0 ? EvidenceSourceStatus.Empty : EvidenceSourceStatus.Available,
            ordered,
            "File metadata only; filtered to the explicit review window.");
    }
}
