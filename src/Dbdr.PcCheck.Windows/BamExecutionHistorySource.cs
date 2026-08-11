using System.Globalization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Microsoft.Win32;

namespace Dbdr.PcCheck.Windows;

public sealed class BamExecutionHistorySource(PathRedactor redactor) : IExecutionHistorySource
{
    private static readonly string[] CandidateRoots =
    [
        @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        @"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    ];

    public string Name => "Background Activity Monitor (BAM)";

    public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken)
    {
        var records = new List<EvidenceRecord>();
        var rootsPresent = 0;

        using var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var candidateRoot in CandidateRoots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var root = localMachine.OpenSubKey(candidateRoot, writable: false);
            if (root is null)
            {
                continue;
            }

            rootsPresent++;
            foreach (var userSettingsName in root.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var userSettings = root.OpenSubKey(userSettingsName, writable: false);
                if (userSettings is null)
                {
                    continue;
                }

                foreach (var valueName in userSettings.GetValueNames())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (userSettings.GetValue(valueName) is not byte[] bytes
                        || !TryReadFileTime(bytes, out var executionTimeUtc)
                        || executionTimeUtc < context.ReviewWindowStartUtc
                        || executionTimeUtc > context.ReviewWindowEndUtc)
                    {
                        continue;
                    }

                    records.Add(new EvidenceRecord(
                        "execution-history",
                        "execution.bam",
                        "Registry:Background Activity Monitor",
                        DateTimeOffset.UtcNow,
                        executionTimeUtc,
                        new Dictionary<string, string?>
                        {
                            ["executablePath"] = redactor.Redact(valueName),
                            ["fileName"] = Path.GetFileName(valueName),
                            ["timestampBasis"] = "BAM registry FILETIME",
                        }));
                }
            }
        }

        var uniqueRecords = records
            .DistinctBy(record => new
            {
                Path = record.Fields["executablePath"],
                record.SourceTimestampUtc,
            })
            .OrderBy(record => record.SourceTimestampUtc)
            .ToArray();

        if (rootsPresent == 0)
        {
            return new EvidenceSourceResult(Name, EvidenceSourceStatus.Unavailable, [], "BAM registry keys were not present.");
        }

        return new EvidenceSourceResult(
            Name,
            uniqueRecords.Length == 0 ? EvidenceSourceStatus.Empty : EvidenceSourceStatus.Available,
            uniqueRecords,
            $"Filtered to the explicit review window; {rootsPresent.ToString(CultureInfo.InvariantCulture)} registry layout(s) present.");
    }

    private static bool TryReadFileTime(byte[] bytes, out DateTimeOffset timestampUtc)
    {
        timestampUtc = default;
        if (bytes.Length < sizeof(long))
        {
            return false;
        }

        try
        {
            var fileTime = BitConverter.ToInt64(bytes, 0);
            if (fileTime <= 0)
            {
                return false;
            }

            timestampUtc = new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime));
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }
}
