using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Dbdr.PcCheck.Core.Models;
using Microsoft.Win32.SafeHandles;

namespace Dbdr.PcCheck.Windows;

public sealed record ParsedUsnRecord(
    string FileReferenceKey,
    string FileName,
    DateTimeOffset TimestampUtc,
    uint Reason);

public static class UsnJournalRecordParser
{
    public static IReadOnlyList<ParsedUsnRecord> Parse(ReadOnlySpan<byte> data, int maximumRecords)
    {
        var records = new List<ParsedUsnRecord>();
        var offset = 0;
        while (offset + 8 <= data.Length && records.Count < maximumRecords)
        {
            var recordLength = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
            if (recordLength < 60 || recordLength > int.MaxValue || offset + recordLength > data.Length)
            {
                break;
            }

            var record = data.Slice(offset, (int)recordLength);
            var majorVersion = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(4, 2));
            int timestampOffset;
            int reasonOffset;
            int fileNameLengthOffset;
            int fileNameOffsetOffset;
            int minimumHeaderSize;
            ReadOnlySpan<byte> fileReference;
            if (majorVersion == 2)
            {
                timestampOffset = 32;
                reasonOffset = 40;
                fileNameLengthOffset = 56;
                fileNameOffsetOffset = 58;
                minimumHeaderSize = 60;
                fileReference = record.Slice(8, 8);
            }
            else if (majorVersion == 3 && recordLength >= 76)
            {
                timestampOffset = 48;
                reasonOffset = 56;
                fileNameLengthOffset = 72;
                fileNameOffsetOffset = 74;
                minimumHeaderSize = 76;
                fileReference = record.Slice(8, 16);
            }
            else
            {
                offset += (int)recordLength;
                continue;
            }

            var fileNameLength = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(fileNameLengthOffset, 2));
            var fileNameOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(fileNameOffsetOffset, 2));
            if (fileNameLength == 0
                || (fileNameLength & 1) != 0
                || fileNameOffset < minimumHeaderSize
                || fileNameOffset + fileNameLength > record.Length)
            {
                offset += (int)recordLength;
                continue;
            }

            var fileTime = BinaryPrimitives.ReadInt64LittleEndian(record.Slice(timestampOffset, 8));
            DateTimeOffset timestamp;
            try
            {
                timestamp = new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime));
            }
            catch (ArgumentOutOfRangeException)
            {
                offset += (int)recordLength;
                continue;
            }

            records.Add(new ParsedUsnRecord(
                Convert.ToHexString(fileReference),
                Encoding.Unicode.GetString(record.Slice(fileNameOffset, fileNameLength)),
                timestamp,
                BinaryPrimitives.ReadUInt32LittleEndian(record.Slice(reasonOffset, 4))));
            offset += (int)recordLength;
        }

        return records;
    }
}

public sealed class UsnJournalExecutionHistorySource : IExecutionHistorySource
{
    public const long MaximumJournalBytesPerVolume = 64L * 1024 * 1024;
    public const int MaximumParsedRecordsPerVolume = 250_000;
    public const int MaximumEvidenceRecords = 5_000;
    private const int JournalReadBufferBytes = 1024 * 1024;

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FsctlQueryUsnJournal = 0x000900f4;
    private const uint FsctlReadUsnJournal = 0x000900bb;

    private const uint UsnReasonDataOverwrite = 0x00000001;
    private const uint UsnReasonDataExtend = 0x00000002;
    private const uint UsnReasonDataTruncation = 0x00000004;
    private const uint UsnReasonFileCreate = 0x00000100;
    private const uint UsnReasonFileDelete = 0x00000200;
    private const uint UsnReasonRenameOldName = 0x00001000;
    private const uint UsnReasonRenameNewName = 0x00002000;
    private const uint UsnReasonSecurityChange = 0x00000800;
    private const uint RelevantReasons = UsnReasonDataOverwrite | UsnReasonDataExtend
        | UsnReasonDataTruncation | UsnReasonFileCreate | UsnReasonFileDelete
        | UsnReasonRenameOldName | UsnReasonRenameNewName | UsnReasonSecurityChange;

    private static readonly HashSet<string> ExecutionCapableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".com", ".scr", ".cpl", ".msi", ".msp",
        ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    };

    public string Name => "NTFS USN Journal executable changes";

    public EvidenceSourceResult Collect(CollectionContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new EvidenceSourceResult(Name, EvidenceSourceStatus.NotSupported, [], "Windows is required.");
        }

        var observations = new List<VolumeObservation>();
        var failures = new List<string>();
        var volumesAttempted = 0;
        var volumesReadable = 0;
        long bytesRead = 0;
        var parsedRecords = 0;
        var capped = false;

        foreach (var drive in EnumerateNtfsFixedDrives().Take(8))
        {
            cancellationToken.ThrowIfCancellationRequested();
            volumesAttempted++;
            try
            {
                var volumeResult = ReadVolume(drive, context, cancellationToken);
                volumesReadable++;
                bytesRead += volumeResult.BytesRead;
                parsedRecords += volumeResult.ParsedRecords;
                observations.AddRange(volumeResult.Observations);
                capped |= volumeResult.Capped;
                if (observations.Count >= MaximumEvidenceRecords)
                {
                    capped = true;
                    break;
                }
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or SecurityException
                or Win32Exception
                or InvalidDataException)
            {
                if (failures.Count < 8)
                {
                    failures.Add($"{drive.Name.TrimEnd('\\')}={exception.GetType().Name}");
                }
            }
        }

        var sequenceByFile = observations
            .GroupBy(observation => observation.Record.FileReferenceKey, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => ClassifySequence(group.Select(item => item.Record.Reason)),
                StringComparer.Ordinal);
        var records = observations
            .OrderBy(observation => observation.Record.TimestampUtc)
            .Take(MaximumEvidenceRecords)
            .Select(observation => new EvidenceRecord(
                "execution-history",
                "execution.usn_executable_change",
                "NTFS USN change journal",
                DateTimeOffset.UtcNow,
                observation.Record.TimestampUtc,
                new Dictionary<string, string?>
                {
                    ["volume"] = observation.Volume,
                    ["fileName"] = observation.Record.FileName,
                    ["extension"] = Path.GetExtension(observation.Record.FileName),
                    ["reasons"] = FormatReasons(observation.Record.Reason),
                    ["sequence"] = sequenceByFile[observation.Record.FileReferenceKey],
                    ["pathAvailability"] = "Parent path not reconstructed under the minimization boundary",
                    ["timestampBasis"] = "NTFS USN record timestamp",
                }))
            .ToArray();

        var detail = $"volumesAttempted={volumesAttempted.ToString(CultureInfo.InvariantCulture)}; "
            + $"volumesReadable={volumesReadable.ToString(CultureInfo.InvariantCulture)}; "
            + $"journalBytesRead={bytesRead.ToString(CultureInfo.InvariantCulture)}; "
            + $"recordsParsed={parsedRecords.ToString(CultureInfo.InvariantCulture)}; "
            + $"reviewWindowExecutableRecords={records.Length.ToString(CultureInfo.InvariantCulture)}; "
            + $"capped={capped.ToString().ToLowerInvariant()}"
            + (failures.Count == 0 ? string.Empty : $"; failures={string.Join(",", failures)}");
        var status = volumesReadable == 0
            ? EvidenceSourceStatus.Unavailable
            : records.Length == 0
                ? EvidenceSourceStatus.Empty
                : EvidenceSourceStatus.Available;
        return new EvidenceSourceResult(Name, status, records, detail);
    }

    private static VolumeReadResult ReadVolume(
        DriveInfo drive,
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        var volume = drive.Name[..2];
        using var handle = CreateFile(
            $@"\\.\{volume}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var journalData = new byte[56];
        if (!DeviceIoControl(
                handle,
                FsctlQueryUsnJournal,
                null,
                0,
                journalData,
                journalData.Length,
                out var journalBytes,
                IntPtr.Zero)
            || journalBytes < journalData.Length)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var journalId = BinaryPrimitives.ReadUInt64LittleEndian(journalData.AsSpan(0, 8));
        var firstUsn = BinaryPrimitives.ReadInt64LittleEndian(journalData.AsSpan(8, 8));
        var nextUsn = BinaryPrimitives.ReadInt64LittleEndian(journalData.AsSpan(16, 8));
        var startUsn = nextUsn > MaximumJournalBytesPerVolume
            ? Math.Max(firstUsn, nextUsn - MaximumJournalBytesPerVolume)
            : firstUsn;
        var readBuffer = new byte[JournalReadBufferBytes];
        var observations = new List<VolumeObservation>();
        long bytesRead = 0;
        var parsedRecords = 0;
        var capped = false;

        while (startUsn < nextUsn
               && bytesRead < MaximumJournalBytesPerVolume
               && parsedRecords < MaximumParsedRecordsPerVolume
               && observations.Count < MaximumEvidenceRecords)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var input = CreateReadInput(startUsn, journalId);
            if (!DeviceIoControl(
                    handle,
                    FsctlReadUsnJournal,
                    input,
                    input.Length,
                    readBuffer,
                    readBuffer.Length,
                    out var returned,
                    IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (returned <= sizeof(long))
            {
                break;
            }

            bytesRead += returned;
            var remainingRecordCapacity = MaximumParsedRecordsPerVolume - parsedRecords;
            var parsed = UsnJournalRecordParser.Parse(
                readBuffer.AsSpan(sizeof(long), returned - sizeof(long)),
                remainingRecordCapacity);
            parsedRecords += parsed.Count;
            foreach (var record in parsed)
            {
                if (record.TimestampUtc < context.ReviewWindowStartUtc
                    || record.TimestampUtc > context.ReviewWindowEndUtc
                    || (record.Reason & RelevantReasons) == 0
                    || !ExecutionCapableExtensions.Contains(Path.GetExtension(record.FileName)))
                {
                    continue;
                }

                observations.Add(new VolumeObservation(volume, record));
                if (observations.Count >= MaximumEvidenceRecords)
                {
                    capped = true;
                    break;
                }
            }

            var returnedNextUsn = BinaryPrimitives.ReadInt64LittleEndian(readBuffer.AsSpan(0, sizeof(long)));
            if (returnedNextUsn <= startUsn)
            {
                break;
            }

            startUsn = returnedNextUsn;
        }

        capped |= bytesRead >= MaximumJournalBytesPerVolume
            || parsedRecords >= MaximumParsedRecordsPerVolume;
        return new VolumeReadResult(observations, bytesRead, parsedRecords, capped);
    }

    private static byte[] CreateReadInput(long startUsn, ulong journalId)
    {
        var input = new byte[40];
        BinaryPrimitives.WriteInt64LittleEndian(input.AsSpan(0, 8), startUsn);
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(8, 4), RelevantReasons);
        BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(32, 8), journalId);
        return input;
    }

    private static IEnumerable<DriveInfo> EnumerateNtfsFixedDrives()
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            bool eligible;
            try
            {
                eligible = drive.IsReady
                    && drive.DriveType == DriveType.Fixed
                    && string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or SecurityException)
            {
                continue;
            }

            if (eligible)
            {
                yield return drive;
            }
        }
    }

    private static string ClassifySequence(IEnumerable<uint> reasons)
    {
        var combined = reasons.Aggregate(0U, (current, reason) => current | reason);
        if ((combined & UsnReasonFileCreate) != 0 && (combined & UsnReasonFileDelete) != 0)
        {
            return "created-and-deleted";
        }

        if ((combined & UsnReasonRenameOldName) != 0 && (combined & UsnReasonRenameNewName) != 0)
        {
            return "renamed";
        }

        return "single-observation";
    }

    private static string FormatReasons(uint reason)
    {
        var values = new List<string>();
        Add(UsnReasonFileCreate, "file-create");
        Add(UsnReasonFileDelete, "file-delete");
        Add(UsnReasonRenameOldName, "rename-old-name");
        Add(UsnReasonRenameNewName, "rename-new-name");
        Add(UsnReasonDataOverwrite, "data-overwrite");
        Add(UsnReasonDataExtend, "data-extend");
        Add(UsnReasonDataTruncation, "data-truncation");
        Add(UsnReasonSecurityChange, "security-change");
        return string.Join(",", values);

        void Add(uint flag, string label)
        {
            if ((reason & flag) != 0)
            {
                values.Add(label);
            }
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint ioControlCode,
        byte[]? inputBuffer,
        int inputBufferSize,
        byte[] outputBuffer,
        int outputBufferSize,
        out int bytesReturned,
        IntPtr overlapped);

    private sealed record VolumeObservation(string Volume, ParsedUsnRecord Record);

    private sealed record VolumeReadResult(
        IReadOnlyList<VolumeObservation> Observations,
        long BytesRead,
        int ParsedRecords,
        bool Capped);
}
