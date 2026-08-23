using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.Windows;

public sealed record PortableExecutableEvidence(
    string Status,
    string? Machine,
    string? Format,
    string? Subsystem,
    string? IsManaged,
    string? LinkerTimestampUtc,
    string? SectionCount,
    string? Sections,
    string? HighEntropySectionCount,
    string? WritableExecutableSectionCount,
    string? SuspiciousSectionNames,
    string? ImportDllCount,
    string? ImportApiCount,
    string? SuspiciousImports,
    string? ImportRiskClusters,
    string? OverlaySizeBytes,
    string? CertificateTablePresent,
    string? PdbFileName,
    string? Error,
    string? OverlayEntropyBitsPerByte = null,
    string? OverlayEntropyClassification = null,
    string? ImportFingerprintSha256 = null)
{
    public static PortableExecutableEvidence NotPe { get; } =
        new("not-pe", null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null);

    public void AddTo(IDictionary<string, string?> fields)
    {
        fields["peStatus"] = Status;
        fields["peMachine"] = Machine;
        fields["peFormat"] = Format;
        fields["peSubsystem"] = Subsystem;
        fields["peIsManaged"] = IsManaged;
        fields["peLinkerTimestampUtc"] = LinkerTimestampUtc;
        fields["peLinkerTimestampBasis"] = LinkerTimestampUtc is null ? null : "untrusted COFF header metadata";
        fields["peSectionCount"] = SectionCount;
        fields["peSections"] = Sections;
        fields["peHighEntropySectionCount"] = HighEntropySectionCount;
        fields["peWritableExecutableSectionCount"] = WritableExecutableSectionCount;
        fields["peSuspiciousSectionNames"] = SuspiciousSectionNames;
        fields["peImportDllCount"] = ImportDllCount;
        fields["peImportApiCount"] = ImportApiCount;
        fields["peSuspiciousImports"] = SuspiciousImports;
        fields["peImportRiskClusters"] = ImportRiskClusters;
        fields["peOverlaySizeBytes"] = OverlaySizeBytes;
        fields["peCertificateTablePresent"] = CertificateTablePresent;
        fields["pePdbFileName"] = PdbFileName;
        fields["peInspectionError"] = Error;
        fields["peOverlayEntropyBitsPerByte"] = OverlayEntropyBitsPerByte;
        fields["peOverlayEntropyClassification"] = OverlayEntropyClassification;
        fields["peImportFingerprintSha256"] = ImportFingerprintSha256;
    }
}

public interface IPortableExecutableAnalyzer
{
    Task<PortableExecutableEvidence> AnalyzeAsync(string path, CancellationToken cancellationToken);
}

/// <summary>
/// Performs a bounded, read-only PE inspection. The parser deliberately avoids PEReader because its
/// official documentation states that it is not designed for hostile input.
/// </summary>
public sealed class PortableExecutableAnalyzer : IPortableExecutableAnalyzer
{
    private const int MaximumPeHeaderOffset = 1024 * 1024;
    private const int MaximumOptionalHeaderSize = 4096;
    private const int MaximumSections = 96;
    private const int MaximumImportDescriptors = 256;
    private const int MaximumImports = 4096;
    private const int MaximumStringBytes = 512;
    private const int MaximumSectionEntropyBytes = 4 * 1024 * 1024;
    private const int MaximumTotalEntropyBytes = 32 * 1024 * 1024;
    private const int MaximumOverlayEntropyBytes = 4 * 1024 * 1024;

    private const uint SectionExecute = 0x20000000;
    private const uint SectionRead = 0x40000000;
    private const uint SectionWrite = 0x80000000;

    private static readonly HashSet<string> SuspiciousSectionNameSet = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0", "UPX1", "UPX2", ".vmp0", ".vmp1", ".vmp2", ".themida", ".packed",
        ".aspack", ".petite", ".enigma", ".boom",
    };

    private static readonly IReadOnlyDictionary<string, string[]> RiskApis =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["remote-process"] =
            [
                "OpenProcess", "WriteProcessMemory", "VirtualAllocEx", "VirtualProtectEx",
                "CreateRemoteThread", "NtWriteVirtualMemory", "NtCreateThreadEx",
                "QueueUserAPC", "SetThreadContext",
            ],
            ["memory-remapping"] =
            [
                "NtMapViewOfSection", "MapViewOfFile", "VirtualAlloc", "VirtualProtect",
                "RtlAddFunctionTable", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
            ],
            ["driver-control"] =
            [
                "NtLoadDriver", "CreateServiceA", "CreateServiceW", "StartServiceA",
                "StartServiceW", "DeviceIoControl",
            ],
            ["input-hooking"] =
            [
                "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
                "SendInput", "mouse_event", "keybd_event",
            ],
            ["anti-analysis"] =
            [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                "OutputDebugStringA", "OutputDebugStringW", "QueryPerformanceCounter",
            ],
            ["network-fetch"] =
            [
                "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "WinHttpConnect",
                "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
            ],
            ["process-launch"] =
            [
                "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
                "WinExec",
            ],
        };

    public async Task<PortableExecutableEvidence> AnalyzeAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                4096,
                FileOptions.Asynchronous | FileOptions.RandomAccess);

            if (stream.Length < 64)
            {
                return PortableExecutableEvidence.NotPe;
            }

            var dosHeader = await ReadAtAsync(stream, 0, 64, cancellationToken).ConfigureAwait(false);
            if (dosHeader[0] != (byte)'M' || dosHeader[1] != (byte)'Z')
            {
                return PortableExecutableEvidence.NotPe;
            }

            var peOffset = BinaryPrimitives.ReadUInt32LittleEndian(dosHeader.AsSpan(0x3c, 4));
            if (peOffset > MaximumPeHeaderOffset || peOffset + 24 > stream.Length)
            {
                return Malformed("InvalidPeHeaderOffset");
            }

            var coff = await ReadAtAsync(stream, peOffset, 24, cancellationToken).ConfigureAwait(false);
            if (coff[0] != (byte)'P' || coff[1] != (byte)'E' || coff[2] != 0 || coff[3] != 0)
            {
                return PortableExecutableEvidence.NotPe;
            }

            var machine = BinaryPrimitives.ReadUInt16LittleEndian(coff.AsSpan(4, 2));
            var sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coff.AsSpan(6, 2));
            var linkerTimestamp = BinaryPrimitives.ReadUInt32LittleEndian(coff.AsSpan(8, 4));
            var optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(coff.AsSpan(20, 2));
            if (sectionCount is 0 or > MaximumSections
                || optionalHeaderSize < 96
                || optionalHeaderSize > MaximumOptionalHeaderSize)
            {
                return Malformed("InvalidHeaderDimensions");
            }

            var optionalOffset = checked((long)peOffset + 24);
            var optional = await ReadAtAsync(stream, optionalOffset, optionalHeaderSize, cancellationToken).ConfigureAwait(false);
            var magic = BinaryPrimitives.ReadUInt16LittleEndian(optional.AsSpan(0, 2));
            var isPe32Plus = magic == 0x20b;
            if (!isPe32Plus && magic != 0x10b)
            {
                return Malformed("UnsupportedOptionalHeaderMagic");
            }

            var directoryStart = isPe32Plus ? 112 : 96;
            if (optional.Length < directoryStart)
            {
                return Malformed("TruncatedOptionalHeader");
            }

            var sizeOfHeaders = ReadUInt32(optional, 60);
            var subsystem = ReadUInt16(optional, 68);
            var importDirectory = ReadDirectory(optional, directoryStart, 1);
            var securityDirectory = ReadDirectory(optional, directoryStart, 4);
            var debugDirectory = ReadDirectory(optional, directoryStart, 6);
            var clrDirectory = ReadDirectory(optional, directoryStart, 14);

            var sectionTableOffset = optionalOffset + optionalHeaderSize;
            var sectionTableSize = checked(sectionCount * 40);
            var sectionBytes = await ReadAtAsync(stream, sectionTableOffset, sectionTableSize, cancellationToken).ConfigureAwait(false);
            var sections = ParseSections(sectionBytes, sectionCount, stream.Length);
            var sectionSummaries = new List<string>(sections.Count);
            var suspiciousSectionNames = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            var highEntropySections = 0;
            var writableExecutableSections = 0;
            var totalEntropyBytes = 0;

            foreach (var section in sections)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var flags = FormatSectionFlags(section.Characteristics);
                var entropyText = "n/a";
                var sampleSize = (int)Math.Min(
                    Math.Min((long)section.RawSize, MaximumSectionEntropyBytes),
                    Math.Max(0, MaximumTotalEntropyBytes - totalEntropyBytes));
                if (sampleSize > 0 && (long)section.RawOffset + sampleSize <= stream.Length)
                {
                    var sample = await ReadAtAsync(stream, section.RawOffset, sampleSize, cancellationToken).ConfigureAwait(false);
                    var entropy = new BinaryEntropy();
                    entropy.Append(sample);
                    var value = entropy.CalculateBitsPerByte();
                    entropyText = value.ToString("F2", CultureInfo.InvariantCulture);
                    if (value >= 7.2)
                    {
                        highEntropySections++;
                    }

                    totalEntropyBytes += sampleSize;
                }

                if ((section.Characteristics & (SectionWrite | SectionExecute)) == (SectionWrite | SectionExecute))
                {
                    writableExecutableSections++;
                }

                if (SuspiciousSectionNameSet.Contains(section.Name))
                {
                    suspiciousSectionNames.Add(section.Name);
                }

                sectionSummaries.Add($"{section.Name}:{flags}:H={entropyText}");
            }

            var imports = await ReadImportsAsync(
                stream,
                sections,
                sizeOfHeaders,
                importDirectory,
                isPe32Plus,
                cancellationToken).ConfigureAwait(false);
            var suspiciousImports = FindSuspiciousImports(imports.ApiNames);
            var riskClusters = ClassifyRiskClusters(suspiciousImports);
            var importFingerprint = CreateImportFingerprint(imports);
            var pdbFileName = await ReadPdbFileNameAsync(
                stream,
                sections,
                sizeOfHeaders,
                debugDirectory,
                cancellationToken).ConfigureAwait(false);

            var rawImageEnd = Math.Max((long)sizeOfHeaders, sections.Count == 0
                ? 0
                : sections.Max(section => (long)section.RawOffset + section.RawSize));
            var certificateEnd = securityDirectory.Rva == 0 || securityDirectory.Size == 0
                ? 0
                : checked((long)securityDirectory.Rva + securityDirectory.Size);
            var overlayStart = Math.Min(stream.Length, Math.Max(rawImageEnd, certificateEnd));
            var overlaySize = Math.Max(0, stream.Length - overlayStart);
            string? overlayEntropyText = null;
            string? overlayEntropyClassification = null;
            var overlaySampleSize = (int)Math.Min(overlaySize, MaximumOverlayEntropyBytes);
            if (overlaySampleSize > 0)
            {
                var overlaySample = await ReadAtAsync(
                    stream,
                    overlayStart,
                    overlaySampleSize,
                    cancellationToken).ConfigureAwait(false);
                var overlayEntropy = new BinaryEntropy();
                overlayEntropy.Append(overlaySample);
                var overlayEntropyValue = overlayEntropy.CalculateBitsPerByte();
                overlayEntropyText = overlayEntropyValue.ToString("F4", CultureInfo.InvariantCulture);
                overlayEntropyClassification = BinaryEntropy.Classify(overlayEntropyValue);
            }

            return new PortableExecutableEvidence(
                "valid",
                FormatMachine(machine),
                isPe32Plus ? "PE32+" : "PE32",
                FormatSubsystem(subsystem),
                (clrDirectory.Rva != 0 && clrDirectory.Size != 0).ToString().ToLowerInvariant(),
                FormatLinkerTimestamp(linkerTimestamp),
                sectionCount.ToString(CultureInfo.InvariantCulture),
                string.Join(", ", sectionSummaries),
                highEntropySections.ToString(CultureInfo.InvariantCulture),
                writableExecutableSections.ToString(CultureInfo.InvariantCulture),
                string.Join(", ", suspiciousSectionNames),
                imports.DllCount.ToString(CultureInfo.InvariantCulture),
                imports.ApiNames.Count.ToString(CultureInfo.InvariantCulture),
                string.Join(", ", suspiciousImports.Order(StringComparer.OrdinalIgnoreCase)),
                string.Join(", ", riskClusters),
                overlaySize.ToString(CultureInfo.InvariantCulture),
                (securityDirectory.Rva != 0 && securityDirectory.Size != 0).ToString().ToLowerInvariant(),
                pdbFileName,
                imports.Truncated ? "ImportEnumerationCapped" : null,
                overlayEntropyText,
                overlayEntropyClassification,
                importFingerprint);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException
            or OverflowException
            or InvalidDataException)
        {
            return Malformed(exception.GetType().Name);
        }
    }

    private static async Task<ImportEvidence> ReadImportsAsync(
        FileStream stream,
        IReadOnlyList<Section> sections,
        uint sizeOfHeaders,
        DataDirectory directory,
        bool isPe32Plus,
        CancellationToken cancellationToken)
    {
        if (directory.Rva == 0 || directory.Size == 0
            || !TryMapRva(directory.Rva, sections, sizeOfHeaders, stream.Length, out var descriptorOffset))
        {
            return new ImportEvidence(
                0,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                false);
        }

        var apiNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var dllNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var truncated = false;
        var maximumDescriptors = (int)Math.Min(
            (uint)MaximumImportDescriptors,
            Math.Max(1U, directory.Size / 20));
        var thunkSize = isPe32Plus ? 8 : 4;

        for (var descriptorIndex = 0; descriptorIndex < maximumDescriptors; descriptorIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var descriptor = await ReadAtAsync(
                stream,
                descriptorOffset + descriptorIndex * 20L,
                20,
                cancellationToken).ConfigureAwait(false);
            var originalThunkRva = ReadUInt32(descriptor, 0);
            var nameRva = ReadUInt32(descriptor, 12);
            var firstThunkRva = ReadUInt32(descriptor, 16);
            if (originalThunkRva == 0 && nameRva == 0 && firstThunkRva == 0)
            {
                break;
            }

            if (TryMapRva(nameRva, sections, sizeOfHeaders, stream.Length, out var nameOffset))
            {
                var dllName = await ReadAsciiAsync(stream, nameOffset, MaximumStringBytes, cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(dllName))
                {
                    dllNames.Add(dllName);
                }
            }

            var thunkRva = originalThunkRva != 0 ? originalThunkRva : firstThunkRva;
            if (!TryMapRva(thunkRva, sections, sizeOfHeaders, stream.Length, out var thunkOffset))
            {
                continue;
            }

            for (var thunkIndex = 0; thunkIndex < MaximumImports; thunkIndex++)
            {
                if (apiNames.Count >= MaximumImports)
                {
                    truncated = true;
                    break;
                }

                var thunk = await ReadAtAsync(
                    stream,
                    thunkOffset + thunkIndex * (long)thunkSize,
                    thunkSize,
                    cancellationToken).ConfigureAwait(false);
                var value = isPe32Plus
                    ? BinaryPrimitives.ReadUInt64LittleEndian(thunk)
                    : BinaryPrimitives.ReadUInt32LittleEndian(thunk);
                if (value == 0)
                {
                    break;
                }

                var ordinalMask = isPe32Plus ? 0x8000000000000000UL : 0x80000000UL;
                if ((value & ordinalMask) != 0 || value > uint.MaxValue)
                {
                    continue;
                }

                if (TryMapRva((uint)value, sections, sizeOfHeaders, stream.Length, out var importNameOffset))
                {
                    var apiName = await ReadAsciiAsync(
                        stream,
                        importNameOffset + 2,
                        MaximumStringBytes,
                        cancellationToken).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(apiName))
                    {
                        apiNames.Add(apiName);
                    }
                }
            }

            if (truncated)
            {
                break;
            }
        }

        return new ImportEvidence(dllNames.Count, dllNames, apiNames, truncated);
    }

    private static async Task<string?> ReadPdbFileNameAsync(
        FileStream stream,
        IReadOnlyList<Section> sections,
        uint sizeOfHeaders,
        DataDirectory directory,
        CancellationToken cancellationToken)
    {
        if (directory.Rva == 0 || directory.Size < 28
            || !TryMapRva(directory.Rva, sections, sizeOfHeaders, stream.Length, out var offset))
        {
            return null;
        }

        var entryCount = Math.Min(32, (int)(directory.Size / 28));
        for (var index = 0; index < entryCount; index++)
        {
            var entry = await ReadAtAsync(stream, offset + index * 28L, 28, cancellationToken).ConfigureAwait(false);
            if (ReadUInt32(entry, 12) != 2)
            {
                continue;
            }

            var dataSize = ReadUInt32(entry, 16);
            var dataOffset = ReadUInt32(entry, 24);
            if (dataSize < 24 || (long)dataOffset + Math.Min((long)dataSize, MaximumStringBytes) > stream.Length)
            {
                continue;
            }

            var data = await ReadAtAsync(
                stream,
                dataOffset,
                (int)Math.Min(dataSize, MaximumStringBytes),
                cancellationToken).ConfigureAwait(false);
            if (data.Length < 24 || Encoding.ASCII.GetString(data, 0, 4) != "RSDS")
            {
                continue;
            }

            var pdbPath = ReadAscii(data.AsSpan(24));
            return pdbPath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
        }

        return null;
    }

    private static IReadOnlyList<Section> ParseSections(byte[] data, int count, long fileLength)
    {
        var sections = new List<Section>(count);
        for (var index = 0; index < count; index++)
        {
            var offset = index * 40;
            var name = ReadAscii(data.AsSpan(offset, 8));
            if (name.Length == 0)
            {
                name = "<unnamed>";
            }

            var virtualSize = ReadUInt32(data, offset + 8);
            var virtualAddress = ReadUInt32(data, offset + 12);
            var rawSize = ReadUInt32(data, offset + 16);
            var rawOffset = ReadUInt32(data, offset + 20);
            var characteristics = ReadUInt32(data, offset + 36);
            if (rawOffset > fileLength || rawSize > fileLength - rawOffset)
            {
                throw new InvalidDataException("A PE section points outside the file.");
            }

            sections.Add(new Section(name, virtualSize, virtualAddress, rawSize, rawOffset, characteristics));
        }

        return sections;
    }

    private static bool TryMapRva(
        uint rva,
        IReadOnlyList<Section> sections,
        uint sizeOfHeaders,
        long fileLength,
        out long fileOffset)
    {
        if (rva < sizeOfHeaders && rva < fileLength)
        {
            fileOffset = rva;
            return true;
        }

        foreach (var section in sections)
        {
            var span = Math.Max(section.VirtualSize, section.RawSize);
            if (rva < section.VirtualAddress || (ulong)rva >= (ulong)section.VirtualAddress + span)
            {
                continue;
            }

            var delta = rva - section.VirtualAddress;
            var candidate = (long)section.RawOffset + delta;
            if (delta < section.RawSize && candidate >= 0 && candidate < fileLength)
            {
                fileOffset = candidate;
                return true;
            }
        }

        fileOffset = 0;
        return false;
    }

    private static SortedSet<string> FindSuspiciousImports(IReadOnlySet<string> imports)
    {
        var result = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var names in RiskApis.Values)
        {
            foreach (var name in names)
            {
                if (imports.Contains(name))
                {
                    result.Add(name);
                }
            }
        }

        return result;
    }

    private static IReadOnlyList<string> ClassifyRiskClusters(IReadOnlySet<string> imports)
    {
        var result = new List<string>();
        AddCluster("remote-process", 3);
        AddCluster("memory-remapping", 4);
        AddCluster("driver-control", 2);
        AddCluster("input-hooking", 2);
        AddCluster("anti-analysis", 3);
        if (Count("network-fetch") >= 1 && Count("process-launch") >= 1)
        {
            result.Add("download-and-launch");
        }

        return result;

        void AddCluster(string name, int minimum)
        {
            if (Count(name) >= minimum)
            {
                result.Add(name);
            }
        }

        int Count(string name) => RiskApis[name].Count(imports.Contains);
    }

    private static string? CreateImportFingerprint(ImportEvidence imports)
    {
        if (imports.DllNames.Count == 0 && imports.ApiNames.Count == 0)
        {
            return null;
        }

        var normalized = string.Join(
            "\n",
            imports.DllNames.Select(name => $"dll:{name.ToLowerInvariant()}")
                .Concat(imports.ApiNames.Select(name => $"api:{name.ToLowerInvariant()}"))
                .OrderBy(value => value, StringComparer.Ordinal));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));
    }

    private static async Task<byte[]> ReadAtAsync(
        FileStream stream,
        long offset,
        int count,
        CancellationToken cancellationToken)
    {
        if (offset < 0 || count < 0 || offset > stream.Length - count)
        {
            throw new EndOfStreamException();
        }

        var buffer = new byte[count];
        stream.Position = offset;
        await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer;
    }

    private static async Task<string> ReadAsciiAsync(
        FileStream stream,
        long offset,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var available = (int)Math.Min(maximumBytes, Math.Max(0, stream.Length - offset));
        if (available <= 0)
        {
            return string.Empty;
        }

        var bytes = await ReadAtAsync(stream, offset, available, cancellationToken).ConfigureAwait(false);
        return ReadAscii(bytes);
    }

    private static string ReadAscii(ReadOnlySpan<byte> bytes)
    {
        var length = bytes.IndexOf((byte)0);
        if (length < 0)
        {
            length = bytes.Length;
        }

        return Encoding.ASCII.GetString(bytes[..length]);
    }

    private static DataDirectory ReadDirectory(byte[] optionalHeader, int directoryStart, int index)
    {
        var offset = directoryStart + index * 8;
        return offset + 8 <= optionalHeader.Length
            ? new DataDirectory(ReadUInt32(optionalHeader, offset), ReadUInt32(optionalHeader, offset + 4))
            : default;
    }

    private static string FormatSectionFlags(uint characteristics) => string.Concat(
        (characteristics & SectionRead) != 0 ? "R" : "-",
        (characteristics & SectionWrite) != 0 ? "W" : "-",
        (characteristics & SectionExecute) != 0 ? "X" : "-");

    private static string FormatMachine(ushort machine) => machine switch
    {
        0x014c => "x86",
        0x8664 => "x64",
        0xaa64 => "arm64",
        0x01c4 => "arm-thumb2",
        0x0200 => "ia64",
        _ => $"0x{machine:X4}",
    };

    private static string FormatSubsystem(ushort subsystem) => subsystem switch
    {
        1 => "native",
        2 => "windows-gui",
        3 => "windows-console",
        7 => "posix-console",
        9 => "windows-ce-gui",
        10 => "efi-application",
        11 => "efi-boot-service-driver",
        12 => "efi-runtime-driver",
        14 => "xbox",
        16 => "windows-boot-application",
        _ => subsystem.ToString(CultureInfo.InvariantCulture),
    };

    private static string? FormatLinkerTimestamp(uint timestamp)
    {
        if (timestamp is 0 or uint.MaxValue)
        {
            return null;
        }

        var value = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        return value.Year is < 1995 or > 2100
            ? null
            : value.ToString("O", CultureInfo.InvariantCulture);
    }

    private static ushort ReadUInt16(byte[] value, int offset) =>
        offset + 2 <= value.Length ? BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(offset, 2)) : (ushort)0;

    private static uint ReadUInt32(byte[] value, int offset) =>
        offset + 4 <= value.Length ? BinaryPrimitives.ReadUInt32LittleEndian(value.AsSpan(offset, 4)) : 0;

    private static PortableExecutableEvidence Malformed(string error) =>
        new("malformed", null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, error);

    private sealed record Section(
        string Name,
        uint VirtualSize,
        uint VirtualAddress,
        uint RawSize,
        uint RawOffset,
        uint Characteristics);

    private readonly record struct DataDirectory(uint Rva, uint Size);

    private sealed record ImportEvidence(
        int DllCount,
        IReadOnlySet<string> DllNames,
        IReadOnlySet<string> ApiNames,
        bool Truncated);
}
