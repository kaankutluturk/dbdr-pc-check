using System.Buffers.Binary;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class PortableExecutableAnalyzerTests
{
    [Fact]
    public async Task ReportsBoundedSectionSignalsForValidPe()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-pe-{Guid.NewGuid():N}.exe");
        try
        {
            await File.WriteAllBytesAsync(path, CreateMinimalPe(invalidSectionBounds: false));

            var evidence = await new PortableExecutableAnalyzer().AnalyzeAsync(path, CancellationToken.None);

            Assert.Equal("valid", evidence.Status);
            Assert.Equal("x64", evidence.Machine);
            Assert.Equal("PE32+", evidence.Format);
            Assert.Equal("1", evidence.WritableExecutableSectionCount);
            Assert.Equal(".vmp0", evidence.SuspiciousSectionNames);
            Assert.Contains(".vmp0:RWX", evidence.Sections ?? string.Empty, StringComparison.Ordinal);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task MalformedSectionBoundsAreExplicit()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-pe-{Guid.NewGuid():N}.exe");
        try
        {
            await File.WriteAllBytesAsync(path, CreateMinimalPe(invalidSectionBounds: true));

            var evidence = await new PortableExecutableAnalyzer().AnalyzeAsync(path, CancellationToken.None);

            Assert.Equal("malformed", evidence.Status);
            Assert.Equal("InvalidDataException", evidence.Error);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task SamplesLargeOverlayEntropyWithinBounds()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-pe-{Guid.NewGuid():N}.exe");
        try
        {
            var bytes = CreateMinimalPe(invalidSectionBounds: false);
            Array.Resize(ref bytes, bytes.Length + 1024 * 1024);
            for (var index = 1024; index < bytes.Length; index++)
            {
                bytes[index] = (byte)((index * 73 + 19) & 0xff);
            }

            await File.WriteAllBytesAsync(path, bytes);

            var evidence = await new PortableExecutableAnalyzer().AnalyzeAsync(path, CancellationToken.None);

            Assert.Equal((1024 * 1024).ToString(System.Globalization.CultureInfo.InvariantCulture), evidence.OverlaySizeBytes);
            Assert.Equal("high", evidence.OverlayEntropyClassification);
            Assert.NotNull(evidence.OverlayEntropyBitsPerByte);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static byte[] CreateMinimalPe(bool invalidSectionBounds)
    {
        var bytes = new byte[1024];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x3c, 4), 0x80);
        bytes[0x80] = (byte)'P';
        bytes[0x81] = (byte)'E';
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x84, 2), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x86, 2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x88, 4), 1_786_406_400);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x94, 2), 0xf0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x98, 2), 0x20b);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x98 + 60, 4), 0x200);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x98 + 68, 2), 3);

        var sectionOffset = 0x98 + 0xf0;
        ".vmp0"u8.CopyTo(bytes.AsSpan(sectionOffset, 5));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(sectionOffset + 8, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(sectionOffset + 12, 4), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(sectionOffset + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(sectionOffset + 20, 4),
            invalidSectionBounds ? 0x400U : 0x200U);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(sectionOffset + 36, 4), 0xe0000020);

        for (var index = 0x200; index < bytes.Length; index++)
        {
            bytes[index] = (byte)((index * 73 + 19) & 0xff);
        }

        return bytes;
    }
}
