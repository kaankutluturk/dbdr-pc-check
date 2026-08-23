using System.Buffers.Binary;
using System.Text;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class UsnJournalRecordParserTests
{
    [Fact]
    public void ParsesBoundedVersionTwoRecord()
    {
        var timestamp = new DateTimeOffset(2026, 8, 22, 12, 30, 0, TimeSpan.Zero);
        var fileName = "loader.exe";
        var nameBytes = Encoding.Unicode.GetBytes(fileName);
        var recordLength = (60 + nameBytes.Length + 7) & ~7;
        var bytes = new byte[recordLength];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0, 4), (uint)recordLength);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4, 2), 2);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(8, 8), 0x0102030405060708);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(32, 8), timestamp.UtcDateTime.ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(40, 4), 0x00000100 | 0x00000200);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(56, 2), (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(58, 2), 60);
        nameBytes.CopyTo(bytes.AsSpan(60));

        var record = Assert.Single(UsnJournalRecordParser.Parse(bytes, maximumRecords: 10));

        Assert.Equal("0102030405060708", record.FileReferenceKey);
        Assert.Equal(fileName, record.FileName);
        Assert.Equal(timestamp, record.TimestampUtc);
        Assert.Equal(0x00000300U, record.Reason);
    }

    [Fact]
    public void StopsAtRecordLimitAndRejectsMalformedLength()
    {
        var malformed = new byte[64];
        BinaryPrimitives.WriteUInt32LittleEndian(malformed.AsSpan(0, 4), uint.MaxValue);

        Assert.Empty(UsnJournalRecordParser.Parse(malformed, maximumRecords: 1));
        Assert.Empty(UsnJournalRecordParser.Parse([], maximumRecords: 1));
    }
}
