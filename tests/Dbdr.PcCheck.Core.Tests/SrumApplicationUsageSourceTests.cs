using System.Text;
using System.Xml;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class SrumApplicationUsageSourceTests
{
    [Fact]
    public void MinimizesApplicationRowsAndDropsSensitiveFields()
    {
        const string xml = """
            <SystemResourceUsageMonitor>
              <ApplicationUsage>
                <Row>
                  <TimeStamp>2026-08-23T09:15:00Z</TimeStamp>
                  <ExeInfo>C:\Users\Alice\AppData\Local\loader.exe</ExeInfo>
                  <UserId>S-1-5-21-private</UserId>
                  <RemoteHost>private.example</RemoteHost>
                  <BytesSent>123456</BytesSent>
                </Row>
                <Row>
                  <TimeStamp>2026-08-22T09:15:00Z</TimeStamp>
                  <AppId>C:\Program Files\Vendor\outside.exe</AppId>
                </Row>
                <Row>
                  <TimeStamp>2026-08-23T09:20:00Z</TimeStamp>
                  <AppId>42</AppId>
                </Row>
              </ApplicationUsage>
            </SystemResourceUsageMonitor>
            """;
        var context = Context();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));

        var parsed = SrumApplicationUsageParser.Parse(
            stream,
            context,
            new PathRedactor(@"C:\Users\Alice"),
            context.ReviewWindowEndUtc,
            CancellationToken.None);

        var record = Assert.Single(parsed.Records);
        Assert.Equal("execution.srum_application", record.Kind);
        Assert.Equal("loader.exe", record.Fields["applicationName"]);
        Assert.Equal(@"%USERPROFILE%\AppData\Local\loader.exe", record.Fields["applicationPath"]);
        Assert.Equal("redacted-path", record.Fields["identityForm"]);
        Assert.Equal(3, record.Fields.Count);
        Assert.DoesNotContain(record.Fields.Keys, key => key.Contains("user", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(record.Fields.Keys, key => key.Contains("remote", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(record.Fields.Keys, key => key.Contains("bytes", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(3, parsed.RecognizedRowCount);
        Assert.Equal(2, parsed.RecognizedIdentityCount);
        Assert.Equal(1, parsed.DroppedIdentityCount);
        Assert.Equal(1, parsed.OutOfWindowCount);
        Assert.False(parsed.Capped);
    }

    [Fact]
    public void EnforcesRecordCapAndRejectsDtd()
    {
        const string twoRows = """
            <Root>
              <Row><TimeStamp>2026-08-23T09:00:00Z</TimeStamp><ApplicationName>one.exe</ApplicationName></Row>
              <Row><TimeStamp>2026-08-23T09:01:00Z</TimeStamp><ApplicationName>two.exe</ApplicationName></Row>
            </Root>
            """;
        using var cappedStream = new MemoryStream(Encoding.UTF8.GetBytes(twoRows));

        var capped = SrumApplicationUsageParser.Parse(
            cappedStream,
            Context(),
            new PathRedactor(@"C:\Users\Alice"),
            Context().ReviewWindowEndUtc,
            CancellationToken.None,
            maximumRecords: 1);

        Assert.Single(capped.Records);
        Assert.True(capped.Capped);

        const string withDtd = "<!DOCTYPE root [<!ENTITY x 'value'>]><root><Row><TimeStamp>2026-08-23T09:00:00Z</TimeStamp><AppId>&x;.exe</AppId></Row></root>";
        using var dtdStream = new MemoryStream(Encoding.UTF8.GetBytes(withDtd));
        Assert.Throws<XmlException>(() => SrumApplicationUsageParser.Parse(
            dtdStream,
            Context(),
            new PathRedactor(@"C:\Users\Alice"),
            Context().ReviewWindowEndUtc,
            CancellationToken.None));
    }

    private static CollectionContext Context()
    {
        var end = new DateTimeOffset(2026, 8, 23, 10, 0, 0, TimeSpan.Zero);
        return new CollectionContext("case-srum", end.AddHours(-2), end, end, "test");
    }
}
