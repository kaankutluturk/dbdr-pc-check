using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class AmcacheExecutionHistorySourceTests
{
    [Fact]
    public void NormalizesExecutableInventoryAndRedactsUserDirectory()
    {
        var redactor = new PathRedactor(@"D:\Profiles\Different");
        var fields = new Dictionary<string, string?>
        {
            ["Name"] = "loader.exe",
            ["LowerCaseLongPath"] = @"C:\Users\PrivateName\Downloads\loader.exe",
            ["Publisher"] = "Example Publisher",
            ["ProductName"] = "Example Product",
            ["ProductVersion"] = "1.2.3",
            ["Size"] = "4096",
            ["LinkDate"] = "2026-08-21T10:11:12Z",
        };

        var record = AmcacheExecutionHistorySource.CreateRecord(redactor, fields);

        Assert.Equal("execution.amcache", record.Kind);
        Assert.Null(record.SourceTimestampUtc);
        Assert.Equal(@"%USERPROFILE%\Downloads\loader.exe", record.Fields["executablePath"]);
        Assert.Equal("loader.exe", record.Fields["fileName"]);
        Assert.DoesNotContain("PrivateName", string.Join('|', record.Fields.Values), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not an execution time", record.Fields["timestampBasis"], StringComparison.OrdinalIgnoreCase);
    }
}
