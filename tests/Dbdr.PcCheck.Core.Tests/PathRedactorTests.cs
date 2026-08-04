using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class PathRedactorTests
{
    [Fact]
    public void ReplacesConfiguredUserProfile()
    {
        var redactor = new PathRedactor(@"C:\Users\Kaan");

        var result = redactor.Redact(@"C:\Users\Kaan\AppData\Local\tool.exe");

        Assert.Equal(@"%USERPROFILE%\AppData\Local\tool.exe", result);
    }

    [Fact]
    public void ReplacesUnknownWindowsUserDirectory()
    {
        var redactor = new PathRedactor(@"D:\Profiles\Different");

        var result = redactor.Redact(@"C:\Users\PrivateName\Downloads\sample.exe");

        Assert.Equal(@"%USERPROFILE%\Downloads\sample.exe", result);
    }
}
