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

    [Fact]
    public void ReplacesUserDirectoryInNtDevicePath()
    {
        var redactor = new PathRedactor(@"D:\Profiles\Different");

        var result = redactor.Redact(@"\Device\HarddiskVolume3\Users\PrivateName\AppData\Local\sample.exe");

        Assert.Equal(@"%USERPROFILE%\AppData\Local\sample.exe", result);
    }
}
