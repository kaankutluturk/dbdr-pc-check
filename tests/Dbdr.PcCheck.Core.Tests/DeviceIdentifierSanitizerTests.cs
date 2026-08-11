using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class DeviceIdentifierSanitizerTests
{
    [Theory]
    [InlineData(@"USB\VID_1234&PID_ABCD\SERIAL-SECRET", "VID_1234&PID_ABCD")]
    [InlineData(@"PCI\VEN_8086&DEV_1234&SUBSYS_00000000", "VEN_8086&DEV_1234")]
    public void KeepsModelIdentifierWithoutUniqueSuffix(string deviceId, string expected)
    {
        var result = DeviceIdentifierSanitizer.ExtractModelIdentifier(deviceId);

        Assert.Equal(expected, result);
        Assert.DoesNotContain("SECRET", result!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsNullWhenNoNonUniqueModelIdentifierExists()
    {
        Assert.Null(DeviceIdentifierSanitizer.ExtractModelIdentifier(@"SWD\PRINTENUM\UNIQUE"));
    }
}
