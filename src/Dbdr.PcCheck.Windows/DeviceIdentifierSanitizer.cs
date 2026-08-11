using System.Text.RegularExpressions;

namespace Dbdr.PcCheck.Windows;

public static partial class DeviceIdentifierSanitizer
{
    public static string? ExtractModelIdentifier(string? deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return null;
        }

        var match = HardwareModel().Match(deviceId);
        return match.Success ? match.Value.ToUpperInvariant() : null;
    }

    [GeneratedRegex(
        @"(?:VID_[0-9A-F]{4}&PID_[0-9A-F]{4}|VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4})",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HardwareModel();
}
