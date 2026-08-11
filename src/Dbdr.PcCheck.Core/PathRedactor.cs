using System.Text.RegularExpressions;

namespace Dbdr.PcCheck.Core;

public sealed partial class PathRedactor
{
    private readonly string? _userProfile;

    public PathRedactor(string? userProfile = null)
    {
        _userProfile = string.IsNullOrWhiteSpace(userProfile)
            ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            : userProfile;
    }

    public string? Redact(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var redacted = value;
        if (!string.IsNullOrWhiteSpace(_userProfile))
        {
            redacted = redacted.Replace(_userProfile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
        }

        redacted = DeviceUserPath().Replace(redacted, "%USERPROFILE%\\");
        return WindowsUserPath().Replace(redacted, "%USERPROFILE%\\");
    }

    [GeneratedRegex(@"(?i)[A-Z]:\\Users\\[^\\]+\\", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsUserPath();

    [GeneratedRegex(@"(?i)\\Device\\HarddiskVolume\d+\\Users\\[^\\]+\\", RegexOptions.CultureInvariant)]
    private static partial Regex DeviceUserPath();
}
