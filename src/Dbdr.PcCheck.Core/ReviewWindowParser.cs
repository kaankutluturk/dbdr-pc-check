using System.Globalization;
using System.Text.RegularExpressions;

namespace Dbdr.PcCheck.Core;

public static partial class ReviewWindowParser
{
    private static readonly string[] UtcPartFormats =
    [
        "yyyy-MM-dd HH:mm",
        "yyyy-MM-dd H:mm",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd H:mm:ss",
    ];

    public static bool TryParseUtc(string? value, out DateTimeOffset timestampUtc)
    {
        timestampUtc = default;
        if (string.IsNullOrWhiteSpace(value) || !ExplicitOffset().IsMatch(value.Trim()))
        {
            return false;
        }

        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            return false;
        }

        timestampUtc = parsed.ToUniversalTime();
        return true;
    }

    public static bool TryParseUtcParts(
        string? date,
        string? time,
        out DateTimeOffset timestampUtc)
    {
        timestampUtc = default;
        if (string.IsNullOrWhiteSpace(date) || string.IsNullOrWhiteSpace(time))
        {
            return false;
        }

        var combined = $"{date.Trim()} {time.Trim()}";
        if (!DateTime.TryParseExact(
                combined,
                UtcPartFormats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces,
                out var parsed))
        {
            return false;
        }

        timestampUtc = new DateTimeOffset(DateTime.SpecifyKind(parsed, DateTimeKind.Utc));
        return true;
    }

    public static bool IsOrdered(DateTimeOffset startUtc, DateTimeOffset endUtc) => startUtc < endUtc;

    [GeneratedRegex(@"(?:Z|[+-]\d{2}:\d{2})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExplicitOffset();
}
