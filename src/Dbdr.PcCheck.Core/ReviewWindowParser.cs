using System.Globalization;
using System.Text.RegularExpressions;

namespace Dbdr.PcCheck.Core;

public static partial class ReviewWindowParser
{
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

    public static bool IsOrdered(DateTimeOffset startUtc, DateTimeOffset endUtc) => startUtc < endUtc;

    [GeneratedRegex(@"(?:Z|[+-]\d{2}:\d{2})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExplicitOffset();
}
