using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class ReviewWindowParserTests
{
    [Theory]
    [InlineData("2026-08-10T14:30:00Z", "2026-08-10T14:30:00+00:00")]
    [InlineData("2026-08-10T16:30:00+02:00", "2026-08-10T14:30:00+00:00")]
    [InlineData("2026-08-10 14:30:00Z", "2026-08-10T14:30:00+00:00")]
    public void ParsesExplicitOffsetsAsUtc(string input, string expected)
    {
        Assert.True(ReviewWindowParser.TryParseUtc(input, out var timestamp));
        Assert.Equal(DateTimeOffset.Parse(expected, System.Globalization.CultureInfo.InvariantCulture), timestamp);
    }

    [Theory]
    [InlineData("")]
    [InlineData("2026-08-10T14:30:00")]
    [InlineData("not-a-date")]
    public void RejectsMissingOrInvalidOffsets(string input)
    {
        Assert.False(ReviewWindowParser.TryParseUtc(input, out _));
    }

    [Fact]
    public void RequiresStartBeforeEnd()
    {
        var start = DateTimeOffset.Parse("2026-08-10T14:30:00Z", System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(ReviewWindowParser.IsOrdered(start, start.AddSeconds(1)));
        Assert.False(ReviewWindowParser.IsOrdered(start, start));
        Assert.False(ReviewWindowParser.IsOrdered(start, start.AddSeconds(-1)));
    }
}
