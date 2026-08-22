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

    [Theory]
    [InlineData("2026-08-22", "06:55", "2026-08-22T06:55:00+00:00")]
    [InlineData("2026-08-22", "6:55", "2026-08-22T06:55:00+00:00")]
    [InlineData("2026-08-22", "06:55:53", "2026-08-22T06:55:53+00:00")]
    public void ParsesSeparateUtcDateAndTimeFields(string date, string time, string expected)
    {
        Assert.True(ReviewWindowParser.TryParseUtcParts(date, time, out var timestamp));
        Assert.Equal(DateTimeOffset.Parse(expected, System.Globalization.CultureInfo.InvariantCulture), timestamp);
    }

    [Theory]
    [InlineData("", "06:55")]
    [InlineData("2026-08-22", "")]
    [InlineData("22-08-2026", "06:55")]
    [InlineData("2026-08-22", "25:00")]
    public void RejectsInvalidSeparateUtcFields(string date, string time)
    {
        Assert.False(ReviewWindowParser.TryParseUtcParts(date, time, out _));
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
