using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class BinaryEntropyTests
{
    [Fact]
    public void ReportsZeroForUniformInput()
    {
        var entropy = new BinaryEntropy();
        entropy.Append(new byte[1024]);

        Assert.Equal(0d, entropy.CalculateBitsPerByte());
        Assert.Equal("ordinary", BinaryEntropy.Classify(entropy.CalculateBitsPerByte()));
    }

    [Fact]
    public void ReportsEightBitsForEvenByteDistribution()
    {
        var entropy = new BinaryEntropy();
        entropy.Append(Enumerable.Range(0, 256).Select(value => (byte)value).ToArray());

        Assert.Equal(8d, entropy.CalculateBitsPerByte(), precision: 10);
        Assert.Equal("high", BinaryEntropy.Classify(entropy.CalculateBitsPerByte()));
    }
}
