namespace Dbdr.PcCheck.Core;

public sealed class BinaryEntropy
{
    private readonly long[] _frequencies = new long[256];

    public long BytesObserved { get; private set; }

    public void Append(ReadOnlySpan<byte> bytes)
    {
        foreach (var value in bytes)
        {
            _frequencies[value]++;
        }

        BytesObserved += bytes.Length;
    }

    public double CalculateBitsPerByte()
    {
        if (BytesObserved == 0)
        {
            return 0;
        }

        var entropy = 0d;
        foreach (var frequency in _frequencies)
        {
            if (frequency == 0)
            {
                continue;
            }

            var probability = (double)frequency / BytesObserved;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    public static string Classify(double bitsPerByte) => bitsPerByte switch
    {
        >= 7.2 => "high",
        >= 6.0 => "elevated",
        _ => "ordinary",
    };
}
