using System.Text;
using ImzaKit.Core.Cryptography;
using ImzaKit.Cryptography.Digests;

namespace ImzaKit.Cryptography.Tests;

public sealed class DefaultDigestCalculatorTests
{
    [Fact]
    public void CalculateProducesKnownSha256Digest()
    {
        DefaultDigestCalculator calculator = new();

        byte[] digest = calculator.Calculate(
            HashAlgorithmId.Sha256,
            Encoding.ASCII.GetBytes("abc"));

        Assert.Equal(
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            Convert.ToHexString(digest));
    }

    [Fact]
    public void CalculateRejectsUnsupportedAlgorithmValue()
    {
        DefaultDigestCalculator calculator = new();

        NotSupportedException exception = Assert.Throws<NotSupportedException>(() =>
            calculator.Calculate((HashAlgorithmId)999, [0x01]));

        Assert.Contains("999", exception.Message, StringComparison.Ordinal);
    }
}
