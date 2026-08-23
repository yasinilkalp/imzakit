using ImzaKit.Core.Cryptography;

namespace ImzaKit.Cryptography.Digests;

public interface IDigestCalculator
{
    byte[] Calculate(HashAlgorithmId algorithm, ReadOnlySpan<byte> data);
}
