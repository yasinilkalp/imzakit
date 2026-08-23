using System.Security.Cryptography;
using ImzaKit.Core.Cryptography;

namespace ImzaKit.Cryptography.Digests;

public sealed class DefaultDigestCalculator : IDigestCalculator
{
    public byte[] Calculate(HashAlgorithmId algorithm, ReadOnlySpan<byte> data) =>
        algorithm switch
        {
            HashAlgorithmId.Sha256 => SHA256.HashData(data),
            _ => throw new NotSupportedException($"Hash algorithm value '{(int)algorithm}' is not supported.")
        };
}
