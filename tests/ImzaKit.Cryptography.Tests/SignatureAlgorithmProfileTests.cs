using ImzaKit.Core.Cryptography;

namespace ImzaKit.Cryptography.Tests;

public sealed class SignatureAlgorithmProfileTests
{
    [Fact]
    public void RsaSha256KeepsHashAndKeyAlgorithmsSeparate()
    {
        SignatureAlgorithmProfile profile = SignatureAlgorithmProfile.RsaSha256;

        Assert.Equal(HashAlgorithmId.Sha256, profile.HashAlgorithm);
        Assert.Equal(KeyAlgorithmId.Rsa, profile.KeyAlgorithm);
    }
}
