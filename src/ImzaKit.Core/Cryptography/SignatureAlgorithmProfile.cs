namespace ImzaKit.Core.Cryptography;

public readonly record struct SignatureAlgorithmProfile(
    HashAlgorithmId HashAlgorithm,
    KeyAlgorithmId KeyAlgorithm)
{
    public static SignatureAlgorithmProfile RsaSha256 { get; } =
        new(HashAlgorithmId.Sha256, KeyAlgorithmId.Rsa);
}
