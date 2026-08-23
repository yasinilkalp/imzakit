using ImzaKit.Cms.SignedAttributes;
using ImzaKit.Core.Cryptography;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;

namespace ImzaKit.Cms.Preparation;

public sealed class CmsSignaturePreparer
{
    private readonly IDigestCalculator digestCalculator;

    public CmsSignaturePreparer(IDigestCalculator digestCalculator)
    {
        ArgumentNullException.ThrowIfNull(digestCalculator);
        this.digestCalculator = digestCalculator;
    }

    public SignaturePreparation PrepareDetached(
        Guid operationId,
        string documentSha256,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signingCertificateDer,
        string certificateFingerprintSha256,
        int prepareVersion)
    {
        byte[] contentDigest = digestCalculator.Calculate(HashAlgorithmId.Sha256, content);
        byte[] certificateHash = digestCalculator.Calculate(HashAlgorithmId.Sha256, signingCertificateDer);
        byte[] signedAttributes = CmsSignedAttributesEncoder.EncodeSha256(
            contentDigest,
            certificateHash);

        return SignaturePreparation.Create(
            operationId,
            documentSha256,
            signedAttributes,
            SignatureAlgorithmProfile.RsaSha256,
            certificateFingerprintSha256,
            prepareVersion);
    }
}
