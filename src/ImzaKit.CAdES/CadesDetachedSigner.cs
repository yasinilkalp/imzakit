using ImzaKit.Cms.Completion;
using ImzaKit.Core.Signing;

namespace ImzaKit.CAdES;

public static class CadesDetachedSigner
{
    public static byte[] SignDetached(
        SignaturePreparation preparation,
        SignatureCompletion completion,
        ReadOnlySpan<byte> signingCertificateDer,
        ReadOnlySpan<byte> signatureTimeStampToken = default)
    {
        return CmsSignedDataCompleter.CompleteDetached(
            preparation,
            completion,
            signingCertificateDer,
            signatureTimeStampToken);
    }

    public static byte[] AddSigner(
        ReadOnlySpan<byte> cms,
        SignaturePreparation preparation,
        SignatureCompletion completion,
        ReadOnlySpan<byte> signingCertificateDer)
    {
        return CmsSignedDataCompleter.AddDetachedSigner(
            cms,
            preparation,
            completion,
            signingCertificateDer);
    }
}
