using ImzaKit.Cms.Completion;
using ImzaKit.Core.Signing;
using ImzaKit.PAdES.Preparation;

namespace ImzaKit.PAdES.Completion;

public static class PadesSignatureCompleter
{
    public static byte[] Complete(
        PadesSignaturePreparation preparation,
        SignatureCompletion completion,
        ReadOnlySpan<byte> signingCertificateDer)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(completion);

        byte[] cms = CmsSignedDataCompleter.CompleteDetached(
            preparation.SignaturePreparation,
            completion,
            signingCertificateDer);

        return preparation.Placeholder.EmbedSignature(cms);
    }
}
