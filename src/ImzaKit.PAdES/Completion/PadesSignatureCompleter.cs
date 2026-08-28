using System.Security.Cryptography;
using ImzaKit.Cms.Completion;
using ImzaKit.Core.Signing;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Incremental;
using ImzaKit.PAdES.Lta;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.PAdES.Completion;

public static class PadesSignatureCompleter
{
    public static byte[] Complete(
        PadesSignaturePreparation preparation,
        SignatureCompletion completion,
        ReadOnlySpan<byte> signingCertificateDer,
        ReadOnlySpan<byte> signatureTimeStampToken = default)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(completion);

        byte[] cms = CmsSignedDataCompleter.CompleteDetached(
            preparation.SignaturePreparation,
            completion,
            signingCertificateDer,
            signatureTimeStampToken);

        return preparation.Placeholder.EmbedSignature(cms);
    }

    public static async Task<byte[]> CompleteBaselineT(
        PadesSignaturePreparation preparation,
        SignatureCompletion completion,
        byte[] signingCertificateDer,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(completion);
        ArgumentNullException.ThrowIfNull(signingCertificateDer);
        ArgumentNullException.ThrowIfNull(timeStampClient);
        ArgumentNullException.ThrowIfNull(authorities);

        byte[] imprint = SHA256.HashData(completion.SignatureValue.Span);
        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            imprint,
            authorities,
            cancellationToken).ConfigureAwait(false);

        return Complete(preparation, completion, signingCertificateDer, timestamp.TokenDer);
    }

    public static byte[] EmbedBaselineLt(byte[] signedPdf, PadesValidationMaterial material)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentNullException.ThrowIfNull(material);
        return PdfDocumentSecurityStoreWriter.Embed(signedPdf, material);
    }

    public static async Task<byte[]> CompleteBaselineLta(
        byte[] longTermPdf,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        int tokenCapacity = 8192,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(longTermPdf);
        ArgumentNullException.ThrowIfNull(timeStampClient);
        ArgumentNullException.ThrowIfNull(authorities);

        PdfSignaturePlaceholder placeholder = PdfDocumentTimestampWriter.Prepare(longTermPdf, tokenCapacity);
        byte[] imprint = SHA256.HashData(placeholder.GetSignableBytes());
        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            imprint,
            authorities,
            cancellationToken).ConfigureAwait(false);
        return placeholder.EmbedSignature(timestamp.TokenDer);
    }
}
