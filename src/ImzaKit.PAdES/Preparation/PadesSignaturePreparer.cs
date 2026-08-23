using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.PAdES.Incremental;

namespace ImzaKit.PAdES.Preparation;

public sealed class PadesSignaturePreparer
{
    private readonly CmsSignaturePreparer cmsSignaturePreparer;

    public PadesSignaturePreparer(CmsSignaturePreparer cmsSignaturePreparer)
    {
        ArgumentNullException.ThrowIfNull(cmsSignaturePreparer);
        this.cmsSignaturePreparer = cmsSignaturePreparer;
    }

    public PadesSignaturePreparation Prepare(
        Guid operationId,
        string documentSha256,
        byte[] originalPdf,
        int cmsCapacity,
        ReadOnlySpan<byte> signingCertificateDer,
        string certificateFingerprintSha256,
        int prepareVersion)
    {
        PdfSignaturePlaceholder placeholder =
            PdfIncrementalSignatureWriter.Prepare(originalPdf, cmsCapacity);
        SignaturePreparation signaturePreparation = cmsSignaturePreparer.PrepareDetached(
            operationId,
            documentSha256,
            placeholder.GetSignableBytes(),
            signingCertificateDer,
            certificateFingerprintSha256,
            prepareVersion);

        return new PadesSignaturePreparation(placeholder, signaturePreparation);
    }
}
