using System.Security.Cryptography;
using System.Text;
using ImzaKit.Cms.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Incremental;
using ImzaKit.PAdES.Reading;
using ImzaKit.Revocation.Online;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.PAdES.Completion;

public static class PadesSignatureExtender
{
    public static async Task<byte[]> ExtendAsync(
        byte[] signedPdf,
        string targetLevel,
        Rfc3161TimeStampClient? timeStampClient = null,
        IReadOnlyList<TimeStampAuthority>? authorities = null,
        PadesValidationMaterial? material = null,
        OnlineRevocationClient? revocationClient = null,
        DateTimeOffset? validationTimeUtc = null,
        int documentTimestampCapacity = 8192,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        int targetRank = Rank(targetLevel);
        string currentLevel = DetectLevel(signedPdf);
        int currentRank = Rank(currentLevel);
        if (targetRank <= currentRank)
        {
            throw new InvalidOperationException(
                $"Unsupported PAdES level transition from {currentLevel} to {targetLevel}.");
        }

        bool needsSignatureTimestamp = currentRank < Rank("B-T");
        bool needsDss = currentRank < Rank("B-LT") && targetRank >= Rank("B-LT");
        bool needsDocumentTimestamp = targetRank >= Rank("B-LTA");
        if ((needsSignatureTimestamp || needsDocumentTimestamp)
            && (timeStampClient is null || authorities is null || authorities.Count == 0))
        {
            throw new ArgumentException("A time-stamp authority is required for B-T and B-LTA extension.");
        }

        if (needsDss && material is null && revocationClient is null)
        {
            throw new ArgumentException("Validation material or an online revocation client is required to extend to B-LT or B-LTA.", nameof(material));
        }

        byte[] pdf = signedPdf;
        if (needsSignatureTimestamp)
        {
            pdf = await AddBaselineT(pdf, timeStampClient!, authorities!, cancellationToken)
                .ConfigureAwait(false);
        }

        if (needsDss)
        {
            PadesValidationMaterial resolved = revocationClient is null
                ? material!
                : await PadesLongTermEvidenceCollector.CollectAsync(
                    pdf,
                    revocationClient,
                    validationTimeUtc ?? DateTimeOffset.UtcNow,
                    material?.Certificates,
                    material?.OcspResponses,
                    material?.CertificateRevocationLists,
                    cancellationToken).ConfigureAwait(false);
            pdf = PadesSignatureCompleter.EmbedBaselineLt(pdf, resolved);
        }

        if (needsDocumentTimestamp)
        {
            pdf = await PadesSignatureCompleter.CompleteBaselineLta(
                pdf,
                timeStampClient!,
                authorities!,
                documentTimestampCapacity,
                cancellationToken).ConfigureAwait(false);
        }

        return pdf;
    }

    public static Task<byte[]> PreserveArchiveTimestampAsync(
        byte[] archivePdf,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        int documentTimestampCapacity = 8192,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(archivePdf);
        if (DetectLevel(archivePdf) != "B-LTA")
        {
            throw new InvalidOperationException("Archive timestamp preservation requires an existing B-LTA document.");
        }

        return PadesSignatureCompleter.CompleteBaselineLta(
            archivePdf,
            timeStampClient,
            authorities,
            documentTimestampCapacity,
            cancellationToken);
    }

    public static string DetectLevel(ReadOnlySpan<byte> pdf)
    {
        if (!PdfCadesSignatureLocator.TryRead(pdf, out _, out byte[] cms, out _, out _))
        {
            throw new ArgumentException("The PDF does not contain a PAdES CAdES signature.", nameof(pdf));
        }

        string text = Encoding.ASCII.GetString(pdf);
        bool hasTimestamp = CmsSignedDataCompleter.HasSignatureTimeStamp(cms);
        bool hasDss = text.Contains("/Type /DSS", StringComparison.Ordinal);
        bool hasDocTimeStamp = text.Contains("/Type /DocTimeStamp", StringComparison.Ordinal)
            && text.Contains("/SubFilter /ETSI.RFC3161", StringComparison.Ordinal);
        return (hasTimestamp, hasDss, hasDocTimeStamp) switch
        {
            (true, true, true) => "B-LTA",
            (true, true, false) => "B-LT",
            (true, false, _) => "B-T",
            _ => "B-B"
        };
    }

    private static async Task<byte[]> AddBaselineT(
        byte[] pdf,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken)
    {
        if (!PdfCadesSignatureLocator.TryRead(
                pdf,
                out long[] byteRange,
                out byte[] cms,
                out int contentsOffset,
                out int contentsLength))
        {
            throw new ArgumentException("The PDF does not contain a PAdES CAdES signature.", nameof(pdf));
        }

        byte[] imprint = SHA256.HashData(CmsSignedDataCompleter.ReadSignatureValue(cms));
        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            imprint,
            authorities,
            cancellationToken).ConfigureAwait(false);
        byte[] extendedCms = CmsSignedDataCompleter.AddSignatureTimeStamp(cms, timestamp.TokenDer);
        return new PdfSignaturePlaceholder(pdf, contentsOffset, contentsLength, byteRange)
            .EmbedSignature(extendedCms);
    }

    private static int Rank(string level) => level switch
    {
        "B-B" => 0,
        "B-T" => 1,
        "B-LT" => 2,
        "B-LTA" => 3,
        _ => throw new ArgumentException($"Unsupported PAdES target level '{level}'.", nameof(level))
    };
}
