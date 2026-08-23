using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace ImzaKit.Verify.Validation;

public static class PadesValidator
{
    private const int MaximumPdfSize = 32 * 1024 * 1024;
    private const string ByteRangeMarker = "/ByteRange [";

    public static PadesValidationReport Validate(ReadOnlySpan<byte> pdf)
    {
        if (!pdf.StartsWith("%PDF-"u8))
        {
            return FailedByteRange("UnsupportedPdf", "The input does not have a supported PDF header.");
        }

        if (pdf.Length > MaximumPdfSize)
        {
            return FailedByteRange("PdfTooLarge", "PDF exceeds the verification size limit.");
        }

        string text = Encoding.ASCII.GetString(pdf);
        int markerIndex = text.LastIndexOf(ByteRangeMarker, StringComparison.Ordinal);
        if (markerIndex < 0)
        {
            return new(
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                null,
                [new("SignatureNotFound", "No PDF signature ByteRange was found.")]);
        }

        if (!TryReadByteRange(text, markerIndex + ByteRangeMarker.Length, out long[] range)
            || !TryValidateByteRange(pdf, range, out int firstLength, out int secondOffset, out int secondLength))
        {
            return FailedByteRange("InvalidByteRange", "The PDF signature ByteRange is malformed or outside the document.");
        }

        int contentsLength = secondOffset - firstLength;
        ReadOnlySpan<byte> contents = pdf.Slice(firstLength, contentsLength);
        if (contentsLength < 4 || contents[0] != '<' || contents[^1] != '>')
        {
            return FailedByteRange("InvalidByteRange", "The ByteRange gap is not a hexadecimal CMS container.");
        }

        byte[] paddedCms;
        try
        {
            paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(contents[1..^1]));
        }
        catch (FormatException)
        {
            return FailedByteRange("InvalidByteRange", "The CMS container is not valid hexadecimal data.");
        }

        if (!TryReadDerLength(paddedCms, out int cmsLength))
        {
            return FailedCrypto("InvalidCms", "The signature container is not valid DER-encoded CMS data.");
        }

        byte[] signedBytes = new byte[firstLength + secondLength];
        pdf[..firstLength].CopyTo(signedBytes);
        pdf.Slice(secondOffset, secondLength).CopyTo(signedBytes.AsSpan(firstLength));

        try
        {
            SignedCms cms = new(new ContentInfo(signedBytes), detached: true);
            cms.Decode(paddedCms.AsSpan(0, cmsLength));
            cms.CheckSignature(verifySignatureOnly: true);
            System.Security.Cryptography.X509Certificates.X509Certificate2? certificate =
                cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].Certificate : null;
            string? fingerprint = certificate is null
                ? null
                : Convert.ToHexString(SHA256.HashData(certificate.RawData));
            List<ValidationFinding> findings = [new("TrustNotEvaluated", "Certificate trust and revocation were not evaluated.")];
            if (fingerprint is null)
            {
                findings.Insert(0, new("SignerCertificateMissing", "The signer certificate is not embedded in the CMS container."));
            }

            return new(
                ValidationStatus.Indeterminate,
                ValidationStatus.Passed,
                ValidationStatus.Passed,
                ValidationStatus.Indeterminate,
                fingerprint,
                findings);
        }
        catch (CryptographicException)
        {
            return FailedCrypto("CmsSignatureInvalid", "The CMS signature does not match the signed PDF bytes.");
        }
    }

    public static PadesValidationReport Validate(ReadOnlySpan<byte> pdf, ValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        PadesValidationService service = new(
            new ImzaKit.Certificate.Building.CertificateChainBuilder(),
            new ImzaKit.Certificate.Validation.CertificateChainValidator(),
            new ImzaKit.Trust.Evaluation.TrustPolicyEvaluator(),
            new ImzaKit.Revocation.Evaluation.OfflineRevocationEvaluator(
                new ImzaKit.Revocation.Parsing.BouncyCastleRevocationEvidenceParser()),
            new ValidationDecisionEngine());
        return service.Validate(pdf, context);
    }

    private static bool TryReadByteRange(string text, int start, out long[] values)
    {
        values = new long[4];
        int index = start;
        for (int item = 0; item < values.Length; item++)
        {
            while (index < text.Length && char.IsWhiteSpace(text[index])) index++;
            int numberStart = index;
            while (index < text.Length && char.IsAsciiDigit(text[index])) index++;
            if (numberStart == index
                || !long.TryParse(text.AsSpan(numberStart, index - numberStart), NumberStyles.None, CultureInfo.InvariantCulture, out values[item]))
            {
                return false;
            }
        }

        while (index < text.Length && char.IsWhiteSpace(text[index])) index++;
        return index < text.Length && text[index] == ']';
    }

    private static bool TryValidateByteRange(
        ReadOnlySpan<byte> pdf,
        long[] range,
        out int firstLength,
        out int secondOffset,
        out int secondLength)
    {
        firstLength = secondOffset = secondLength = 0;
        if (range[0] != 0 || range.Any(value => value > int.MaxValue)) return false;
        firstLength = (int)range[1];
        secondOffset = (int)range[2];
        secondLength = (int)range[3];
        return firstLength >= 0
            && secondOffset > firstLength
            && secondLength >= 0
            && secondOffset <= pdf.Length
            && secondLength <= pdf.Length - secondOffset
            && secondOffset + secondLength == pdf.Length;
    }

    private static bool TryReadDerLength(ReadOnlySpan<byte> encoded, out int totalLength)
    {
        totalLength = 0;
        if (encoded.Length < 2 || encoded[0] != 0x30) return false;
        int firstLengthByte = encoded[1];
        if ((firstLengthByte & 0x80) == 0)
        {
            totalLength = 2 + firstLengthByte;
            return totalLength <= encoded.Length;
        }

        int lengthByteCount = firstLengthByte & 0x7F;
        if (lengthByteCount is 0 or > 4 || encoded.Length < 2 + lengthByteCount) return false;
        int contentLength = 0;
        for (int index = 0; index < lengthByteCount; index++)
        {
            if (contentLength > (int.MaxValue >> 8)) return false;
            contentLength = (contentLength << 8) | encoded[2 + index];
        }

        totalLength = 2 + lengthByteCount + contentLength;
        return totalLength <= encoded.Length;
    }

    private static PadesValidationReport FailedByteRange(string code, string message) =>
        new(ValidationStatus.Failed, ValidationStatus.Failed, ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate, null, [new(code, message)]);

    private static PadesValidationReport FailedCrypto(string code, string message) =>
        new(ValidationStatus.Failed, ValidationStatus.Passed, ValidationStatus.Failed,
            ValidationStatus.Indeterminate, null, [new(code, message)]);
}
