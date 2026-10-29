using System.Globalization;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.RegularExpressions;
using ImzaKit.CAdES;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.Verify.Validation;

internal enum PdfCadesReadStatus
{
    NotFound,
    InvalidByteRange,
    InvalidCms,
    Success
}

internal sealed record PdfCadesLocatedSignature(
    PdfCadesReadStatus Status,
    long[] ByteRange,
    byte[] Cms,
    byte[] SignedBytes,
    int CoveredLength,
    string? FieldName);

internal static partial class PdfCadesSignatureReader
{
    internal static IReadOnlyList<PdfCadesLocatedSignature> ReadAll(ReadOnlySpan<byte> pdf) =>
        ReadAll(pdf, CadesSubFilter());

    internal static IReadOnlyList<PdfCadesLocatedSignature> ReadDocumentTimeStamps(ReadOnlySpan<byte> pdf) =>
        ReadAll(pdf, DocumentTimeStampSubFilter());

    private static IReadOnlyList<PdfCadesLocatedSignature> ReadAll(ReadOnlySpan<byte> pdf, Regex subFilter)
    {
        string text = Encoding.ASCII.GetString(pdf);
        List<PdfCadesLocatedSignature> signatures = [];
        foreach (Match match in subFilter.Matches(text))
        {
            signatures.Add(ReadOne(pdf, text, match.Index));
        }

        return [.. signatures.OrderBy(signature => signature.CoveredLength)
            .ThenBy(signature => signature.FieldName, StringComparer.Ordinal)];
    }

    internal static int CountCoveredRevisions(ReadOnlySpan<byte> pdf, int coveredLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(coveredLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(coveredLength, pdf.Length);
        string text = Encoding.ASCII.GetString(pdf[..coveredLength]);
        int count = 0;
        int index = 0;
        while ((index = text.IndexOf("%%EOF", index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += 5;
        }

        return count;
    }

    // Time-stamps only count towards a level when their tokens verify: the signature time-stamp
    // over this signature value, and every document time-stamp over its own ByteRange. When a trust
    // check is given, each time-stamp authority must also pass it.
    internal static string DetectLevel(
        ReadOnlySpan<byte> pdf,
        SignedCms cms,
        List<ValidationFinding> findings,
        Predicate<Rfc3161TimeStampTokenVerification>? isAuthorityTrusted = null)
    {
        string text = Encoding.ASCII.GetString(pdf);
        Rfc3161TimeStampTokenVerification? signatureTimeStamp = cms.SignerInfos.Count == 0
            ? null
            : CadesSignatureTimeStampVerifier.Verify(cms.SignerInfos[0]);
        if (signatureTimeStamp is { IsValid: false })
        {
            findings.Add(new(
                "SignatureTimeStampInvalid",
                $"The signature time-stamp does not verify ({signatureTimeStamp.FailureCode})."));
        }

        bool hasTimestamp = signatureTimeStamp is { IsValid: true }
            && IsAuthorityTrusted(signatureTimeStamp, isAuthorityTrusted, "signature", findings);
        bool hasDss = DssDictionary().IsMatch(text);
        bool hasDocTimeStamp = HasValidDocumentTimeStamps(pdf, findings, isAuthorityTrusted);
        return (hasTimestamp, hasDss, hasDocTimeStamp) switch
        {
            (true, true, true) => PadesBaselineLevel.BLTA,
            (true, true, false) => PadesBaselineLevel.BLT,
            (true, false, _) => PadesBaselineLevel.BT,
            _ => PadesBaselineLevel.BB
        };
    }

    private static bool HasValidDocumentTimeStamps(
        ReadOnlySpan<byte> pdf,
        List<ValidationFinding> findings,
        Predicate<Rfc3161TimeStampTokenVerification>? isAuthorityTrusted)
    {
        IReadOnlyList<PdfCadesLocatedSignature> timeStamps = ReadDocumentTimeStamps(pdf);
        foreach (PdfCadesLocatedSignature timeStamp in timeStamps)
        {
            Rfc3161TimeStampTokenVerification verification = timeStamp.Status != PdfCadesReadStatus.Success
                ? new(false, "IMZAKIT.TS.TOKEN_MALFORMED", null)
                : Rfc3161TimeStampTokenVerifier.Verify(timeStamp.Cms, timeStamp.SignedBytes);
            if (!verification.IsValid)
            {
                findings.Add(new(
                    "DocumentTimeStampInvalid",
                    $"A document time-stamp does not verify over its ByteRange ({verification.FailureCode})."));
                return false;
            }

            if (!IsAuthorityTrusted(verification, isAuthorityTrusted, "document", findings))
            {
                return false;
            }
        }

        return timeStamps.Count > 0;
    }

    private static bool IsAuthorityTrusted(
        Rfc3161TimeStampTokenVerification timeStamp,
        Predicate<Rfc3161TimeStampTokenVerification>? isAuthorityTrusted,
        string kind,
        List<ValidationFinding> findings)
    {
        if (isAuthorityTrusted is null || isAuthorityTrusted(timeStamp))
        {
            return true;
        }

        findings.Add(new(
            "TimeStampAuthorityUntrusted",
            $"The {kind} time-stamp authority does not chain to a trust anchor enabled for this profile."));
        return false;
    }

    private static PdfCadesLocatedSignature ReadOne(ReadOnlySpan<byte> pdf, string text, int subFilter)
    {
        string? fieldName = ReadFieldName(text, subFilter);
        int dictionaryStart = text.LastIndexOf("<<", subFilter, StringComparison.Ordinal);
        Match marker = dictionaryStart < 0 ? Match.Empty : ByteRangeMarker().Match(text, dictionaryStart);
        if (!marker.Success
            || !TryReadByteRange(text, marker.Index + marker.Length, out long[] byteRange)
            || !TryValidateByteRange(pdf.Length, byteRange, out int firstLength, out int secondOffset, out int secondLength))
        {
            return new(PdfCadesReadStatus.InvalidByteRange, [], [], [], pdf.Length, fieldName);
        }

        int coveredLength = checked((int)(byteRange[2] + byteRange[3]));
        int contentsLength = secondOffset - firstLength;
        if (contentsLength < 4
            || pdf[firstLength] != (byte)'<'
            || pdf[secondOffset - 1] != (byte)'>')
        {
            return new(PdfCadesReadStatus.InvalidByteRange, byteRange, [], [], coveredLength, fieldName);
        }

        byte[] paddedCms;
        try
        {
            paddedCms = Convert.FromHexString(
                Encoding.ASCII.GetString(pdf.Slice(firstLength + 1, contentsLength - 2)));
        }
        catch (FormatException)
        {
            return new(PdfCadesReadStatus.InvalidByteRange, byteRange, [], [], coveredLength, fieldName);
        }

        if (!TryReadDerLength(paddedCms, out int cmsLength))
        {
            return new(PdfCadesReadStatus.InvalidCms, byteRange, [], [], coveredLength, fieldName);
        }

        byte[] cms = paddedCms[..cmsLength];
        byte[] signedBytes = new byte[firstLength + secondLength];
        pdf[..firstLength].CopyTo(signedBytes);
        pdf.Slice(secondOffset, secondLength).CopyTo(signedBytes.AsSpan(firstLength));
        return new(PdfCadesReadStatus.Success, byteRange, cms, signedBytes, coveredLength, fieldName);
    }

    private static string? ReadFieldName(string text, int subFilter)
    {
        int windowEnd = text.IndexOf("%%EOF", subFilter, StringComparison.Ordinal);
        if (windowEnd < 0)
        {
            windowEnd = text.Length;
        }

        int nameToken = text.IndexOf("/T (", subFilter, StringComparison.Ordinal);
        if (nameToken < 0 || nameToken >= windowEnd)
        {
            return null;
        }

        int nameStart = nameToken + 4;
        int nameEnd = text.IndexOf(')', nameStart);
        return nameEnd < 0 || nameEnd > windowEnd ? null : text[nameStart..nameEnd];
    }

    private static bool TryReadByteRange(string text, int start, out long[] values)
    {
        values = new long[4];
        int index = start;
        for (int item = 0; item < values.Length; item++)
        {
            while (index < text.Length && char.IsWhiteSpace(text[index]))
            {
                index++;
            }

            int numberStart = index;
            while (index < text.Length && char.IsAsciiDigit(text[index]))
            {
                index++;
            }

            if (numberStart == index
                || !long.TryParse(
                    text.AsSpan(numberStart, index - numberStart),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out values[item]))
            {
                return false;
            }
        }

        while (index < text.Length && char.IsWhiteSpace(text[index]))
        {
            index++;
        }

        return index < text.Length && text[index] == ']';
    }

    private static bool TryValidateByteRange(
        int pdfLength,
        long[] range,
        out int firstLength,
        out int secondOffset,
        out int secondLength)
    {
        firstLength = secondOffset = secondLength = 0;
        if (range[0] != 0 || range.Any(value => value > int.MaxValue))
        {
            return false;
        }

        firstLength = (int)range[1];
        secondOffset = (int)range[2];
        secondLength = (int)range[3];
        return firstLength >= 0
            && secondOffset > firstLength
            && secondLength >= 0
            && secondOffset <= pdfLength
            && secondLength <= pdfLength - secondOffset
            && secondOffset + secondLength <= pdfLength;
    }

    private static bool TryReadDerLength(ReadOnlySpan<byte> encoded, out int totalLength)
    {
        totalLength = 0;
        if (encoded.Length < 2 || encoded[0] != 0x30)
        {
            return false;
        }

        int firstLengthByte = encoded[1];
        if ((firstLengthByte & 0x80) == 0)
        {
            totalLength = 2 + firstLengthByte;
            return totalLength <= encoded.Length;
        }

        int lengthByteCount = firstLengthByte & 0x7F;
        if (lengthByteCount is 0 or > 4 || encoded.Length < 2 + lengthByteCount)
        {
            return false;
        }

        int contentLength = 0;
        for (int index = 0; index < lengthByteCount; index++)
        {
            if (contentLength > (int.MaxValue >> 8))
            {
                return false;
            }

            contentLength = (contentLength << 8) | encoded[2 + index];
        }

        totalLength = 2 + lengthByteCount + contentLength;
        return totalLength <= encoded.Length;
    }

    [GeneratedRegex(@"/SubFilter\s*/ETSI\.CAdES\.detached\b")]
    private static partial Regex CadesSubFilter();

    [GeneratedRegex(@"/SubFilter\s*/ETSI\.RFC3161\b")]
    private static partial Regex DocumentTimeStampSubFilter();

    [GeneratedRegex(@"/ByteRange\s*\[")]
    private static partial Regex ByteRangeMarker();

    [GeneratedRegex(@"/Type\s*/DSS\b")]
    private static partial Regex DssDictionary();
}
