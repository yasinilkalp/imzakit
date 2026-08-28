using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

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

internal static class PdfCadesSignatureReader
{
    private const string CadesSubFilter = "/SubFilter /ETSI.CAdES.detached";
    private const string ByteRangeMarker = "/ByteRange [";
    private const string SignatureTimeStampOid = "1.2.840.113549.1.9.16.2.14";

    internal static PdfCadesReadStatus TryRead(
        ReadOnlySpan<byte> pdf,
        out long[] byteRange,
        out byte[] cms,
        out byte[] signedBytes)
    {
        IReadOnlyList<PdfCadesLocatedSignature> signatures = ReadAll(pdf);
        if (signatures.Count == 0)
        {
            byteRange = [];
            cms = [];
            signedBytes = [];
            return PdfCadesReadStatus.NotFound;
        }

        PdfCadesLocatedSignature last = signatures[^1];
        byteRange = last.ByteRange;
        cms = last.Cms;
        signedBytes = last.SignedBytes;
        return last.Status;
    }

    internal static IReadOnlyList<PdfCadesLocatedSignature> ReadAll(ReadOnlySpan<byte> pdf)
    {
        string text = Encoding.ASCII.GetString(pdf);
        List<PdfCadesLocatedSignature> signatures = [];
        int search = 0;
        while (true)
        {
            int subFilter = text.IndexOf(CadesSubFilter, search, StringComparison.Ordinal);
            if (subFilter < 0)
            {
                break;
            }

            search = subFilter + CadesSubFilter.Length;
            signatures.Add(ReadOne(pdf, text, subFilter));
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

    internal static string DetectLevel(ReadOnlySpan<byte> pdf, SignedCms cms)
    {
        string text = Encoding.ASCII.GetString(pdf);
        bool hasTimestamp = HasSignatureTimeStamp(cms);
        bool hasDss = text.Contains("/Type /DSS", StringComparison.Ordinal);
        bool hasDocTimeStamp = text.Contains("/Type /DocTimeStamp", StringComparison.Ordinal)
            && text.Contains("/SubFilter /ETSI.RFC3161", StringComparison.Ordinal);
        return (hasTimestamp, hasDss, hasDocTimeStamp) switch
        {
            (true, true, true) => PadesBaselineLevel.BLTA,
            (true, true, false) => PadesBaselineLevel.BLT,
            (true, false, _) => PadesBaselineLevel.BT,
            _ => PadesBaselineLevel.BB
        };
    }

    private static PdfCadesLocatedSignature ReadOne(ReadOnlySpan<byte> pdf, string text, int subFilter)
    {
        string? fieldName = ReadFieldName(text, subFilter);
        int dictionaryStart = text.LastIndexOf("<<", subFilter, StringComparison.Ordinal);
        int markerIndex = dictionaryStart < 0
            ? -1
            : text.IndexOf(ByteRangeMarker, dictionaryStart, StringComparison.Ordinal);
        if (markerIndex < 0
            || !TryReadByteRange(text, markerIndex + ByteRangeMarker.Length, out long[] byteRange)
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

    private static bool HasSignatureTimeStamp(SignedCms cms)
    {
        if (cms.SignerInfos.Count == 0)
        {
            return false;
        }

        foreach (CryptographicAttributeObject attribute in cms.SignerInfos[0].UnsignedAttributes)
        {
            if (attribute.Oid?.Value == SignatureTimeStampOid)
            {
                return true;
            }
        }

        return false;
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
}
