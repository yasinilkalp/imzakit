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
        byteRange = [];
        cms = [];
        signedBytes = [];
        string text = Encoding.ASCII.GetString(pdf);
        int subFilter = text.LastIndexOf(CadesSubFilter, StringComparison.Ordinal);
        if (subFilter < 0)
        {
            return PdfCadesReadStatus.NotFound;
        }

        int dictionaryStart = text.LastIndexOf("<<", subFilter, StringComparison.Ordinal);
        int markerIndex = dictionaryStart < 0
            ? -1
            : text.IndexOf(ByteRangeMarker, dictionaryStart, StringComparison.Ordinal);
        if (markerIndex < 0
            || !TryReadByteRange(text, markerIndex + ByteRangeMarker.Length, out byteRange)
            || !TryValidateByteRange(pdf.Length, byteRange, out int firstLength, out int secondOffset, out int secondLength))
        {
            return PdfCadesReadStatus.InvalidByteRange;
        }

        int contentsLength = secondOffset - firstLength;
        if (contentsLength < 4
            || pdf[firstLength] != (byte)'<'
            || pdf[secondOffset - 1] != (byte)'>')
        {
            return PdfCadesReadStatus.InvalidByteRange;
        }

        byte[] paddedCms;
        try
        {
            paddedCms = Convert.FromHexString(
                Encoding.ASCII.GetString(pdf.Slice(firstLength + 1, contentsLength - 2)));
        }
        catch (FormatException)
        {
            return PdfCadesReadStatus.InvalidByteRange;
        }

        if (!TryReadDerLength(paddedCms, out int cmsLength))
        {
            return PdfCadesReadStatus.InvalidCms;
        }

        cms = paddedCms[..cmsLength];
        signedBytes = new byte[firstLength + secondLength];
        pdf[..firstLength].CopyTo(signedBytes);
        pdf.Slice(secondOffset, secondLength).CopyTo(signedBytes.AsSpan(firstLength));
        return PdfCadesReadStatus.Success;
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
