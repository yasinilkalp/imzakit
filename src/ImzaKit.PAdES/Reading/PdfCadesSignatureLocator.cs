using System.Globalization;
using System.Text;

namespace ImzaKit.PAdES.Reading;

internal static class PdfCadesSignatureLocator
{
    private const string CadesSubFilter = "/SubFilter /ETSI.CAdES.detached";
    private const string ByteRangeMarker = "/ByteRange [";

    internal static bool TryRead(
        ReadOnlySpan<byte> pdf,
        out long[] byteRange,
        out byte[] cms,
        out int contentsOffset,
        out int contentsLength)
    {
        byteRange = [];
        cms = [];
        contentsOffset = 0;
        contentsLength = 0;
        string text = Encoding.ASCII.GetString(pdf);
        int subFilter = text.LastIndexOf(CadesSubFilter, StringComparison.Ordinal);
        if (subFilter < 0)
        {
            return false;
        }

        int dictionaryStart = text.LastIndexOf("<<", subFilter, StringComparison.Ordinal);
        int markerIndex = dictionaryStart < 0
            ? -1
            : text.IndexOf(ByteRangeMarker, dictionaryStart, StringComparison.Ordinal);
        if (markerIndex < 0
            || !TryReadByteRange(text, markerIndex + ByteRangeMarker.Length, out byteRange)
            || !TryValidateByteRange(pdf.Length, byteRange, out int firstLength, out int secondOffset, out _))
        {
            return false;
        }

        contentsLength = secondOffset - firstLength;
        if (contentsLength < 4
            || pdf[firstLength] != (byte)'<'
            || pdf[secondOffset - 1] != (byte)'>')
        {
            return false;
        }

        byte[] paddedCms;
        try
        {
            paddedCms = Convert.FromHexString(
                Encoding.ASCII.GetString(pdf.Slice(firstLength + 1, contentsLength - 2)));
        }
        catch (FormatException)
        {
            return false;
        }

        if (!TryReadDerLength(paddedCms, out int cmsLength))
        {
            return false;
        }

        cms = paddedCms[..cmsLength];
        contentsOffset = firstLength;
        return true;
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
