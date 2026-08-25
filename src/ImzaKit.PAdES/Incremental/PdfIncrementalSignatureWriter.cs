using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ImzaKit.PAdES.Appearance;
using ImzaKit.PAdES.Preflight;

namespace ImzaKit.PAdES.Incremental;

public static class PdfIncrementalSignatureWriter
{
    private const int ByteRangeNumberWidth = 20;

    public static PdfSignaturePlaceholder Prepare(
        byte[] originalPdf,
        int cmsCapacity,
        PadesSignatureAppearance? appearance = null)
    {
        ArgumentNullException.ThrowIfNull(originalPdf);
        ArgumentOutOfRangeException.ThrowIfLessThan(cmsCapacity, 1);
        PdfSigningPreflight.Validate(originalPdf, PdfPreflightLimits.Default);
        appearance ??= PadesSignatureAppearance.Invisible;

        string source = Encoding.ASCII.GetString(originalPdf);
        int previousXref = ReadIntegerAfterLastToken(source, "startxref");
        int signatureObjectNumber = ReadIntegerAfterLastToken(source, "/Size");
        int rootObjectNumber = ReadIntegerAfterLastToken(source, "/Root");
        int acroFormObjectNumber = signatureObjectNumber + 1;
        int signatureFieldObjectNumber = signatureObjectNumber + 2;
        int appearanceObjectNumber = signatureFieldObjectNumber + 1;
        int fontObjectNumber = appearanceObjectNumber + 1;
        int imageObjectNumber = fontObjectNumber + 1;
        bool hasImage = appearance.IsVisible && appearance.ImageBytes is { Length: > 0 };
        string catalogDictionary = ReadCatalogDictionary(source, rootObjectNumber);
        string updatedCatalogDictionary = catalogDictionary.Insert(
            catalogDictionary.Length - 2,
            $" /AcroForm {acroFormObjectNumber} 0 R ");

        int? pageObjectNumber = null;
        string? updatedPageDictionary = null;
        if (appearance.IsVisible)
        {
            pageObjectNumber = ReadPageObjectNumber(source, rootObjectNumber, appearance.PageNumber);
            string pageDictionary = ReadObjectDictionary(source, pageObjectNumber.Value);
            if (pageDictionary.Contains("/Annots", StringComparison.Ordinal))
            {
                throw new NotSupportedException("PDF pages with existing annotations are not supported yet.");
            }

            updatedPageDictionary = pageDictionary.Insert(
                pageDictionary.Length - 2,
                $" /Annots [{signatureFieldObjectNumber} 0 R] ");
        }

        string emptyRange = new('0', ByteRangeNumberWidth);
        string contents = $"<{new string('0', checked(cmsCapacity * 2))}>";
        using MemoryStream revision = new();
        List<(int Number, long Offset)> xrefEntries = [];

        WriteAscii(revision, $"\n{rootObjectNumber} 0 obj\n{updatedCatalogDictionary}\nendobj\n");
        xrefEntries.Add((rootObjectNumber, originalPdf.Length + 1));

        if (pageObjectNumber is int pageNumber && updatedPageDictionary is not null)
        {
            xrefEntries.Add((pageNumber, originalPdf.Length + revision.Length));
            WriteAscii(revision, $"{pageNumber} 0 obj\n{updatedPageDictionary}\nendobj\n");
        }

        long signatureObjectOffset = originalPdf.Length + revision.Length;
        xrefEntries.Add((signatureObjectNumber, signatureObjectOffset));
        WriteAscii(
            revision,
            $"{signatureObjectNumber} 0 obj\n" +
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached " +
            $"/ByteRange [{emptyRange} {emptyRange} {emptyRange} {emptyRange}] " +
            $"/Contents {contents} >>\nendobj\n");

        xrefEntries.Add((acroFormObjectNumber, originalPdf.Length + revision.Length));
        WriteAscii(
            revision,
            $"{acroFormObjectNumber} 0 obj\n" +
            $"<< /Fields [{signatureFieldObjectNumber} 0 R] /SigFlags 3 >>\nendobj\n");

        xrefEntries.Add((signatureFieldObjectNumber, originalPdf.Length + revision.Length));
        WriteAscii(revision, BuildSignatureFieldObject(
            signatureFieldObjectNumber,
            signatureObjectNumber,
            appearance,
            pageObjectNumber,
            appearanceObjectNumber));

        if (appearance.IsVisible)
        {
            byte[] appearanceStream = Encoding.ASCII.GetBytes(
                BuildAppearanceContent(appearance, hasImage));
            xrefEntries.Add((appearanceObjectNumber, originalPdf.Length + revision.Length));
            WriteAscii(
                revision,
                $"{appearanceObjectNumber} 0 obj\n" +
                $"<< /Type /XObject /Subtype /Form /BBox [0 0 {PdfNumber(appearance.Width)} {PdfNumber(appearance.Height)}] " +
                BuildAppearanceResources(fontObjectNumber, hasImage ? imageObjectNumber : null) +
                $" /Length {appearanceStream.Length} >>\nstream\n");
            revision.Write(appearanceStream);
            WriteAscii(revision, "\nendstream\nendobj\n");

            xrefEntries.Add((fontObjectNumber, originalPdf.Length + revision.Length));
            WriteAscii(
                revision,
                $"{fontObjectNumber} 0 obj\n" +
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

            if (hasImage)
            {
                byte[] jpeg = appearance.ImageBytes!;
                (int width, int height) = ReadJpegSize(jpeg);
                xrefEntries.Add((imageObjectNumber, originalPdf.Length + revision.Length));
                WriteAscii(
                    revision,
                    $"{imageObjectNumber} 0 obj\n" +
                    "<< /Type /XObject /Subtype /Image " +
                    $"/Width {width} /Height {height} /ColorSpace /DeviceRGB /BitsPerComponent 8 " +
                    $"/Filter /DCTDecode /Length {jpeg.Length} >>\nstream\n");
                revision.Write(jpeg);
                WriteAscii(revision, "\nendstream\nendobj\n");
            }
        }

        long xrefOffset = originalPdf.Length + revision.Length;
        int trailerSize = xrefEntries.Max(entry => entry.Number) + 1;
        WriteAscii(revision, BuildXref(xrefEntries, trailerSize, rootObjectNumber, previousXref, xrefOffset));

        byte[] revisionBytes = revision.ToArray();
        byte[] documentBytes = new byte[originalPdf.Length + revisionBytes.Length];
        originalPdf.CopyTo(documentBytes, 0);
        revisionBytes.CopyTo(documentBytes, originalPdf.Length);

        int contentsOffset = originalPdf.Length + IndexOf(revisionBytes, Encoding.ASCII.GetBytes(contents));
        int contentsLength = contents.Length;
        long[] byteRange =
        [
            0,
            contentsOffset,
            contentsOffset + contentsLength,
            documentBytes.Length - contentsOffset - contentsLength,
        ];

        int byteRangeOffset = originalPdf.Length +
            IndexOf(revisionBytes, Encoding.ASCII.GetBytes("/ByteRange [")) + "/ByteRange [".Length;
        WriteByteRange(documentBytes, byteRangeOffset, byteRange);

        return new PdfSignaturePlaceholder(documentBytes, contentsOffset, contentsLength, byteRange);
    }

    private static string BuildSignatureFieldObject(
        int fieldObjectNumber,
        int signatureObjectNumber,
        PadesSignatureAppearance appearance,
        int? pageObjectNumber,
        int appearanceObjectNumber)
    {
        if (!appearance.IsVisible)
        {
            return $"{fieldObjectNumber} 0 obj\n" +
                $"<< /FT /Sig /T (Signature1) /V {signatureObjectNumber} 0 R >>\nendobj\n";
        }

        return $"{fieldObjectNumber} 0 obj\n" +
            "<< /FT /Sig /Type /Annot /Subtype /Widget /F 4 " +
            $"/P {pageObjectNumber} 0 R " +
            $"/Rect [{PdfNumber(appearance.LowerLeftX)} {PdfNumber(appearance.LowerLeftY)} {PdfNumber(appearance.UpperRightX)} {PdfNumber(appearance.UpperRightY)}] " +
            $"/T (Signature1) /V {signatureObjectNumber} 0 R " +
            $"/AP << /N {appearanceObjectNumber} 0 R >> >>\nendobj\n";
    }

    private static string BuildAppearanceResources(int fontObjectNumber, int? imageObjectNumber)
    {
        string fonts = $"/Resources << /Font << /Helv {fontObjectNumber} 0 R >>";
        if (imageObjectNumber is int image)
        {
            fonts += $" /XObject << /Im0 {image} 0 R >>";
        }

        return fonts + " >>";
    }

    private static string BuildAppearanceContent(PadesSignatureAppearance appearance, bool hasImage)
    {
        StringBuilder content = new();
        content.Append("q\n");
        if (hasImage)
        {
            content.Append(CultureInfo.InvariantCulture, $"{PdfNumber(appearance.Width)} 0 0 {PdfNumber(appearance.Height)} 0 0 cm /Im0 Do\n");
        }

        content.Append(CultureInfo.InvariantCulture, $"0.5 w 0 0 {PdfNumber(appearance.Width)} {PdfNumber(appearance.Height)} re S\n");
        content.Append("BT /Helv 8 Tf 0 g 2 ");
        content.Append(PdfNumber(Math.Max(appearance.Height - 12, 2)));
        content.Append(" Td (");
        content.Append(appearance.Text);
        content.Append(") Tj");
        if (appearance.DisplayedAt is DateTimeOffset displayedAt)
        {
            content.Append(" 0 -10 Td (");
            content.Append(displayedAt.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture));
            content.Append(") Tj");
        }

        content.Append(" ET Q");
        return content.ToString();
    }

    private static string BuildXref(
        List<(int Number, long Offset)> entries,
        int trailerSize,
        int rootObjectNumber,
        int previousXref,
        long xrefOffset)
    {
        entries.Sort((left, right) => left.Number.CompareTo(right.Number));
        StringBuilder xref = new("xref\n");
        int index = 0;
        while (index < entries.Count)
        {
            int start = entries[index].Number;
            int count = 1;
            while (index + count < entries.Count &&
                   entries[index + count].Number == start + count)
            {
                count++;
            }

            xref.Append(CultureInfo.InvariantCulture, $"{start} {count}\n");
            for (int offset = 0; offset < count; offset++)
            {
                xref.Append(CultureInfo.InvariantCulture, $"{entries[index + offset].Offset:0000000000} 00000 n \n");
            }

            index += count;
        }

        xref.Append(CultureInfo.InvariantCulture,
            $"trailer\n<< /Size {trailerSize} /Root {rootObjectNumber} 0 R /Prev {previousXref} >>\n" +
            $"startxref\n{xrefOffset}\n%%EOF\n");
        return xref.ToString();
    }

    private static int ReadPageObjectNumber(string source, int catalogObjectNumber, int pageNumber)
    {
        string catalog = ReadObjectDictionary(source, catalogObjectNumber);
        Match pagesReference = Regex.Match(catalog, @"/Pages\s+(\d+)\s+0\s+R");
        if (!pagesReference.Success)
        {
            throw new NotSupportedException("Visible signatures require a PDF page tree.");
        }

        int pagesObjectNumber = int.Parse(pagesReference.Groups[1].Value, CultureInfo.InvariantCulture);
        string pagesDictionary = ReadObjectDictionary(source, pagesObjectNumber);
        Match kids = Regex.Match(pagesDictionary, @"/Kids\s*\[(.*?)\]", RegexOptions.Singleline);
        if (!kids.Success)
        {
            throw new NotSupportedException("PDF page tree does not contain Kids.");
        }

        MatchCollection references = Regex.Matches(kids.Groups[1].Value, @"(\d+)\s+0\s+R");
        if (pageNumber > references.Count)
        {
            throw new NotSupportedException($"PDF does not contain page {pageNumber}.");
        }

        return int.Parse(references[pageNumber - 1].Groups[1].Value, CultureInfo.InvariantCulture);
    }

    private static (int Width, int Height) ReadJpegSize(ReadOnlySpan<byte> jpeg)
    {
        for (int index = 0; index < jpeg.Length - 8; index++)
        {
            if (jpeg[index] == 0xFF && jpeg[index + 1] is 0xC0 or 0xC1 or 0xC2)
            {
                int height = (jpeg[index + 5] << 8) | jpeg[index + 6];
                int width = (jpeg[index + 7] << 8) | jpeg[index + 8];
                return (width, height);
            }
        }

        throw new ArgumentException("JPEG appearance image does not contain a Start of Frame marker.");
    }

    private static string PdfNumber(double value) =>
        value.ToString("0.###", CultureInfo.InvariantCulture);

    private static void WriteAscii(MemoryStream stream, string text)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        stream.Write(bytes);
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        int index = haystack.AsSpan().IndexOf(needle);
        if (index < 0)
        {
            throw new InvalidOperationException("Required PDF token was not written to the revision.");
        }

        return index;
    }

    private static void WriteByteRange(byte[] documentBytes, int offset, long[] byteRange)
    {
        for (int index = 0; index < byteRange.Length; index++)
        {
            string number = byteRange[index].ToString(
                $"D{ByteRangeNumberWidth}", CultureInfo.InvariantCulture);
            Encoding.ASCII.GetBytes(number, documentBytes.AsSpan(offset, ByteRangeNumberWidth));
            offset += ByteRangeNumberWidth + 1;
        }
    }

    private static int ReadIntegerAfterLastToken(string source, string token)
    {
        int tokenIndex = source.LastIndexOf(token, StringComparison.Ordinal);
        if (tokenIndex < 0)
        {
            throw new NotSupportedException($"PDF does not contain required {token} metadata.");
        }

        ReadOnlySpan<char> remainder = source.AsSpan(tokenIndex + token.Length).TrimStart();
        int digitCount = 0;
        while (digitCount < remainder.Length && char.IsAsciiDigit(remainder[digitCount]))
        {
            digitCount++;
        }

        if (digitCount == 0 ||
            !int.TryParse(remainder[..digitCount], NumberStyles.None, CultureInfo.InvariantCulture, out int value))
        {
            throw new NotSupportedException($"PDF contains invalid {token} metadata.");
        }

        return value;
    }

    private static string ReadCatalogDictionary(string source, int objectNumber)
    {
        string dictionary = ReadObjectDictionary(source, objectNumber);
        if (dictionary.Contains("/AcroForm", StringComparison.Ordinal))
        {
            throw new NotSupportedException("PDF documents with an existing AcroForm are not supported yet.");
        }

        return dictionary;
    }

    private static string ReadObjectDictionary(string source, int objectNumber)
    {
        int objectIndex = IndexOfGenerationZeroObject(source, objectNumber);
        if (objectIndex < 0)
        {
            throw new NotSupportedException($"PDF object {objectNumber} must be an uncompressed generation-zero object.");
        }

        int headerLength = $"{objectNumber} 0 obj".Length;
        int dictionaryStart = source.IndexOf("<<", objectIndex + headerLength, StringComparison.Ordinal);
        int dictionaryEnd = dictionaryStart < 0 ? -1 : FindMatchingDictionaryEnd(source, dictionaryStart);
        if (dictionaryStart < 0 || dictionaryEnd < 0)
        {
            throw new NotSupportedException($"PDF object {objectNumber} dictionary could not be read.");
        }

        return source[dictionaryStart..(dictionaryEnd + 2)];
    }

    private static int IndexOfGenerationZeroObject(string source, int objectNumber)
    {
        string objectHeader = $"{objectNumber} 0 obj";
        int start = 0;
        while (start < source.Length)
        {
            int index = source.IndexOf(objectHeader, start, StringComparison.Ordinal);
            if (index < 0)
            {
                return -1;
            }

            if (index == 0 || !char.IsAsciiDigit(source[index - 1]))
            {
                return index;
            }

            start = index + 1;
        }

        return -1;
    }

    private static int FindMatchingDictionaryEnd(string source, int dictionaryStart)
    {
        int depth = 0;
        int index = dictionaryStart;
        while (index < source.Length - 1)
        {
            char current = source[index];
            if (current == '%')
            {
                int newline = source.IndexOf('\n', index);
                index = newline < 0 ? source.Length : newline + 1;
                continue;
            }

            if (current == '(')
            {
                index = SkipLiteralString(source, index);
                continue;
            }

            if (current == '<' && source[index + 1] == '<')
            {
                depth++;
                index += 2;
                continue;
            }

            if (current == '>' && source[index + 1] == '>')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }

                index += 2;
                continue;
            }

            index++;
        }

        return -1;
    }

    private static int SkipLiteralString(string source, int openParen)
    {
        int depth = 0;
        for (int index = openParen; index < source.Length; index++)
        {
            char current = source[index];
            if (current == '\\')
            {
                index++;
                continue;
            }

            if (current == '(')
            {
                depth++;
            }
            else if (current == ')')
            {
                depth--;
                if (depth == 0)
                {
                    return index + 1;
                }
            }
        }

        return source.Length;
    }
}
