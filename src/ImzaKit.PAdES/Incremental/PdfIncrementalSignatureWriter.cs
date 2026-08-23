using System.Globalization;
using System.Text;
using ImzaKit.PAdES.Preflight;

namespace ImzaKit.PAdES.Incremental;

public static class PdfIncrementalSignatureWriter
{
    private const int ByteRangeNumberWidth = 20;

    public static PdfSignaturePlaceholder Prepare(byte[] originalPdf, int cmsCapacity)
    {
        ArgumentNullException.ThrowIfNull(originalPdf);
        ArgumentOutOfRangeException.ThrowIfLessThan(cmsCapacity, 1);
        PdfSigningPreflight.Validate(originalPdf, PdfPreflightLimits.Default);

        string source = Encoding.ASCII.GetString(originalPdf);
        int previousXref = ReadIntegerAfterLastToken(source, "startxref");
        int signatureObjectNumber = ReadIntegerAfterLastToken(source, "/Size");
        int rootObjectNumber = ReadIntegerAfterLastToken(source, "/Root");
        int acroFormObjectNumber = signatureObjectNumber + 1;
        int signatureFieldObjectNumber = signatureObjectNumber + 2;
        string catalogDictionary = ReadObjectDictionary(source, rootObjectNumber);
        string updatedCatalogDictionary = catalogDictionary.Insert(
            catalogDictionary.Length - 2,
            $" /AcroForm {acroFormObjectNumber} 0 R ");

        string emptyRange = new('0', ByteRangeNumberWidth);
        string contents = $"<{new string('0', checked(cmsCapacity * 2))}>";
        string catalogObject = $"\n{rootObjectNumber} 0 obj\n" +
            $"{updatedCatalogDictionary}\nendobj\n";
        string signatureObject = $"{signatureObjectNumber} 0 obj\n" +
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached " +
            $"/ByteRange [{emptyRange} {emptyRange} {emptyRange} {emptyRange}] " +
            $"/Contents {contents} >>\nendobj\n";
        string acroFormObject = $"{acroFormObjectNumber} 0 obj\n" +
            $"<< /Fields [{signatureFieldObjectNumber} 0 R] /SigFlags 3 >>\nendobj\n";
        string signatureFieldObject = $"{signatureFieldObjectNumber} 0 obj\n" +
            $"<< /FT /Sig /T (Signature1) /V {signatureObjectNumber} 0 R >>\nendobj\n";
        string objectText = catalogObject + signatureObject + acroFormObject + signatureFieldObject;

        int catalogOffset = originalPdf.Length + 1;
        int signatureOffset = originalPdf.Length + Encoding.ASCII.GetByteCount(catalogObject);
        int acroFormOffset = signatureOffset + Encoding.ASCII.GetByteCount(signatureObject);
        int signatureFieldOffset = acroFormOffset + Encoding.ASCII.GetByteCount(acroFormObject);
        int xrefOffset = signatureFieldOffset + Encoding.ASCII.GetByteCount(signatureFieldObject);
        string revision = objectText +
            $"xref\n{rootObjectNumber} 1\n{catalogOffset:0000000000} 00000 n \n" +
            $"{signatureObjectNumber} 3\n" +
            $"{signatureOffset:0000000000} 00000 n \n" +
            $"{acroFormOffset:0000000000} 00000 n \n" +
            $"{signatureFieldOffset:0000000000} 00000 n \n" +
            $"trailer\n<< /Size {signatureFieldObjectNumber + 1} /Root {rootObjectNumber} 0 R /Prev {previousXref} >>\n" +
            $"startxref\n{xrefOffset}\n%%EOF\n";

        byte[] revisionBytes = Encoding.ASCII.GetBytes(revision);
        byte[] documentBytes = new byte[originalPdf.Length + revisionBytes.Length];
        originalPdf.CopyTo(documentBytes, 0);
        revisionBytes.CopyTo(documentBytes, originalPdf.Length);

        int contentsOffset = originalPdf.Length + objectText.IndexOf(contents, StringComparison.Ordinal);
        int contentsLength = contents.Length;
        long[] byteRange =
        [
            0,
            contentsOffset,
            contentsOffset + contentsLength,
            documentBytes.Length - contentsOffset - contentsLength,
        ];

        int byteRangeOffset = originalPdf.Length +
            objectText.IndexOf("/ByteRange [", StringComparison.Ordinal) + "/ByteRange [".Length;
        WriteByteRange(documentBytes, byteRangeOffset, byteRange);

        return new PdfSignaturePlaceholder(documentBytes, contentsOffset, contentsLength, byteRange);
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

    private static string ReadObjectDictionary(string source, int objectNumber)
    {
        string objectHeader = $"{objectNumber} 0 obj";
        int objectIndex = source.IndexOf(objectHeader, StringComparison.Ordinal);
        if (objectIndex < 0)
        {
            throw new NotSupportedException("PDF root catalog must be an uncompressed generation-zero object.");
        }

        int dictionaryStart = source.IndexOf("<<", objectIndex + objectHeader.Length, StringComparison.Ordinal);
        int dictionaryEnd = source.IndexOf(">>", dictionaryStart + 2, StringComparison.Ordinal);
        if (dictionaryStart < 0 || dictionaryEnd < 0)
        {
            throw new NotSupportedException("PDF root catalog dictionary could not be read.");
        }

        string dictionary = source[dictionaryStart..(dictionaryEnd + 2)];
        if (dictionary.Contains("/AcroForm", StringComparison.Ordinal))
        {
            throw new NotSupportedException("PDF documents with an existing AcroForm are not supported yet.");
        }

        return dictionary;
    }
}
