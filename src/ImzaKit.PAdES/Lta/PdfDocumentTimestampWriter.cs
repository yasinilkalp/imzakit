using System.Text;
using ImzaKit.PAdES.Incremental;

namespace ImzaKit.PAdES.Lta;

public static class PdfDocumentTimestampWriter
{
    public static PdfSignaturePlaceholder Prepare(byte[] longTermPdf, int tokenCapacity)
    {
        ArgumentNullException.ThrowIfNull(longTermPdf);
        ArgumentOutOfRangeException.ThrowIfLessThan(tokenCapacity, 1);
        if (longTermPdf.Length == 0)
        {
            throw new ArgumentException("Signed PDF cannot be empty.", nameof(longTermPdf));
        }

        string source = Encoding.ASCII.GetString(longTermPdf);
        int rootObjectNumber = PdfIncrementalSyntax.ReadIntegerAfterLastToken(source, "/Root");
        string catalogDictionary = PdfIncrementalSyntax.ReadObjectDictionary(source, rootObjectNumber);
        if (!catalogDictionary.Contains("/DSS", StringComparison.Ordinal))
        {
            throw new NotSupportedException("B-LTA requires a DSS revision covering validation material.");
        }

        if (!catalogDictionary.Contains("/AcroForm", StringComparison.Ordinal))
        {
            throw new NotSupportedException("B-LTA requires an AcroForm signature field container.");
        }

        int previousXref = PdfIncrementalSyntax.ReadIntegerAfterLastToken(source, "startxref");
        int nextObjectNumber = PdfIncrementalSyntax.ReadIntegerAfterLastToken(source, "/Size");
        int acroFormObjectNumber = PdfIncrementalSyntax.ReadReferenceNumber(catalogDictionary, "/AcroForm");
        string acroFormDictionary = PdfIncrementalSyntax.AppendFieldReference(
            PdfIncrementalSyntax.ReadObjectDictionary(source, acroFormObjectNumber),
            nextObjectNumber + 1);
        string fieldName = PdfIncrementalSyntax.NextDocumentTimestampFieldName(source);
        string emptyRange = new('0', PdfIncrementalSyntax.ByteRangeNumberWidth);
        string contents = $"<{new string('0', checked(tokenCapacity * 2))}>";

        using MemoryStream revision = new();
        List<(int Number, long Offset)> xrefEntries = [];
        PdfIncrementalSyntax.WriteAscii(revision, "\n");

        int timestampObjectNumber = nextObjectNumber++;
        int fieldObjectNumber = nextObjectNumber++;
        xrefEntries.Add((timestampObjectNumber, longTermPdf.Length + revision.Length));
        PdfIncrementalSyntax.WriteAscii(
            revision,
            $"{timestampObjectNumber} 0 obj\n" +
            "<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 " +
            $"/ByteRange [{emptyRange} {emptyRange} {emptyRange} {emptyRange}] " +
            $"/Contents {contents} >>\nendobj\n");

        xrefEntries.Add((fieldObjectNumber, longTermPdf.Length + revision.Length));
        PdfIncrementalSyntax.WriteAscii(
            revision,
            $"{fieldObjectNumber} 0 obj\n" +
            $"<< /FT /Sig /T ({fieldName}) /V {timestampObjectNumber} 0 R >>\nendobj\n");

        xrefEntries.Add((acroFormObjectNumber, longTermPdf.Length + revision.Length));
        PdfIncrementalSyntax.WriteAscii(revision, $"{acroFormObjectNumber} 0 obj\n{acroFormDictionary}\nendobj\n");

        long xrefOffset = longTermPdf.Length + revision.Length;
        int trailerSize = Math.Max(nextObjectNumber, xrefEntries.Max(entry => entry.Number) + 1);
        PdfIncrementalSyntax.WriteAscii(
            revision,
            PdfIncrementalSyntax.BuildXref(xrefEntries, trailerSize, rootObjectNumber, previousXref, xrefOffset));

        byte[] revisionBytes = revision.ToArray();
        byte[] documentBytes = new byte[longTermPdf.Length + revisionBytes.Length];
        longTermPdf.CopyTo(documentBytes, 0);
        revisionBytes.CopyTo(documentBytes, longTermPdf.Length);

        int contentsOffset = longTermPdf.Length + PdfIncrementalSyntax.IndexOf(revisionBytes, Encoding.ASCII.GetBytes(contents));
        int contentsLength = contents.Length;
        long[] byteRange =
        [
            0,
            contentsOffset,
            contentsOffset + contentsLength,
            documentBytes.Length - contentsOffset - contentsLength,
        ];

        int byteRangeOffset = longTermPdf.Length +
            PdfIncrementalSyntax.IndexOf(revisionBytes, Encoding.ASCII.GetBytes("/ByteRange [")) +
            "/ByteRange [".Length;
        PdfIncrementalSyntax.WriteByteRange(documentBytes, byteRangeOffset, byteRange);
        return new PdfSignaturePlaceholder(documentBytes, contentsOffset, contentsLength, byteRange);
    }
}
