using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ImzaKit.PAdES.Incremental;

namespace ImzaKit.PAdES.Dss;

public static class PdfDocumentSecurityStoreWriter
{
    public static byte[] Embed(byte[] signedPdf, PadesValidationMaterial material)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentNullException.ThrowIfNull(material);
        if (signedPdf.Length == 0)
        {
            throw new ArgumentException("Signed PDF cannot be empty.", nameof(signedPdf));
        }

        string source = Encoding.ASCII.GetString(signedPdf);
        int rootObjectNumber = PdfIncrementalSyntax.ReadIntegerAfterLastToken(source, "/Root");
        string catalogDictionary = PdfIncrementalSyntax.ReadObjectDictionary(source, rootObjectNumber);
        bool merging = catalogDictionary.Contains("/DSS", StringComparison.Ordinal);
        List<int> existingCerts = [];
        List<int> existingOcsps = [];
        List<int> existingCrls = [];
        if (merging)
        {
            int existingDss = PdfIncrementalSyntax.ReadReferenceNumber(catalogDictionary, "/DSS");
            string dssDictionary = PdfIncrementalSyntax.ReadObjectDictionary(source, existingDss);
            existingCerts = PdfIncrementalSyntax.ReadReferenceArray(dssDictionary, "/Certs");
            existingOcsps = PdfIncrementalSyntax.ReadReferenceArray(dssDictionary, "/OCSPs");
            existingCrls = PdfIncrementalSyntax.ReadReferenceArray(dssDictionary, "/CRLs");
        }

        int previousXref = PdfIncrementalSyntax.ReadIntegerAfterLastToken(source, "startxref");
        int nextObjectNumber = PdfIncrementalSyntax.ReadIntegerAfterLastToken(source, "/Size");

        using MemoryStream revision = new();
        List<(int Number, long Offset)> xrefEntries = [];
        PdfIncrementalSyntax.WriteAscii(revision, "\n");

        List<int> certObjects = MergeStreams(
            revision, signedPdf, xrefEntries, ref nextObjectNumber, existingCerts, material.Certificates);
        List<int> ocspObjects = MergeStreams(
            revision, signedPdf, xrefEntries, ref nextObjectNumber, existingOcsps, material.OcspResponses);
        List<int> crlObjects = MergeStreams(
            revision, signedPdf, xrefEntries, ref nextObjectNumber, existingCrls, material.CertificateRevocationLists);

        int vriObjectNumber = nextObjectNumber++;
        xrefEntries.Add((vriObjectNumber, signedPdf.Length + revision.Length));
        PdfIncrementalSyntax.WriteAscii(revision, $"{vriObjectNumber} 0 obj\n{BuildVriDictionary(source, certObjects, ocspObjects, crlObjects)}\nendobj\n");

        int dssObjectNumber = nextObjectNumber++;
        xrefEntries.Add((dssObjectNumber, signedPdf.Length + revision.Length));
        PdfIncrementalSyntax.WriteAscii(revision, $"{dssObjectNumber} 0 obj\n{BuildDssDictionary(certObjects, ocspObjects, crlObjects, vriObjectNumber)}\nendobj\n");

        string updatedCatalog = merging
            ? PdfIncrementalSyntax.ReplaceReferenceNumber(catalogDictionary, "/DSS", dssObjectNumber)
            : catalogDictionary.Insert(catalogDictionary.Length - 2, $" /DSS {dssObjectNumber} 0 R ");
        xrefEntries.Add((rootObjectNumber, signedPdf.Length + revision.Length));
        PdfIncrementalSyntax.WriteAscii(revision, $"{rootObjectNumber} 0 obj\n{updatedCatalog}\nendobj\n");

        long xrefOffset = signedPdf.Length + revision.Length;
        int trailerSize = Math.Max(nextObjectNumber, xrefEntries.Max(entry => entry.Number) + 1);
        PdfIncrementalSyntax.WriteAscii(
            revision,
            PdfIncrementalSyntax.BuildXref(xrefEntries, trailerSize, rootObjectNumber, previousXref, xrefOffset));

        byte[] revisionBytes = revision.ToArray();
        byte[] document = new byte[signedPdf.Length + revisionBytes.Length];
        signedPdf.CopyTo(document, 0);
        revisionBytes.CopyTo(document, signedPdf.Length);
        return document;
    }

    private static List<int> MergeStreams(
        MemoryStream revision,
        byte[] originalPdf,
        List<(int Number, long Offset)> xrefEntries,
        ref int nextObjectNumber,
        IReadOnlyList<int> existingObjects,
        IReadOnlyList<byte[]> payloads)
    {
        Dictionary<string, int> known = new(StringComparer.Ordinal);
        foreach (int objectNumber in existingObjects)
        {
            if (PdfIncrementalSyntax.TryReadStream(originalPdf, objectNumber, out byte[] existing))
            {
                known[Convert.ToHexString(SHA256.HashData(existing))] = objectNumber;
            }
        }

        List<int> objectNumbers = [.. existingObjects];
        foreach (byte[] payload in payloads)
        {
            string digest = Convert.ToHexString(SHA256.HashData(payload));
            if (known.ContainsKey(digest))
            {
                continue;
            }

            int objectNumber = nextObjectNumber++;
            objectNumbers.Add(objectNumber);
            known[digest] = objectNumber;
            xrefEntries.Add((objectNumber, originalPdf.Length + revision.Length));
            PdfIncrementalSyntax.WriteAscii(
                revision,
                $"{objectNumber} 0 obj\n<< /Length {payload.Length.ToString(CultureInfo.InvariantCulture)} >>\nstream\n");
            revision.Write(payload);
            PdfIncrementalSyntax.WriteAscii(revision, "\nendstream\nendobj\n");
        }

        return objectNumbers;
    }

    private static string BuildDssDictionary(
        IReadOnlyList<int> certs,
        IReadOnlyList<int> ocsps,
        IReadOnlyList<int> crls,
        int vriObjectNumber)
    {
        StringBuilder dictionary = new("<< /Type /DSS");
        AppendReferenceArray(dictionary, "/Certs", certs);
        AppendReferenceArray(dictionary, "/OCSPs", ocsps);
        AppendReferenceArray(dictionary, "/CRLs", crls);
        dictionary.Append(CultureInfo.InvariantCulture, $" /VRI {vriObjectNumber} 0 R >>");
        return dictionary.ToString();
    }

    private static string BuildVriDictionary(
        string source,
        IReadOnlyList<int> certs,
        IReadOnlyList<int> ocsps,
        IReadOnlyList<int> crls)
    {
        string key = SignatureVriKey(source);
        StringBuilder entry = new("<<");
        AppendReferenceArray(entry, "/Cert", certs);
        AppendReferenceArray(entry, "/OCSP", ocsps);
        AppendReferenceArray(entry, "/CRL", crls);
        entry.Append(" >>");
        return $"<< /{key} {entry} >>";
    }

    private static void AppendReferenceArray(StringBuilder dictionary, string token, IReadOnlyList<int> objectNumbers)
    {
        if (objectNumbers.Count == 0)
        {
            return;
        }

        dictionary.Append(' ');
        dictionary.Append(token);
        dictionary.Append(" [");
        for (int index = 0; index < objectNumbers.Count; index++)
        {
            if (index > 0)
            {
                dictionary.Append(' ');
            }

            dictionary.Append(CultureInfo.InvariantCulture, $"{objectNumbers[index]} 0 R");
        }

        dictionary.Append(" ]");
    }

    private static string SignatureVriKey(string source)
    {
        int signatureIndex = source.LastIndexOf("/SubFilter /ETSI.CAdES.detached", StringComparison.Ordinal);
        if (signatureIndex < 0)
        {
            throw new NotSupportedException("DSS requires an ETSI.CAdES.detached signature.");
        }

        int contentsIndex = source.IndexOf("/Contents <", signatureIndex, StringComparison.Ordinal);
        int hexStart = contentsIndex < 0 ? -1 : contentsIndex + "/Contents <".Length;
        int hexEnd = hexStart < 0 ? -1 : source.IndexOf('>', hexStart);
        if (contentsIndex < 0 || hexEnd < 0)
        {
            throw new NotSupportedException("Signature Contents could not be read for VRI.");
        }

        byte[] padded = Convert.FromHexString(source[hexStart..hexEnd]);
        int cmsLength = ReadDerValueLength(padded);
        if (cmsLength > padded.Length)
        {
            throw new NotSupportedException("Signature Contents is not a complete CMS value.");
        }

#pragma warning disable CA5350
        byte[] digest = SHA1.HashData(padded.AsSpan(0, cmsLength));
#pragma warning restore CA5350
        return Convert.ToHexString(digest);
    }

    private static int ReadDerValueLength(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < 2)
        {
            throw new NotSupportedException("Signature Contents is not a complete CMS value.");
        }

        int lengthByte = encoded[1];
        if ((lengthByte & 0x80) == 0)
        {
            return 2 + lengthByte;
        }

        int lengthByteCount = lengthByte & 0x7F;
        int contentLength = 0;
        for (int index = 0; index < lengthByteCount; index++)
        {
            contentLength = (contentLength << 8) | encoded[2 + index];
        }

        return 2 + lengthByteCount + contentLength;
    }
}
