using System.Security.Cryptography;
using System.Text;

namespace ImzaKit.ASiC;

internal static class AsicManifest
{
    private const string Namespace = "http://uri.etsi.org/02918/v1.2.1#";
    private const string DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

    public static byte[] Create(
        IReadOnlyList<AsicDataObject> dataObjects,
        IReadOnlyList<AsicSignatureFile> signatures)
    {
        StringBuilder xml = new();
        xml.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        xml.Append("<ASiCManifest xmlns=\"").Append(Namespace).Append("\">");
        foreach (AsicSignatureFile signature in signatures)
        {
            xml.Append("<SigReference URI=\"")
                .Append(AsicPaths.MetaInfFile(signature.FileName))
                .Append("\"/>");
        }

        foreach (AsicDataObject data in dataObjects)
        {
            xml.Append("<DataObjectReference URI=\"").Append(data.Name).Append("\">");
            xml.Append("<DigestMethod Algorithm=\"").Append(DigestMethod).Append("\"/>");
            xml.Append("<DigestValue>")
                .Append(Convert.ToBase64String(SHA256.HashData(data.Content)))
                .Append("</DigestValue>");
            xml.Append("</DataObjectReference>");
        }

        xml.Append("</ASiCManifest>");
        return Encoding.UTF8.GetBytes(xml.ToString());
    }

    public static void Verify(byte[] manifest, IReadOnlyList<AsicDataObject> dataObjects)
    {
        string text = Encoding.UTF8.GetString(manifest);
        foreach (AsicDataObject data in dataObjects)
        {
            string expected = Convert.ToBase64String(SHA256.HashData(data.Content));
            string marker = "URI=\"" + data.Name + "\"";
            int uri = text.IndexOf(marker, StringComparison.Ordinal);
            if (uri < 0)
            {
                throw new InvalidDataException("ASiC manifest does not cover a data object.");
            }

            int digest = text.IndexOf("<DigestValue>", uri, StringComparison.Ordinal);
            int end = text.IndexOf("</DigestValue>", uri, StringComparison.Ordinal);
            if (digest < 0 || end < 0)
            {
                throw new InvalidDataException("ASiC manifest digest is missing.");
            }

            string value = text[(digest + "<DigestValue>".Length)..end];
            if (!string.Equals(value, expected, StringComparison.Ordinal))
            {
                throw new InvalidDataException("ASiC manifest digest does not match the data object.");
            }
        }
    }
}
