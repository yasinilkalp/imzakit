using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.XAdES;

public static class XadesExtender
{
    public static async Task<byte[]> ExtendBaselineT(
        byte[] signedXml,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        ArgumentNullException.ThrowIfNull(timeStampClient);
        ArgumentNullException.ThrowIfNull(authorities);
        XmlDocument document = XadesXmlLoader.Load(signedXml);
        XmlElement signature = XadesXmlTree.Require(document, "Signature", SignedXml.XmlDsigNamespaceUrl);
        if (XadesXmlTree.Has(signature, "SignatureTimeStamp", XadesXmlAlgorithms.XadesNamespace))
        {
            throw new InvalidOperationException("The XML already contains an XAdES signature time-stamp.");
        }

        byte[] signatureValue = Convert.FromBase64String(
            XadesXmlTree.Require(signature, "SignatureValue", SignedXml.XmlDsigNamespaceUrl).InnerText.Trim());
        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            SHA256.HashData(signatureValue),
            authorities,
            cancellationToken).ConfigureAwait(false);
        AppendUnsignedChild(document, signature, "SignatureTimeStamp", timestamp.TokenDer);
        return XadesXmlLoader.Save(document);
    }

    public static byte[] ExtendBaselineLt(byte[] signedXml, XadesLongTermEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        ArgumentNullException.ThrowIfNull(evidence);
        XmlDocument document = XadesXmlLoader.Load(signedXml);
        XmlElement signature = XadesXmlTree.Require(document, "Signature", SignedXml.XmlDsigNamespaceUrl);
        if (!XadesXmlTree.Has(signature, "SignatureTimeStamp", XadesXmlAlgorithms.XadesNamespace))
        {
            throw new InvalidOperationException("XAdES B-LT requires a B-T signature time-stamp.");
        }

        if (XadesXmlTree.Has(signature, "CertificateValues", XadesXmlAlgorithms.XadesNamespace)
            || XadesXmlTree.Has(signature, "RevocationValues", XadesXmlAlgorithms.XadesNamespace))
        {
            throw new InvalidOperationException("The XML already contains XAdES B-LT evidence.");
        }

        XmlElement unsigned = EnsureUnsignedSignatureProperties(document, signature);
        unsigned.AppendChild(BuildCertificateValues(document, evidence));
        if (evidence.OcspResponses.Count > 0 || evidence.CertificateRevocationLists.Count > 0)
        {
            unsigned.AppendChild(BuildRevocationValues(document, evidence));
        }

        return XadesXmlLoader.Save(document);
    }

    public static async Task<byte[]> ExtendBaselineLta(
        byte[] signedXml,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        ArgumentNullException.ThrowIfNull(timeStampClient);
        ArgumentNullException.ThrowIfNull(authorities);
        XmlDocument document = XadesXmlLoader.Load(signedXml);
        XmlElement signature = XadesXmlTree.Require(document, "Signature", SignedXml.XmlDsigNamespaceUrl);
        if (!XadesXmlTree.Has(signature, "SignatureTimeStamp", XadesXmlAlgorithms.XadesNamespace)
            || (!XadesXmlTree.Has(signature, "CertificateValues", XadesXmlAlgorithms.XadesNamespace)
                && !XadesXmlTree.Has(signature, "RevocationValues", XadesXmlAlgorithms.XadesNamespace)))
        {
            throw new InvalidOperationException("XAdES B-LTA requires B-LT certificate-values or revocation-values.");
        }

        if (XadesXmlTree.Has(signature, "ArchiveTimeStamp", XadesXmlAlgorithms.XadesNamespace))
        {
            throw new InvalidOperationException("The XML already contains an XAdES archive time-stamp.");
        }

        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            SHA256.HashData(signedXml),
            authorities,
            cancellationToken).ConfigureAwait(false);
        AppendUnsignedChild(document, signature, "ArchiveTimeStamp", timestamp.TokenDer);
        return XadesXmlLoader.Save(document);
    }

    private static void AppendUnsignedChild(
        XmlDocument document,
        XmlElement signature,
        string localName,
        byte[] tokenDer)
    {
        XmlElement unsigned = EnsureUnsignedSignatureProperties(document, signature);
        XmlElement stamp = document.CreateElement("xades", localName, XadesXmlAlgorithms.XadesNamespace);
        XmlElement encapsulated = document.CreateElement(
            "xades",
            "EncapsulatedTimeStamp",
            XadesXmlAlgorithms.XadesNamespace);
        encapsulated.InnerText = Convert.ToBase64String(tokenDer);
        stamp.AppendChild(encapsulated);
        unsigned.AppendChild(stamp);
    }

    private static XmlElement EnsureUnsignedSignatureProperties(XmlDocument document, XmlElement signature)
    {
        XmlElement qualifying = XadesXmlTree.Require(
            signature,
            "QualifyingProperties",
            XadesXmlAlgorithms.XadesNamespace);
        XmlElement? unsignedProperties = XadesXmlTree.Find(
            qualifying,
            "UnsignedProperties",
            XadesXmlAlgorithms.XadesNamespace);
        if (unsignedProperties is null)
        {
            unsignedProperties = document.CreateElement(
                "xades",
                "UnsignedProperties",
                XadesXmlAlgorithms.XadesNamespace);
            qualifying.AppendChild(unsignedProperties);
        }

        XmlElement? unsignedSignature = XadesXmlTree.Find(
            unsignedProperties,
            "UnsignedSignatureProperties",
            XadesXmlAlgorithms.XadesNamespace);
        if (unsignedSignature is null)
        {
            unsignedSignature = document.CreateElement(
                "xades",
                "UnsignedSignatureProperties",
                XadesXmlAlgorithms.XadesNamespace);
            unsignedProperties.AppendChild(unsignedSignature);
        }

        return unsignedSignature;
    }

    private static XmlElement BuildCertificateValues(XmlDocument document, XadesLongTermEvidence evidence)
    {
        XmlElement values = document.CreateElement("xades", "CertificateValues", XadesXmlAlgorithms.XadesNamespace);
        foreach (byte[] certificate in evidence.Certificates)
        {
            XmlElement encapsulated = document.CreateElement(
                "xades",
                "EncapsulatedX509Certificate",
                XadesXmlAlgorithms.XadesNamespace);
            encapsulated.InnerText = Convert.ToBase64String(certificate);
            values.AppendChild(encapsulated);
        }

        return values;
    }

    private static XmlElement BuildRevocationValues(XmlDocument document, XadesLongTermEvidence evidence)
    {
        XmlElement values = document.CreateElement("xades", "RevocationValues", XadesXmlAlgorithms.XadesNamespace);
        if (evidence.OcspResponses.Count > 0)
        {
            XmlElement ocspValues = document.CreateElement("xades", "OCSPValues", XadesXmlAlgorithms.XadesNamespace);
            foreach (byte[] ocsp in evidence.OcspResponses)
            {
                XmlElement encapsulated = document.CreateElement(
                    "xades",
                    "EncapsulatedOCSPValue",
                    XadesXmlAlgorithms.XadesNamespace);
                encapsulated.InnerText = Convert.ToBase64String(ocsp);
                ocspValues.AppendChild(encapsulated);
            }

            values.AppendChild(ocspValues);
        }

        if (evidence.CertificateRevocationLists.Count > 0)
        {
            XmlElement crlValues = document.CreateElement("xades", "CRLValues", XadesXmlAlgorithms.XadesNamespace);
            foreach (byte[] crl in evidence.CertificateRevocationLists)
            {
                XmlElement encapsulated = document.CreateElement(
                    "xades",
                    "EncapsulatedCRLValue",
                    XadesXmlAlgorithms.XadesNamespace);
                encapsulated.InnerText = Convert.ToBase64String(crl);
                crlValues.AppendChild(encapsulated);
            }

            values.AppendChild(crlValues);
        }

        return values;
    }
}
