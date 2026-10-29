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
        if (XadesXmlTree.HasUnsignedProperty(signature, "SignatureTimeStamp", XadesXmlAlgorithms.XadesNamespace))
        {
            throw new InvalidOperationException("The XML already contains an XAdES signature time-stamp.");
        }

        byte[] covered = XadesTimeStampInput.ForSignatureTimeStamp(signature, XadesXmlAlgorithms.ExclusiveCanonicalization)
            ?? throw new InvalidOperationException("XML element SignatureValue is missing.");
        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            SHA256.HashData(covered),
            authorities,
            cancellationToken).ConfigureAwait(false);
        AppendTimeStamp(document, signature, "SignatureTimeStamp", XadesXmlAlgorithms.XadesNamespace, timestamp.TokenDer);
        return XadesXmlLoader.Save(document);
    }

    public static byte[] ExtendBaselineLt(byte[] signedXml, XadesLongTermEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        ArgumentNullException.ThrowIfNull(evidence);
        XmlDocument document = XadesXmlLoader.Load(signedXml);
        XmlElement signature = XadesXmlTree.Require(document, "Signature", SignedXml.XmlDsigNamespaceUrl);
        if (!XadesXmlTree.HasUnsignedProperty(signature, "SignatureTimeStamp", XadesXmlAlgorithms.XadesNamespace))
        {
            throw new InvalidOperationException("XAdES B-LT requires a B-T signature time-stamp.");
        }

        if (XadesXmlTree.HasUnsignedProperty(signature, "CertificateValues", XadesXmlAlgorithms.XadesNamespace)
            || XadesXmlTree.HasUnsignedProperty(signature, "RevocationValues", XadesXmlAlgorithms.XadesNamespace))
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

    public static Task<byte[]> ExtendBaselineLta(
        byte[] signedXml,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken) =>
        ExtendBaselineLta(signedXml, detachedContent: null, timeStampClient, authorities, cancellationToken);

    // The archive time-stamp covers the referenced data, so a detached signature needs its detached content.
    public static async Task<byte[]> ExtendBaselineLta(
        byte[] signedXml,
        byte[]? detachedContent,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        ArgumentNullException.ThrowIfNull(timeStampClient);
        ArgumentNullException.ThrowIfNull(authorities);
        XmlDocument document = XadesXmlLoader.Load(signedXml);
        XmlElement signature = XadesXmlTree.Require(document, "Signature", SignedXml.XmlDsigNamespaceUrl);
        if (!XadesXmlTree.HasUnsignedProperty(signature, "SignatureTimeStamp", XadesXmlAlgorithms.XadesNamespace)
            || (!XadesXmlTree.HasUnsignedProperty(signature, "CertificateValues", XadesXmlAlgorithms.XadesNamespace)
                && !XadesXmlTree.HasUnsignedProperty(signature, "RevocationValues", XadesXmlAlgorithms.XadesNamespace)))
        {
            throw new InvalidOperationException("XAdES B-LTA requires B-LT certificate-values or revocation-values.");
        }

        if (XadesXmlTree.HasUnsignedProperty(signature, "ArchiveTimeStamp", XadesXmlAlgorithms.Xades141Namespace)
            || XadesXmlTree.HasUnsignedProperty(signature, "ArchiveTimeStamp", XadesXmlAlgorithms.XadesNamespace))
        {
            throw new InvalidOperationException("The XML already contains an XAdES archive time-stamp.");
        }

        XmlElement? payload = detachedContent is null
            ? null
            : XadesValidator.InjectDetachedPayload(document, signature, detachedContent);
        byte[] covered = XadesTimeStampInput.ForArchiveTimeStamp(
                signature,
                archiveTimeStamp: null,
                XadesXmlAlgorithms.ExclusiveCanonicalization)
            ?? throw new InvalidOperationException(
                "The archive time-stamp input cannot be computed; a detached signature needs its detached content.");
        payload?.ParentNode!.RemoveChild(payload);
        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            SHA256.HashData(covered),
            authorities,
            cancellationToken).ConfigureAwait(false);
        AppendTimeStamp(document, signature, "ArchiveTimeStamp", XadesXmlAlgorithms.Xades141Namespace, timestamp.TokenDer);
        return XadesXmlLoader.Save(document);
    }

    // XAdESTimeStampType with an explicit canonicalization, since its absence means inclusive C14N.
    private static void AppendTimeStamp(
        XmlDocument document,
        XmlElement signature,
        string localName,
        string namespaceUri,
        byte[] tokenDer)
    {
        XmlElement unsigned = EnsureUnsignedSignatureProperties(document, signature);
        XmlElement stamp = document.CreateElement(
            namespaceUri == XadesXmlAlgorithms.Xades141Namespace ? "xades141" : "xades",
            localName,
            namespaceUri);
        stamp.SetAttribute("Id", "ts-" + Guid.NewGuid().ToString("N"));
        XmlElement canonicalization = document.CreateElement("ds", "CanonicalizationMethod", SignedXml.XmlDsigNamespaceUrl);
        canonicalization.SetAttribute("Algorithm", XadesXmlAlgorithms.ExclusiveCanonicalization);
        stamp.AppendChild(canonicalization);
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
        XmlElement qualifying = XadesXmlTree.QualifyingProperties(signature)
            ?? throw new InvalidOperationException("XML element QualifyingProperties is missing.");
        XmlElement? unsignedProperties = XadesXmlTree.Child(
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

        XmlElement? unsignedSignature = XadesXmlTree.Child(
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
