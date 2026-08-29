using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ImzaKit.XAdES;

public static class XadesSigner
{
    public static byte[] Sign(
        XadesPackaging packaging,
        ReadOnlySpan<byte> xml,
        X509Certificate2 certificate,
        RSA privateKey,
        XadesSignaturePolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(privateKey);
        (policy ?? XadesSignaturePolicy.AllowAll).EnsureAllowed(packaging);
        XmlDocument payload = XadesXmlLoader.Load(xml);
        if (payload.DocumentElement is null)
        {
            throw new InvalidOperationException("XML document element is missing.");
        }

        return packaging switch
        {
            XadesPackaging.Enveloped => SignEnveloped(payload, certificate, privateKey),
            XadesPackaging.Enveloping => SignEnveloping(payload, certificate, privateKey),
            XadesPackaging.Detached => SignDetached(payload, certificate, privateKey),
            _ => throw new ArgumentOutOfRangeException(nameof(packaging))
        };
    }

    private static byte[] SignEnveloped(XmlDocument document, X509Certificate2 certificate, RSA privateKey)
    {
        PolicySignedXml signedXml = new(document);
        Configure(signedXml, certificate, privateKey, XadesPackaging.Enveloped, payloadObjectId: null);
        document.DocumentElement!.AppendChild(document.ImportNode(signedXml.GetXml(), true));
        return XadesXmlLoader.Save(document);
    }

    private static byte[] SignEnveloping(XmlDocument payload, X509Certificate2 certificate, RSA privateKey)
    {
        string payloadObjectId = "obj-" + Guid.NewGuid().ToString("N");
        PolicySignedXml signedXml = new();
        signedXml.AddObject(CreatePayloadObject(payload, payloadObjectId));
        Configure(signedXml, certificate, privateKey, XadesPackaging.Enveloping, payloadObjectId);
        return SignatureDocument(signedXml);
    }

    private static byte[] SignDetached(XmlDocument payload, X509Certificate2 certificate, RSA privateKey)
    {
        PolicySignedXml signedXml = new();
        signedXml.AddObject(CreatePayloadObject(payload, XadesXmlAlgorithms.DetachedObjectId));
        Configure(signedXml, certificate, privateKey, XadesPackaging.Detached, XadesXmlAlgorithms.DetachedObjectId);
        return SignatureDocument(signedXml, stripDetachedObject: true);
    }

    private static void Configure(
        PolicySignedXml signedXml,
        X509Certificate2 certificate,
        RSA privateKey,
        XadesPackaging packaging,
        string? payloadObjectId)
    {
        string signatureId = "id-" + Guid.NewGuid().ToString("N");
        string signedPropertiesId = "sp-" + Guid.NewGuid().ToString("N");
        signedXml.SigningKey = privateKey;
        signedXml.Signature.Id = signatureId;
        SignedInfo signedInfo = signedXml.SignedInfo
            ?? throw new InvalidOperationException("XML signature SignedInfo is missing.");
        signedInfo.CanonicalizationMethod = XadesXmlAlgorithms.ExclusiveCanonicalization;
        signedInfo.SignatureMethod = XadesXmlAlgorithms.RsaSha256;
        signedXml.AddReference(CreateContentReference(packaging, payloadObjectId));
        signedXml.AddReference(CreateSignedPropertiesReference(signedPropertiesId));
        signedXml.AddObject(CreateQualifyingObject(signatureId, signedPropertiesId, certificate));
        signedXml.KeyInfo = new KeyInfo();
        signedXml.KeyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.ComputeSignature();
    }

    private static byte[] SignatureDocument(SignedXml signedXml, bool stripDetachedObject = false)
    {
        XmlElement signature = signedXml.GetXml();
        if (stripDetachedObject)
        {
            XmlElement? payloadObject = null;
            foreach (XmlNode child in signature.ChildNodes)
            {
                if (child is XmlElement element
                    && element.LocalName == "Object"
                    && string.Equals(
                        element.GetAttribute("Id"),
                        XadesXmlAlgorithms.DetachedObjectId,
                        StringComparison.Ordinal))
                {
                    payloadObject = element;
                    break;
                }
            }

            payloadObject?.ParentNode!.RemoveChild(payloadObject);
        }

        XmlDocument result = XadesXmlLoader.CreateEmpty();
        result.AppendChild(result.ImportNode(signature, true));
        return XadesXmlLoader.Save(result);
    }

    private static Reference CreateContentReference(XadesPackaging packaging, string? payloadObjectId)
    {
        Reference reference = new()
        {
            Uri = packaging switch
            {
                XadesPackaging.Enveloped => string.Empty,
                XadesPackaging.Enveloping => "#" + payloadObjectId,
                XadesPackaging.Detached => XadesXmlAlgorithms.DetachedUri,
                _ => throw new ArgumentOutOfRangeException(nameof(packaging))
            },
            DigestMethod = XadesXmlAlgorithms.Sha256Digest
        };
        if (packaging == XadesPackaging.Enveloped)
        {
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        }

        reference.AddTransform(new XmlDsigExcC14NTransform());
        return reference;
    }

    private static Reference CreateSignedPropertiesReference(string signedPropertiesId)
    {
        Reference reference = new()
        {
            Uri = "#" + signedPropertiesId,
            Type = XadesXmlAlgorithms.SignedPropertiesType,
            DigestMethod = XadesXmlAlgorithms.Sha256Digest
        };
        reference.AddTransform(new XmlDsigExcC14NTransform());
        return reference;
    }

    private static DataObject CreatePayloadObject(XmlDocument payload, string payloadObjectId)
    {
        XmlDocument holder = XadesXmlLoader.CreateEmpty();
        XmlElement imported = (XmlElement)holder.ImportNode(payload.DocumentElement!, true);
        return new DataObject(payloadObjectId, string.Empty, string.Empty, imported);
    }

    private static DataObject CreateQualifyingObject(
        string signatureId,
        string signedPropertiesId,
        X509Certificate2 certificate)
    {
        XmlDocument holder = XadesXmlLoader.CreateEmpty();
        XmlElement qualifying = BuildQualifyingProperties(holder, signatureId, signedPropertiesId, certificate);
        return new DataObject(string.Empty, string.Empty, string.Empty, qualifying);
    }

    private static XmlElement BuildQualifyingProperties(
        XmlDocument document,
        string signatureId,
        string signedPropertiesId,
        X509Certificate2 certificate)
    {
        XmlElement qualifying = document.CreateElement("xades", "QualifyingProperties", XadesXmlAlgorithms.XadesNamespace);
        qualifying.SetAttribute("Target", "#" + signatureId);
        XmlElement signedProperties = document.CreateElement("xades", "SignedProperties", XadesXmlAlgorithms.XadesNamespace);
        signedProperties.SetAttribute("Id", signedPropertiesId);
        XmlElement signedSignatureProperties = document.CreateElement(
            "xades",
            "SignedSignatureProperties",
            XadesXmlAlgorithms.XadesNamespace);
        XmlElement signingTime = document.CreateElement("xades", "SigningTime", XadesXmlAlgorithms.XadesNamespace);
        signingTime.InnerText = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        signedSignatureProperties.AppendChild(signingTime);
        signedSignatureProperties.AppendChild(BuildSigningCertificate(document, certificate));
        signedProperties.AppendChild(signedSignatureProperties);
        qualifying.AppendChild(signedProperties);
        return qualifying;
    }

    private static XmlElement BuildSigningCertificate(XmlDocument document, X509Certificate2 certificate)
    {
        XmlElement signingCertificate = document.CreateElement(
            "xades",
            "SigningCertificateV2",
            XadesXmlAlgorithms.XadesNamespace);
        XmlElement cert = document.CreateElement("xades", "Cert", XadesXmlAlgorithms.XadesNamespace);
        XmlElement certDigest = document.CreateElement("xades", "CertDigest", XadesXmlAlgorithms.XadesNamespace);
        XmlElement digestMethod = document.CreateElement("ds", "DigestMethod", SignedXml.XmlDsigNamespaceUrl);
        digestMethod.SetAttribute("Algorithm", XadesXmlAlgorithms.Sha256Digest);
        XmlElement digestValue = document.CreateElement("ds", "DigestValue", SignedXml.XmlDsigNamespaceUrl);
        digestValue.InnerText = Convert.ToBase64String(SHA256.HashData(certificate.RawData));
        certDigest.AppendChild(digestMethod);
        certDigest.AppendChild(digestValue);
        cert.AppendChild(certDigest);
        signingCertificate.AppendChild(cert);
        return signingCertificate;
    }
}
