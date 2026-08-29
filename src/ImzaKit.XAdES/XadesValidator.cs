using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ImzaKit.XAdES;

public static class XadesValidator
{
    public static XadesValidationReport Validate(
        ReadOnlySpan<byte> signedXml,
        ReadOnlySpan<byte> detachedContent = default)
    {
        XmlDocument document;
        try
        {
            document = XadesXmlLoader.Load(signedXml);
        }
        catch (XmlException)
        {
            return Failed(XadesPackaging.Enveloped, ["InvalidXml"]);
        }

        XmlElement? signatureElement = XadesXmlTree.Find(document, "Signature", SignedXml.XmlDsigNamespaceUrl);
        if (signatureElement is null)
        {
            return Failed(XadesPackaging.Enveloped, ["SignatureMissing"]);
        }

        List<string> findings = [];
        if (!InspectAlgorithms(signatureElement, findings))
        {
            return new(XadesStatus.Failed, DetectPackaging(signatureElement), XadesBaselineLevel.BB, null, findings);
        }

        XadesPackaging packaging = DetectPackaging(signatureElement);
        if (packaging == XadesPackaging.Detached)
        {
            if (detachedContent.IsEmpty)
            {
                return Failed(packaging, ["DetachedContentMissing"]);
            }

            try
            {
                InjectDetachedPayload(document, signatureElement, detachedContent.ToArray());
            }
            catch (XmlException)
            {
                return Failed(packaging, ["InvalidXml"]);
            }
        }

        PolicySignedXml signedXmlVerifier;
        try
        {
            signedXmlVerifier = new PolicySignedXml(document);
            signedXmlVerifier.LoadXml(signatureElement);
        }
        catch (CryptographicException)
        {
            return Failed(DetectPackaging(signatureElement), ["InvalidSignatureXml"]);
        }

        X509Certificate2? certificate = ReadSignerCertificate(signatureElement);
        string? fingerprint = certificate is null ? null : Convert.ToHexString(SHA256.HashData(certificate.RawData));
        if (certificate is null)
        {
            findings.Add("SignerCertificateMissing");
            return new(
                XadesStatus.Failed,
                DetectPackaging(signatureElement),
                DetectLevel(signatureElement),
                fingerprint,
                findings);
        }

        bool crypto;
        try
        {
            crypto = signedXmlVerifier.CheckSignature(certificate, verifySignatureOnly: true);
        }
        catch (Exception ex) when (ex is CryptographicException or XmlException or InvalidOperationException)
        {
            findings.Add("XmlSignatureInvalid");
            return new(
                XadesStatus.Failed,
                DetectPackaging(signatureElement),
                DetectLevel(signatureElement),
                fingerprint,
                findings);
        }

        if (!crypto)
        {
            findings.Add("XmlSignatureInvalid");
        }

        return new(
            crypto ? XadesStatus.Passed : XadesStatus.Failed,
            DetectPackaging(signatureElement),
            DetectLevel(signatureElement),
            fingerprint,
            findings);
    }

    internal static string DetectLevel(XmlNode signatureElement)
    {
        bool timestamp = XadesXmlTree.Has(signatureElement, "SignatureTimeStamp", XadesXmlAlgorithms.XadesNamespace);
        bool longTerm = XadesXmlTree.Has(signatureElement, "CertificateValues", XadesXmlAlgorithms.XadesNamespace)
            || XadesXmlTree.Has(signatureElement, "RevocationValues", XadesXmlAlgorithms.XadesNamespace);
        bool archive = XadesXmlTree.Has(signatureElement, "ArchiveTimeStamp", XadesXmlAlgorithms.XadesNamespace);
        return (timestamp, longTerm, archive) switch
        {
            (true, true, true) => XadesBaselineLevel.BLTA,
            (true, true, false) => XadesBaselineLevel.BLT,
            (true, false, _) => XadesBaselineLevel.BT,
            _ => XadesBaselineLevel.BB
        };
    }

    private static XadesValidationReport Failed(XadesPackaging packaging, IReadOnlyList<string> findings) =>
        new(XadesStatus.Failed, packaging, XadesBaselineLevel.BB, null, findings);

    private static void InjectDetachedPayload(XmlDocument document, XmlElement signatureElement, byte[] content)
    {
        XmlDocument payload = XadesXmlLoader.Load(content);
        if (payload.DocumentElement is null)
        {
            throw new XmlException("Detached XML document element is missing.");
        }

        XmlElement objectElement = document.CreateElement("Object", SignedXml.XmlDsigNamespaceUrl);
        objectElement.SetAttribute("Id", XadesXmlAlgorithms.DetachedObjectId);
        objectElement.AppendChild(document.ImportNode(payload.DocumentElement, true));
        signatureElement.AppendChild(objectElement);
    }

    private static XadesPackaging DetectPackaging(XmlElement signatureElement)
    {
        if (HasReferenceUri(signatureElement, XadesXmlAlgorithms.DetachedUri))
        {
            return XadesPackaging.Detached;
        }

        if (signatureElement.ParentNode is XmlElement)
        {
            return XadesPackaging.Enveloped;
        }

        return XadesPackaging.Enveloping;
    }

    private static bool HasReferenceUri(XmlElement signatureElement, string uri)
    {
        foreach (XmlElement reference in XadesXmlTree.FindAll(signatureElement, "Reference", SignedXml.XmlDsigNamespaceUrl))
        {
            if (string.Equals(reference.GetAttribute("URI"), uri, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool InspectAlgorithms(XmlElement signatureElement, List<string> findings)
    {
        XmlElement signedInfo = XadesXmlTree.Require(signatureElement, "SignedInfo", SignedXml.XmlDsigNamespaceUrl);
        XmlElement canonicalization = XadesXmlTree.Require(
            signedInfo,
            "CanonicalizationMethod",
            SignedXml.XmlDsigNamespaceUrl);
        if (!XadesXmlAlgorithms.IsAllowedCanonicalization(canonicalization.GetAttribute("Algorithm")))
        {
            findings.Add("CanonicalizationNotAllowed");
        }

        XmlElement signatureMethod = XadesXmlTree.Require(signedInfo, "SignatureMethod", SignedXml.XmlDsigNamespaceUrl);
        if (!XadesXmlAlgorithms.IsAllowedSignatureMethod(signatureMethod.GetAttribute("Algorithm")))
        {
            findings.Add("SignatureMethodNotAllowed");
        }

        foreach (XmlElement reference in XadesXmlTree.FindAll(signedInfo, "Reference", SignedXml.XmlDsigNamespaceUrl))
        {
            if (!XadesXmlAlgorithms.IsAllowedReferenceUri(reference.GetAttribute("URI")))
            {
                findings.Add("ExternalUriDereferenceDisabled");
            }

            XmlElement digestMethod = XadesXmlTree.Require(reference, "DigestMethod", SignedXml.XmlDsigNamespaceUrl);
            if (!XadesXmlAlgorithms.IsAllowedDigest(digestMethod.GetAttribute("Algorithm")))
            {
                findings.Add("DigestMethodNotAllowed");
            }

            foreach (XmlElement transform in XadesXmlTree.FindAll(reference, "Transform", SignedXml.XmlDsigNamespaceUrl))
            {
                if (!XadesXmlAlgorithms.IsAllowedTransform(transform.GetAttribute("Algorithm")))
                {
                    findings.Add("TransformNotAllowed");
                }
            }
        }

        return findings.Count == 0;
    }

    private static X509Certificate2? ReadSignerCertificate(XmlElement signatureElement)
    {
        XmlElement? x509 = XadesXmlTree.Find(signatureElement, "X509Certificate", SignedXml.XmlDsigNamespaceUrl);
        if (x509 is null || string.IsNullOrWhiteSpace(x509.InnerText))
        {
            return null;
        }

        try
        {
            return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x509.InnerText.Trim()));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return null;
        }
    }
}
