using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ImzaKit.XAdES;

// The octets XAdES time-stamps cover (ETSI EN 319 132-1): a signature time-stamp covers the canonicalized
// ds:SignatureValue element (5.3); an archive time-stamp covers the referenced data, ds:SignedInfo,
// ds:SignatureValue, ds:KeyInfo, the unsigned signature properties before it and the other ds:Object
// elements (5.5.2). Null means the input cannot be reproduced here, so the time-stamp cannot be relied on.
internal static class XadesTimeStampInput
{
    private const string XmlnsNamespace = "http://www.w3.org/2000/xmlns/";

    public static bool IsSupportedCanonicalization(string? algorithm) =>
        algorithm is XadesXmlAlgorithms.ExclusiveCanonicalization or XadesXmlAlgorithms.InclusiveCanonicalization;

    public static byte[]? ForSignatureTimeStamp(XmlElement signature, string canonicalization)
    {
        XmlElement? signatureValue = XadesXmlTree.Child(signature, "SignatureValue", SignedXml.XmlDsigNamespaceUrl);
        return signatureValue is null || !IsSupportedCanonicalization(canonicalization)
            ? null
            : Canonicalize(signatureValue, canonicalization);
    }

    // archiveTimeStamp is the time-stamp being verified, or null when computing the input for a new one.
    public static byte[]? ForArchiveTimeStamp(XmlElement signature, XmlElement? archiveTimeStamp, string canonicalization)
    {
        if (!IsSupportedCanonicalization(canonicalization)
            || XadesXmlTree.Child(signature, "SignedInfo", SignedXml.XmlDsigNamespaceUrl) is not XmlElement signedInfo
            || XadesXmlTree.Child(signature, "SignatureValue", SignedXml.XmlDsigNamespaceUrl) is not XmlElement signatureValue)
        {
            return null;
        }

        using MemoryStream input = new();
        foreach (XmlElement reference in XadesXmlTree.Children(signedInfo, "Reference", SignedXml.XmlDsigNamespaceUrl))
        {
            byte[]? data = ReferencedData(signature, reference);
            if (data is null)
            {
                return null;
            }

            input.Write(data);
        }

        input.Write(Canonicalize(signedInfo, canonicalization));
        input.Write(Canonicalize(signatureValue, canonicalization));
        if (XadesXmlTree.Child(signature, "KeyInfo", SignedXml.XmlDsigNamespaceUrl) is XmlElement keyInfo)
        {
            input.Write(Canonicalize(keyInfo, canonicalization));
        }

        if (XadesXmlTree.UnsignedSignatureProperties(signature) is XmlElement properties)
        {
            foreach (XmlNode property in properties.ChildNodes)
            {
                if (property == archiveTimeStamp)
                {
                    break;
                }

                if (property is XmlElement element)
                {
                    input.Write(Canonicalize(element, canonicalization));
                }
            }
        }

        // The detached payload is injected only to resolve its reference; it is not part of the signature.
        foreach (XmlElement dataObject in XadesXmlTree.Children(signature, "Object", SignedXml.XmlDsigNamespaceUrl))
        {
            if (XadesXmlTree.Child(dataObject, "QualifyingProperties", XadesXmlAlgorithms.XadesNamespace) is null
                && dataObject.GetAttribute("Id") != XadesXmlAlgorithms.DetachedObjectId)
            {
                input.Write(Canonicalize(dataObject, canonicalization));
            }
        }

        return input.ToArray();
    }

    // Same-document references only: "" with the enveloped-signature transform, or "#id", each followed by
    // at most one canonicalization; without one, the node-set becomes octets through inclusive C14N.
    private static byte[]? ReferencedData(XmlElement signature, XmlElement reference)
    {
        List<string> transforms = [];
        if (XadesXmlTree.Child(reference, "Transforms", SignedXml.XmlDsigNamespaceUrl) is XmlElement transformList)
        {
            foreach (XmlNode node in transformList.ChildNodes)
            {
                if (node is not XmlElement transform)
                {
                    continue;
                }

                if (transform.LocalName != "Transform"
                    || transform.NamespaceURI != SignedXml.XmlDsigNamespaceUrl
                    || transform.ChildNodes.OfType<XmlElement>().Any())
                {
                    return null;
                }

                transforms.Add(transform.GetAttribute("Algorithm"));
            }
        }

        bool enveloped = transforms.Count > 0 && transforms[0] == XadesXmlAlgorithms.EnvelopedSignature;
        List<string> canonicalizations = enveloped ? transforms[1..] : transforms;
        string? canonicalization = canonicalizations.Count switch
        {
            0 => XadesXmlAlgorithms.InclusiveCanonicalization,
            1 when IsSupportedCanonicalization(canonicalizations[0]) => canonicalizations[0],
            _ => null
        };
        if (canonicalization is null || !reference.HasAttribute("URI"))
        {
            return null;
        }

        string uri = reference.GetAttribute("URI");
        XmlDocument document = signature.OwnerDocument;
        if (uri.Length == 0)
        {
            return enveloped ? CanonicalizeWithout(document, signature, canonicalization) : null;
        }

        if (enveloped || uri[0] != '#')
        {
            return null;
        }

        XmlElement? target;
        try
        {
            target = PolicySignedXml.FindUniqueId(document.DocumentElement, uri[1..]);
        }
        catch (CryptographicException)
        {
            return null;
        }

        return target is null ? null : Canonicalize(target, canonicalization);
    }

    private static byte[] CanonicalizeWithout(XmlDocument document, XmlElement signature, string canonicalization)
    {
        XmlNode parent = signature.ParentNode!;
        XmlNode? next = signature.NextSibling;
        parent.RemoveChild(signature);
        try
        {
            return Canonicalize(document, canonicalization);
        }
        finally
        {
            parent.InsertBefore(signature, next);
        }
    }

    // Canonicalizes the element as a document subset: the namespace declarations in scope travel with it,
    // as they do for same-document references in XML signatures.
    private static byte[] Canonicalize(XmlElement element, string canonicalization)
    {
        XmlDocument holder = XadesXmlLoader.CreateEmpty();
        XmlElement copy = (XmlElement)holder.ImportNode(element, deep: true);
        for (XmlNode? scope = element.ParentNode; scope is XmlElement ancestor; scope = ancestor.ParentNode)
        {
            foreach (XmlAttribute attribute in ancestor.Attributes)
            {
                if (attribute.NamespaceURI == XmlnsNamespace && !copy.HasAttribute(attribute.Name))
                {
                    copy.SetAttributeNode((XmlAttribute)holder.ImportNode(attribute, deep: true));
                }
            }
        }

        holder.AppendChild(copy);
        return Canonicalize(holder, canonicalization);
    }

    private static byte[] Canonicalize(XmlDocument document, string canonicalization)
    {
        Transform transform = canonicalization == XadesXmlAlgorithms.ExclusiveCanonicalization
            ? new XmlDsigExcC14NTransform()
            : new XmlDsigC14NTransform();
        transform.LoadInput(document);
        using Stream output = (Stream)transform.GetOutput(typeof(Stream));
        using MemoryStream buffer = new();
        output.CopyTo(buffer);
        return buffer.ToArray();
    }
}
