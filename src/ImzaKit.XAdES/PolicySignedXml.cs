using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ImzaKit.XAdES;

internal sealed class PolicySignedXml : SignedXml
{
    public PolicySignedXml(XmlDocument document)
        : base(document)
    {
        Configure();
    }

    public PolicySignedXml()
    {
        Configure();
    }

    public override XmlElement? GetIdElement(XmlDocument? document, string idValue)
    {
        if (string.IsNullOrEmpty(idValue))
        {
            return null;
        }

        XmlElement? fromDocument = FindUniqueId(document?.DocumentElement, idValue);
        if (fromDocument is not null)
        {
            return fromDocument;
        }

        XmlElement? fromObjects = null;
        foreach (object obj in Signature.ObjectList)
        {
            if (obj is not DataObject dataObject)
            {
                continue;
            }

            XmlElement? found = FindUniqueId(dataObject.GetXml(), idValue);
            if (found is null)
            {
                continue;
            }

            if (fromObjects is not null)
            {
                throw new CryptographicException("XML signature Id is not unique.");
            }

            fromObjects = found;
        }

        return fromObjects;
    }

    private void Configure()
    {
        SafeCanonicalizationMethods.Clear();
        SafeCanonicalizationMethods.Add(XadesXmlAlgorithms.ExclusiveCanonicalization);
        Resolver = DisabledXmlResolver.Instance;
    }

    private static XmlElement? FindUniqueId(XmlElement? root, string idValue)
    {
        if (root is null)
        {
            return null;
        }

        XmlElement? match = null;
        foreach (XmlElement element in EnumerateElements(root))
        {
            if (!HasId(element, idValue))
            {
                continue;
            }

            if (match is not null)
            {
                throw new CryptographicException("XML signature Id is not unique.");
            }

            match = element;
        }

        return match;
    }

    private static IEnumerable<XmlElement> EnumerateElements(XmlElement root)
    {
        yield return root;
        foreach (XmlNode node in root.GetElementsByTagName("*"))
        {
            if (node is XmlElement element)
            {
                yield return element;
            }
        }
    }

    private static bool HasId(XmlElement element, string idValue)
    {
        string id = element.GetAttribute("Id");
        if (id.Length == 0)
        {
            id = element.GetAttribute("id");
        }

        if (id.Length == 0)
        {
            id = element.GetAttribute("id", "http://www.w3.org/XML/1998/namespace");
        }

        return string.Equals(id, idValue, StringComparison.Ordinal);
    }

    private sealed class DisabledXmlResolver : XmlResolver
    {
        public static DisabledXmlResolver Instance { get; } = new();

        public override ICredentials? Credentials
        {
            set { }
        }

        public override object GetEntity(Uri absoluteUri, string? role, Type? ofObjectToReturn) =>
            throw new InvalidOperationException("External URI dereference is disabled.");
    }
}
