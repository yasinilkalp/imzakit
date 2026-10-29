using System.Security.Cryptography.Xml;
using System.Xml;

namespace ImzaKit.XAdES;

internal static class XadesXmlTree
{
    public static XmlElement? Find(XmlNode node, string localName, string namespaceUri)
    {
        if (node is XmlElement self
            && self.LocalName == localName
            && self.NamespaceURI == namespaceUri)
        {
            return self;
        }

        foreach (XmlNode child in node.ChildNodes)
        {
            XmlElement? found = Find(child, localName, namespaceUri);
            if (found is not null)
            {
                return found;
            }
        }

        return null;
    }

    public static XmlElement Require(XmlNode node, string localName, string namespaceUri)
    {
        return Find(node, localName, namespaceUri)
            ?? throw new InvalidOperationException($"XML element {localName} is missing.");
    }

    public static bool Has(XmlNode node, string localName, string namespaceUri) =>
        Find(node, localName, namespaceUri) is not null;

    public static XmlElement? Child(XmlNode parent, string localName, string namespaceUri) =>
        Children(parent, localName, namespaceUri).FirstOrDefault();

    public static IEnumerable<XmlElement> Children(XmlNode parent, string localName, string namespaceUri)
    {
        foreach (XmlNode child in parent.ChildNodes)
        {
            if (child is XmlElement element
                && element.LocalName == localName
                && element.NamespaceURI == namespaceUri)
            {
                yield return element;
            }
        }
    }

    // The signature's own qualifying properties (a direct ds:Object child), never ones nested in signed content.
    public static XmlElement? QualifyingProperties(XmlElement signature)
    {
        foreach (XmlElement dataObject in Children(signature, "Object", SignedXml.XmlDsigNamespaceUrl))
        {
            XmlElement? qualifying = Child(dataObject, "QualifyingProperties", XadesXmlAlgorithms.XadesNamespace);
            if (qualifying is not null)
            {
                return qualifying;
            }
        }

        return null;
    }

    public static XmlElement? UnsignedSignatureProperties(XmlElement signature)
    {
        XmlElement? unsignedProperties = QualifyingProperties(signature) is XmlElement qualifying
            ? Child(qualifying, "UnsignedProperties", XadesXmlAlgorithms.XadesNamespace)
            : null;
        return unsignedProperties is null
            ? null
            : Child(unsignedProperties, "UnsignedSignatureProperties", XadesXmlAlgorithms.XadesNamespace);
    }

    public static bool HasUnsignedProperty(XmlElement signature, string localName, string namespaceUri) =>
        UnsignedSignatureProperties(signature) is XmlElement properties
        && Child(properties, localName, namespaceUri) is not null;

    public static IEnumerable<XmlElement> FindAll(XmlNode node, string localName, string namespaceUri)
    {
        if (node is XmlElement self
            && self.LocalName == localName
            && self.NamespaceURI == namespaceUri)
        {
            yield return self;
        }

        foreach (XmlNode child in node.ChildNodes)
        {
            foreach (XmlElement found in FindAll(child, localName, namespaceUri))
            {
                yield return found;
            }
        }
    }
}
