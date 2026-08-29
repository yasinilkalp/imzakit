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
