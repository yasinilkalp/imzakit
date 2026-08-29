using System.Text;
using System.Xml;

namespace ImzaKit.XAdES;

internal static class XadesXmlLoader
{
    private const int MaxCharactersInDocument = 10_000_000;

    public static XmlDocument CreateEmpty()
    {
        return new XmlDocument
        {
            XmlResolver = null,
            PreserveWhitespace = true
        };
    }

    public static XmlDocument Load(ReadOnlySpan<byte> xml)
    {
        XmlReaderSettings settings = new()
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
            MaxCharactersInDocument = MaxCharactersInDocument
        };
        using MemoryStream stream = new(xml.ToArray(), writable: false);
        using XmlReader reader = XmlReader.Create(stream, settings);
        XmlDocument document = CreateEmpty();
        document.Load(reader);
        return document;
    }

    public static byte[] Save(XmlDocument document)
    {
        using MemoryStream stream = new();
        XmlWriterSettings settings = new()
        {
            Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            OmitXmlDeclaration = false,
            Indent = false,
            CloseOutput = false
        };
        using (XmlWriter writer = XmlWriter.Create(stream, settings))
        {
            document.Save(writer);
        }

        return stream.ToArray();
    }
}
