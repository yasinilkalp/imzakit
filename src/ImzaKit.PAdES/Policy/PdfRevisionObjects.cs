using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace ImzaKit.PAdES.Policy;

internal sealed record PdfObjectDefinition(
    int Number,
    string Body,
    IReadOnlyDictionary<string, string> Dictionary,
    bool IsStream)
{
    public string? Name(string key) =>
        Dictionary.TryGetValue(key, out string? value) && value.StartsWith('/') ? value : null;

    public bool Has(string key) => Dictionary.ContainsKey(key);
}

// Reads the objects defined inside one byte range of a PDF (one or more incremental revisions),
// including objects packed into object streams, so revisions can be compared object by object.
internal sealed partial class PdfRevisionObjects
{
    private const int MaxDecodedObjectStreamBytes = 16 * 1024 * 1024;

    private PdfRevisionObjects()
    {
    }

    public Dictionary<int, PdfObjectDefinition> Objects { get; } = [];

    public HashSet<int> FreedObjects { get; } = [];

    public int? DeclaredSize { get; private set; }

    public int? RootObject { get; private set; }

    // False when some objects in the range could not be read (undecodable object streams).
    public bool Complete { get; private set; } = true;

    public static PdfRevisionObjects Read(ReadOnlySpan<byte> pdf, int start, int end)
    {
        string text = Encoding.Latin1.GetString(pdf);
        PdfRevisionObjects result = new();
        int position = start;
        while (position < end)
        {
            Match header = ObjectHeader().Match(text, position);
            if (!header.Success || header.Index >= end)
            {
                break;
            }

            int number = int.Parse(header.Groups[1].Value, CultureInfo.InvariantCulture);
            position = result.ReadObject(text, number, header.Index + header.Length, end);
        }

        string range = text[start..end];
        if (LastNumberAfter(SizeToken(), range) is int size)
        {
            result.DeclaredSize = size;
        }

        result.RootObject = LastNumberAfter(RootToken(), range);
        result.ReadFreedObjects(range);
        return result;
    }

    private int ReadObject(string text, int number, int bodyStart, int end)
    {
        int index = PdfSyntax.SkipWhitespace(text, bodyStart);
        int endObject = text.IndexOf("endobj", index, StringComparison.Ordinal);
        if (index + 1 < text.Length && text[index] == '<' && text[index + 1] == '<')
        {
            int dictionaryEnd = PdfSyntax.FindDictionaryEnd(text, index);
            if (dictionaryEnd < 0)
            {
                Complete = false;
                return endObject < 0 ? end : endObject + 6;
            }

            string dictionaryText = text[index..dictionaryEnd];
            IReadOnlyDictionary<string, string> dictionary = PdfSyntax.ParseDictionary(dictionaryText);
            int afterDictionary = PdfSyntax.SkipWhitespace(text, dictionaryEnd);
            if (string.CompareOrdinal(text, afterDictionary, "stream", 0, 6) == 0)
            {
                int dataStart = afterDictionary + 6;
                dataStart += text[dataStart] == '\r' ? 2 : 1;
                int dataEnd = StreamEnd(text, dictionary, dataStart);
                string data = text[dataStart..dataEnd];
                Add(new PdfObjectDefinition(number, dictionaryText + "stream" + data, dictionary, IsStream: true));
                if (dictionary.TryGetValue("/Type", out string? type) && type == "/ObjStm")
                {
                    ReadObjectStream(dictionary, data);
                }

                endObject = text.IndexOf("endobj", dataEnd, StringComparison.Ordinal);
            }
            else
            {
                Add(new PdfObjectDefinition(number, dictionaryText, dictionary, IsStream: false));
                endObject = text.IndexOf("endobj", dictionaryEnd, StringComparison.Ordinal);
            }
        }
        else
        {
            string body = endObject < 0 ? text[index..end] : text[index..endObject];
            Add(new PdfObjectDefinition(number, PdfSyntax.Normalize(body), new Dictionary<string, string>(), IsStream: false));
        }

        return endObject < 0 ? end : endObject + 6;
    }

    // Cross-reference and object streams are containers, not document objects.
    private void Add(PdfObjectDefinition definition)
    {
        if (definition.Name("/Type") is not ("/XRef" or "/ObjStm"))
        {
            Objects[definition.Number] = definition;
        }
    }

    private static int StreamEnd(string text, IReadOnlyDictionary<string, string> dictionary, int dataStart)
    {
        if (dictionary.TryGetValue("/Length", out string? lengthText)
            && int.TryParse(lengthText, NumberStyles.None, CultureInfo.InvariantCulture, out int length)
            && dataStart + length <= text.Length
            && text.IndexOf("endstream", dataStart + length, StringComparison.Ordinal) is int marker
            && marker >= 0
            && string.IsNullOrWhiteSpace(text[(dataStart + length)..marker]))
        {
            return dataStart + length;
        }

        int fallback = text.IndexOf("endstream", dataStart, StringComparison.Ordinal);
        return fallback < 0 ? text.Length : fallback;
    }

    private void ReadObjectStream(IReadOnlyDictionary<string, string> dictionary, string data)
    {
        if (dictionary.ContainsKey("/DecodeParms")
            || !dictionary.TryGetValue("/Filter", out string? filter)
            || filter.Trim('[', ']', ' ') != "/FlateDecode"
            || !dictionary.TryGetValue("/N", out string? countText)
            || !dictionary.TryGetValue("/First", out string? firstText)
            || !int.TryParse(countText, NumberStyles.None, CultureInfo.InvariantCulture, out int count)
            || !int.TryParse(firstText, NumberStyles.None, CultureInfo.InvariantCulture, out int first)
            || !TryInflate(Encoding.Latin1.GetBytes(data), out string decoded)
            || first > decoded.Length)
        {
            Complete = false;
            return;
        }

        string[] header = decoded[..first].Split((char[])[' ', '\r', '\n', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (header.Length < count * 2)
        {
            Complete = false;
            return;
        }

        for (int item = 0; item < count; item++)
        {
            if (!int.TryParse(header[item * 2], NumberStyles.None, CultureInfo.InvariantCulture, out int number)
                || !int.TryParse(header[(item * 2) + 1], NumberStyles.None, CultureInfo.InvariantCulture, out int offset)
                || first + offset > decoded.Length)
            {
                Complete = false;
                return;
            }

            int bodyStart = first + offset;
            int bodyEnd = decoded.Length;
            if (item + 1 < count
                && int.TryParse(header[(item * 2) + 3], NumberStyles.None, CultureInfo.InvariantCulture, out int next)
                && first + next >= bodyStart
                && first + next <= decoded.Length)
            {
                bodyEnd = first + next;
            }

            string body = decoded[bodyStart..bodyEnd].Trim();
            Add(body.StartsWith("<<", StringComparison.Ordinal)
                ? new PdfObjectDefinition(number, body, PdfSyntax.ParseDictionary(body), IsStream: false)
                : new PdfObjectDefinition(number, PdfSyntax.Normalize(body), new Dictionary<string, string>(), IsStream: false));
        }
    }

    private static bool TryInflate(byte[] compressed, out string decoded)
    {
        decoded = "";
        try
        {
            using MemoryStream input = new(compressed);
            using ZLibStream inflater = new(input, CompressionMode.Decompress);
            using MemoryStream output = new();
            byte[] buffer = new byte[81920];
            int read;
            while ((read = inflater.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + read > MaxDecodedObjectStreamBytes)
                {
                    return false;
                }

                output.Write(buffer, 0, read);
            }

            decoded = Encoding.Latin1.GetString(output.ToArray());
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private void ReadFreedObjects(string range)
    {
        foreach (Match section in ClassicXref().Matches(range))
        {
            int start = int.Parse(section.Groups[1].Value, CultureInfo.InvariantCulture);
            int number = start;
            foreach (Capture entry in section.Groups[2].Captures)
            {
                if (entry.Value.EndsWith('f') && number > 0)
                {
                    FreedObjects.Add(number);
                }

                number++;
            }
        }
    }

    private static int? LastNumberAfter(Regex token, string range)
    {
        MatchCollection matches = token.Matches(range);
        return matches.Count == 0
            ? null
            : int.Parse(matches[^1].Groups[1].Value, CultureInfo.InvariantCulture);
    }

    [GeneratedRegex(@"(?<![0-9])([0-9]{1,10})\s+[0-9]{1,5}\s+obj\b")]
    private static partial Regex ObjectHeader();

    [GeneratedRegex(@"/Size\s+([0-9]{1,10})")]
    private static partial Regex SizeToken();

    [GeneratedRegex(@"/Root\s+([0-9]{1,10})\s+[0-9]{1,5}\s+R")]
    private static partial Regex RootToken();

    [GeneratedRegex(@"([0-9]{1,10})\s+[0-9]{1,10}\s*\r?\n(?:([0-9]{10}\s[0-9]{5}\s[nf])\s*\r?\n?)+")]
    private static partial Regex ClassicXref();
}
