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
                switch (dictionary.GetValueOrDefault("/Type"))
                {
                    case "/ObjStm":
                        ReadObjectStream(dictionary, data);
                        break;
                    case "/XRef":
                        ReadXrefStream(dictionary, data);
                        break;
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
        if (!dictionary.TryGetValue("/N", out string? countText)
            || !dictionary.TryGetValue("/First", out string? firstText)
            || !int.TryParse(countText, NumberStyles.None, CultureInfo.InvariantCulture, out int count)
            || !int.TryParse(firstText, NumberStyles.None, CultureInfo.InvariantCulture, out int first)
            || !TryDecode(dictionary, data, out byte[] bytes)
            || first > bytes.Length)
        {
            Complete = false;
            return;
        }

        string decoded = Encoding.Latin1.GetString(bytes);

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

    // Free (type 0) entries of a cross-reference stream are deletions, like 'f' entries in a classic table.
    private void ReadXrefStream(IReadOnlyDictionary<string, string> dictionary, string data)
    {
        int[] widths = Numbers(dictionary.GetValueOrDefault("/W"));
        int[] index = dictionary.TryGetValue("/Index", out string? indexText)
            ? Numbers(indexText)
            : [0, DeclaredSizeOf(dictionary)];
        if (widths.Length != 3
            || widths.Any(width => width is < 0 or > 8)
            || index.Length % 2 != 0
            || index.Any(value => value < 0)
            || !TryDecode(dictionary, data, out byte[] decoded))
        {
            Complete = false;
            return;
        }

        int entrySize = widths.Sum();
        int offset = 0;
        for (int section = 0; section < index.Length; section += 2)
        {
            for (int number = index[section]; number < index[section] + index[section + 1]; number++)
            {
                if (entrySize == 0 || offset + entrySize > decoded.Length)
                {
                    Complete = false;
                    return;
                }

                long type = widths[0] == 0 ? 1 : ReadBigEndian(decoded, offset, widths[0]);
                if (type == 0 && number > 0)
                {
                    FreedObjects.Add(number);
                }

                offset += entrySize;
            }
        }
    }

    private static int DeclaredSizeOf(IReadOnlyDictionary<string, string> dictionary) =>
        int.TryParse(dictionary.GetValueOrDefault("/Size"), NumberStyles.None, CultureInfo.InvariantCulture, out int size)
            ? size
            : -1;

    // Parses an array of non-negative integers such as "[0 8 12 3]"; a malformed item yields [-1].
    private static int[] Numbers(string? array)
    {
        if (array is null || !array.StartsWith('[') || !array.EndsWith(']'))
        {
            return [];
        }

        string[] items = array[1..^1].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int[] numbers = new int[items.Length];
        for (int item = 0; item < items.Length; item++)
        {
            if (!int.TryParse(items[item], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[item]))
            {
                return [-1];
            }
        }

        return numbers;
    }

    private static long ReadBigEndian(byte[] data, int offset, int width)
    {
        long value = 0;
        for (int index = 0; index < width; index++)
        {
            value = (value << 8) | data[offset + index];
        }

        return value;
    }

    // Supports unfiltered and FlateDecode streams, with or without the PNG predictors that
    // cross-reference streams usually carry. Anything else is reported as undecodable.
    private static bool TryDecode(IReadOnlyDictionary<string, string> dictionary, string data, out byte[] decoded)
    {
        decoded = Encoding.Latin1.GetBytes(data);
        if (!dictionary.TryGetValue("/Filter", out string? filter))
        {
            return !dictionary.ContainsKey("/DecodeParms");
        }

        if (filter.Trim('[', ']', ' ') != "/FlateDecode" || !TryInflate(decoded, out decoded))
        {
            return false;
        }

        if (!dictionary.TryGetValue("/DecodeParms", out string? parametersText))
        {
            return true;
        }

        string parametersDictionary = parametersText.Trim('[', ']', ' ');
        if (!parametersDictionary.StartsWith("<<", StringComparison.Ordinal))
        {
            return false;
        }

        IReadOnlyDictionary<string, string> parameters = PdfSyntax.ParseDictionary(parametersDictionary);
        int predictor = Parameter(parameters, "/Predictor", 1);
        if (predictor == 1)
        {
            return true;
        }

        return predictor >= 10
            && Parameter(parameters, "/Colors", 1) == 1
            && Parameter(parameters, "/BitsPerComponent", 8) == 8
            && TryUndoPngPredictor(decoded, Parameter(parameters, "/Columns", 1), out decoded);
    }

    private static int Parameter(IReadOnlyDictionary<string, string> parameters, string key, int fallback) =>
        !parameters.TryGetValue(key, out string? value)
            ? fallback
            : int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int number) ? number : -1;

    // PNG predictors (ISO 32000-1, 7.4.4.4) with one byte per pixel: each row starts with its filter type.
    private static bool TryUndoPngPredictor(byte[] encoded, int columns, out byte[] decoded)
    {
        decoded = [];
        if (columns < 1 || encoded.Length % (columns + 1) != 0)
        {
            return false;
        }

        int rows = encoded.Length / (columns + 1);
        byte[] output = new byte[rows * columns];
        for (int row = 0; row < rows; row++)
        {
            int source = row * (columns + 1);
            int target = row * columns;
            byte filter = encoded[source];
            for (int column = 0; column < columns; column++)
            {
                int left = column > 0 ? output[target + column - 1] : 0;
                int up = row > 0 ? output[target - columns + column] : 0;
                int upperLeft = row > 0 && column > 0 ? output[target - columns + column - 1] : 0;
                int raw = encoded[source + 1 + column];
                int value = filter switch
                {
                    0 => raw,
                    1 => raw + left,
                    2 => raw + up,
                    3 => raw + ((left + up) / 2),
                    4 => raw + Paeth(left, up, upperLeft),
                    _ => -1
                };
                if (value < 0)
                {
                    return false;
                }

                output[target + column] = (byte)value;
            }
        }

        decoded = output;
        return true;
    }

    private static int Paeth(int left, int up, int upperLeft)
    {
        int estimate = left + up - upperLeft;
        int distanceLeft = Math.Abs(estimate - left);
        int distanceUp = Math.Abs(estimate - up);
        int distanceUpperLeft = Math.Abs(estimate - upperLeft);
        return distanceLeft <= distanceUp && distanceLeft <= distanceUpperLeft
            ? left
            : distanceUp <= distanceUpperLeft ? up : upperLeft;
    }

    private static bool TryInflate(byte[] compressed, out byte[] decoded)
    {
        decoded = [];
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

            decoded = output.ToArray();
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
