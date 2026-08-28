using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ImzaKit.PAdES.Incremental;

internal static class PdfIncrementalSyntax
{
    internal const int ByteRangeNumberWidth = 20;

    internal static void WriteAscii(MemoryStream stream, string text)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        stream.Write(bytes);
    }

    internal static string BuildXref(
        List<(int Number, long Offset)> entries,
        int trailerSize,
        int rootObjectNumber,
        int previousXref,
        long xrefOffset)
    {
        entries.Sort((left, right) => left.Number.CompareTo(right.Number));
        StringBuilder xref = new("xref\n");
        int index = 0;
        while (index < entries.Count)
        {
            int start = entries[index].Number;
            int count = 1;
            while (index + count < entries.Count &&
                   entries[index + count].Number == start + count)
            {
                count++;
            }

            xref.Append(CultureInfo.InvariantCulture, $"{start} {count}\n");
            for (int offset = 0; offset < count; offset++)
            {
                xref.Append(CultureInfo.InvariantCulture, $"{entries[index + offset].Offset:0000000000} 00000 n \n");
            }

            index += count;
        }

        xref.Append(CultureInfo.InvariantCulture,
            $"trailer\n<< /Size {trailerSize} /Root {rootObjectNumber} 0 R /Prev {previousXref} >>\n" +
            $"startxref\n{xrefOffset}\n%%EOF\n");
        return xref.ToString();
    }

    internal static int ReadIntegerAfterLastToken(string source, string token)
    {
        int tokenIndex = source.LastIndexOf(token, StringComparison.Ordinal);
        if (tokenIndex < 0)
        {
            throw new NotSupportedException($"PDF does not contain required {token} metadata.");
        }

        ReadOnlySpan<char> remainder = source.AsSpan(tokenIndex + token.Length).TrimStart();
        int digitCount = 0;
        while (digitCount < remainder.Length && char.IsAsciiDigit(remainder[digitCount]))
        {
            digitCount++;
        }

        if (digitCount == 0 ||
            !int.TryParse(remainder[..digitCount], NumberStyles.None, CultureInfo.InvariantCulture, out int value))
        {
            throw new NotSupportedException($"PDF contains invalid {token} metadata.");
        }

        return value;
    }

    internal static string ReadObjectDictionary(string source, int objectNumber)
    {
        int objectIndex = IndexOfGenerationZeroObject(source, objectNumber);
        if (objectIndex < 0)
        {
            throw new NotSupportedException($"PDF object {objectNumber} must be an uncompressed generation-zero object.");
        }

        int headerLength = $"{objectNumber} 0 obj".Length;
        int dictionaryStart = source.IndexOf("<<", objectIndex + headerLength, StringComparison.Ordinal);
        int dictionaryEnd = dictionaryStart < 0 ? -1 : FindMatchingDictionaryEnd(source, dictionaryStart);
        if (dictionaryStart < 0 || dictionaryEnd < 0)
        {
            throw new NotSupportedException($"PDF object {objectNumber} dictionary could not be read.");
        }

        return source[dictionaryStart..(dictionaryEnd + 2)];
    }

    internal static int ReadReferenceNumber(string dictionary, string token)
    {
        Match match = Regex.Match(dictionary, $@"{Regex.Escape(token)}\s+(\d+)\s+0\s+R");
        if (!match.Success)
        {
            throw new NotSupportedException($"PDF dictionary does not contain {token}.");
        }

        return int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
    }

    internal static string AppendFieldReference(string acroFormDictionary, int fieldObjectNumber)
    {
        Match fields = Regex.Match(acroFormDictionary, @"/Fields\s*\[(.*?)\]", RegexOptions.Singleline);
        if (!fields.Success)
        {
            throw new NotSupportedException("Existing AcroForm does not contain a Fields array.");
        }

        string existing = fields.Groups[1].Value.Trim();
        string updated = string.IsNullOrEmpty(existing)
            ? $"{fieldObjectNumber} 0 R"
            : $"{existing} {fieldObjectNumber} 0 R";
        return string.Concat(
            acroFormDictionary.AsSpan(0, fields.Index),
            $"/Fields [{updated}]",
            acroFormDictionary.AsSpan(fields.Index + fields.Length));
    }

    internal static int IndexOf(byte[] haystack, byte[] needle)
    {
        int index = haystack.AsSpan().IndexOf(needle);
        if (index < 0)
        {
            throw new InvalidOperationException("Required PDF token was not written to the revision.");
        }

        return index;
    }

    internal static void WriteByteRange(byte[] documentBytes, int offset, long[] byteRange)
    {
        for (int index = 0; index < byteRange.Length; index++)
        {
            string number = byteRange[index].ToString(
                $"D{ByteRangeNumberWidth}", CultureInfo.InvariantCulture);
            Encoding.ASCII.GetBytes(number, documentBytes.AsSpan(offset, ByteRangeNumberWidth));
            offset += ByteRangeNumberWidth + 1;
        }
    }

    internal static string NextDocumentTimestampFieldName(string source)
    {
        int highest = 0;
        foreach (Match match in Regex.Matches(source, @"/T\s*\(DocTimeStamp(\d+)\)"))
        {
            if (int.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int value))
            {
                highest = Math.Max(highest, value);
            }
        }

        return $"DocTimeStamp{highest + 1}";
    }

    internal static List<int> ReadReferenceArray(string dictionary, string token)
    {
        Match array = Regex.Match(dictionary, $@"{Regex.Escape(token)}\s*\[(.*?)\]", RegexOptions.Singleline);
        if (!array.Success)
        {
            return [];
        }

        List<int> numbers = [];
        foreach (Match reference in Regex.Matches(array.Groups[1].Value, @"(\d+)\s+0\s+R"))
        {
            numbers.Add(int.Parse(reference.Groups[1].Value, CultureInfo.InvariantCulture));
        }

        return numbers;
    }

    internal static bool TryReadStream(ReadOnlySpan<byte> pdf, int objectNumber, out byte[] payload)
    {
        payload = [];
        string source = Encoding.ASCII.GetString(pdf);
        int objectIndex = IndexOfGenerationZeroObject(source, objectNumber);
        if (objectIndex < 0)
        {
            return false;
        }

        string dictionary = ReadObjectDictionary(source, objectNumber);
        Match length = Regex.Match(dictionary, @"/Length\s+(\d+)");
        if (!length.Success
            || !int.TryParse(length.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int contentLength)
            || contentLength < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> afterObject = pdf[objectIndex..];
        int streamToken = afterObject.IndexOf("stream"u8);
        if (streamToken < 0)
        {
            return false;
        }

        int dataStart = streamToken + "stream".Length;
        if (dataStart < afterObject.Length && afterObject[dataStart] == (byte)'\r')
        {
            dataStart++;
        }

        if (dataStart < afterObject.Length && afterObject[dataStart] == (byte)'\n')
        {
            dataStart++;
        }

        if (dataStart + contentLength > afterObject.Length)
        {
            return false;
        }

        payload = afterObject.Slice(dataStart, contentLength).ToArray();
        return true;
    }

    internal static string ReplaceReferenceNumber(string dictionary, string token, int objectNumber)
    {
        Match match = Regex.Match(dictionary, $@"{Regex.Escape(token)}\s+\d+\s+0\s+R");
        if (!match.Success)
        {
            throw new NotSupportedException($"PDF dictionary does not contain {token}.");
        }

        return string.Concat(
            dictionary.AsSpan(0, match.Index),
            $"{token} {objectNumber.ToString(CultureInfo.InvariantCulture)} 0 R",
            dictionary.AsSpan(match.Index + match.Length));
    }

    private static int IndexOfGenerationZeroObject(string source, int objectNumber)
    {
        string objectHeader = $"{objectNumber} 0 obj";
        int last = -1;
        int start = 0;
        while (start < source.Length)
        {
            int index = source.IndexOf(objectHeader, start, StringComparison.Ordinal);
            if (index < 0)
            {
                return last;
            }

            if (index == 0 || !char.IsAsciiDigit(source[index - 1]))
            {
                last = index;
            }

            start = index + 1;
        }

        return last;
    }

    private static int FindMatchingDictionaryEnd(string source, int dictionaryStart)
    {
        int depth = 0;
        int index = dictionaryStart;
        while (index < source.Length - 1)
        {
            char current = source[index];
            if (current == '%')
            {
                int newline = source.IndexOf('\n', index);
                index = newline < 0 ? source.Length : newline + 1;
                continue;
            }

            if (current == '(')
            {
                index = SkipLiteralString(source, index);
                continue;
            }

            if (current == '<' && source[index + 1] == '<')
            {
                depth++;
                index += 2;
                continue;
            }

            if (current == '>' && source[index + 1] == '>')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }

                index += 2;
                continue;
            }

            index++;
        }

        return -1;
    }

    private static int SkipLiteralString(string source, int openParen)
    {
        int depth = 0;
        for (int index = openParen; index < source.Length; index++)
        {
            char current = source[index];
            if (current == '\\')
            {
                index++;
                continue;
            }

            if (current == '(')
            {
                depth++;
            }
            else if (current == ')')
            {
                depth--;
                if (depth == 0)
                {
                    return index + 1;
                }
            }
        }

        return source.Length;
    }
}
