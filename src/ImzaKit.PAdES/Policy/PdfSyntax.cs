using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ImzaKit.PAdES.Policy;

// Minimal PDF token reader: enough to split a dictionary into its top-level entries
// without being fooled by whitespace variations, strings or nested containers.
internal static partial class PdfSyntax
{
    public static int SkipWhitespace(string text, int index)
    {
        while (index < text.Length)
        {
            if (IsWhitespace(text[index]))
            {
                index++;
            }
            else if (text[index] == '%')
            {
                while (index < text.Length && text[index] is not ('\r' or '\n'))
                {
                    index++;
                }
            }
            else
            {
                break;
            }
        }

        return index;
    }

    // Returns the index just past the ">>" that closes the dictionary opened at start, or -1.
    public static int FindDictionaryEnd(string text, int start)
    {
        int index = start + 2;
        while (index < text.Length)
        {
            index = SkipWhitespace(text, index);
            if (index + 1 < text.Length && text[index] == '>' && text[index + 1] == '>')
            {
                return index + 2;
            }

            int next = SkipValue(text, index);
            if (next <= index)
            {
                return -1;
            }

            index = next;
        }

        return -1;
    }

    public static IReadOnlyDictionary<string, string> ParseDictionary(string dictionaryText)
    {
        Dictionary<string, string> entries = new(StringComparer.Ordinal);
        int index = 2;
        int end = dictionaryText.Length - 2;
        while (true)
        {
            index = SkipWhitespace(dictionaryText, index);
            if (index >= end || dictionaryText[index] != '/')
            {
                break;
            }

            int keyEnd = SkipValue(dictionaryText, index);
            string key = dictionaryText[index..keyEnd];
            int valueStart = SkipWhitespace(dictionaryText, keyEnd);
            int valueEnd = SkipValue(dictionaryText, valueStart);
            if (valueEnd <= valueStart || valueEnd > end)
            {
                break;
            }

            entries[key] = Normalize(dictionaryText[valueStart..valueEnd]);
            index = valueEnd;
        }

        return entries;
    }

    public static IReadOnlyList<int> References(string value) =>
        [.. Reference().Matches(value).Select(match => int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture))];

    public static int? SingleReference(string? value) =>
        value is not null && ReferenceAt().Match(value) is { Success: true } match
            ? int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture)
            : null;

    public static IReadOnlyList<string> LiteralStrings(string value)
    {
        List<string> strings = [];
        int index = 0;
        while ((index = value.IndexOf('(', index)) >= 0)
        {
            int end = SkipLiteralString(value, index);
            strings.Add(value[(index + 1)..(end - 1)]);
            index = end;
        }

        return strings;
    }

    public static string Normalize(string value)
    {
        StringBuilder normalized = new(value.Length);
        bool pendingSpace = false;
        foreach (char character in value.Trim())
        {
            if (IsWhitespace(character))
            {
                pendingSpace = true;
                continue;
            }

            if (pendingSpace && normalized.Length > 0)
            {
                normalized.Append(' ');
            }

            pendingSpace = false;
            normalized.Append(character);
        }

        return normalized.ToString();
    }

    private static int SkipValue(string text, int index)
    {
        if (index >= text.Length)
        {
            return index;
        }

        char current = text[index];
        if (current == '<' && index + 1 < text.Length && text[index + 1] == '<')
        {
            int end = FindDictionaryEnd(text, index);
            return end < 0 ? text.Length : end;
        }

        if (current == '<')
        {
            int end = text.IndexOf('>', index + 1);
            return end < 0 ? text.Length : end + 1;
        }

        if (current == '(')
        {
            return SkipLiteralString(text, index);
        }

        if (current == '[')
        {
            int position = index + 1;
            while (position < text.Length)
            {
                position = SkipWhitespace(text, position);
                if (position < text.Length && text[position] == ']')
                {
                    return position + 1;
                }

                int next = SkipValue(text, position);
                if (next <= position)
                {
                    return text.Length;
                }

                position = next;
            }

            return text.Length;
        }

        if (current == '/')
        {
            int position = index + 1;
            while (position < text.Length && !IsWhitespace(text[position]) && !IsDelimiter(text[position]))
            {
                position++;
            }

            return position;
        }

        Match reference = ReferenceAt().Match(text, index);
        if (reference.Success)
        {
            return index + reference.Length;
        }

        int token = index;
        while (token < text.Length && !IsWhitespace(text[token]) && !IsDelimiter(text[token]))
        {
            token++;
        }

        return token == index ? index + 1 : token;
    }

    private static int SkipLiteralString(string text, int open)
    {
        int depth = 0;
        for (int index = open; index < text.Length; index++)
        {
            switch (text[index])
            {
                case '\\':
                    index++;
                    break;
                case '(':
                    depth++;
                    break;
                case ')':
                    depth--;
                    if (depth == 0)
                    {
                        return index + 1;
                    }

                    break;
            }
        }

        return text.Length;
    }

    private static bool IsWhitespace(char character) =>
        character is ' ' or '\t' or '\r' or '\n' or '\f' or '\0';

    private static bool IsDelimiter(char character) =>
        character is '(' or ')' or '<' or '>' or '[' or ']' or '{' or '}' or '/' or '%';

    [GeneratedRegex(@"([0-9]{1,10})\s+[0-9]{1,5}\s+R\b")]
    private static partial Regex Reference();

    [GeneratedRegex(@"\G([0-9]{1,10})\s+[0-9]{1,5}\s+R\b")]
    private static partial Regex ReferenceAt();
}
