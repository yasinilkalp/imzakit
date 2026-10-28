using System.Text;
using System.Text.RegularExpressions;

namespace ImzaKit.PAdES.Policy;

public static partial class PdfModificationPolicyInspector
{
    public static PdfModificationPolicy Inspect(ReadOnlySpan<byte> pdf)
    {
        string source = Encoding.ASCII.GetString(pdf);
        PdfCertificationChangeLevel certification = ReadCertificationPermission(source);
        IReadOnlyDictionary<string, string>? fieldParameters = ReadTransformParameters(source, FieldMdpTransform());
        PdfFieldLockAction fieldAction = ReadFieldLockAction(fieldParameters);
        string[] fieldNames = fieldAction == PdfFieldLockAction.None || fieldParameters is null
            ? []
            : [.. PdfSyntax.LiteralStrings(fieldParameters.GetValueOrDefault("/Fields") ?? "")];
        return new PdfModificationPolicy(certification, fieldAction, fieldNames);
    }

    private static PdfCertificationChangeLevel ReadCertificationPermission(string source)
    {
        if (!DocMdpTransform().IsMatch(source))
        {
            return PdfCertificationChangeLevel.None;
        }

        // ISO 32000: /P defaults to 2 when the transform parameters or the entry are absent.
        IReadOnlyDictionary<string, string>? parameters = ReadTransformParameters(source, DocMdpTransform());
        return parameters?.GetValueOrDefault("/P") switch
        {
            "1" => PdfCertificationChangeLevel.NoChanges,
            "3" => PdfCertificationChangeLevel.FormFillSignAndAnnotate,
            _ => PdfCertificationChangeLevel.FormFillAndSign,
        };
    }

    private static PdfFieldLockAction ReadFieldLockAction(IReadOnlyDictionary<string, string>? parameters)
    {
        if (parameters is null)
        {
            return PdfFieldLockAction.None;
        }

        return parameters.GetValueOrDefault("/Action") switch
        {
            "/Include" => PdfFieldLockAction.Include,
            "/Exclude" => PdfFieldLockAction.Exclude,
            _ => PdfFieldLockAction.All,
        };
    }

    // Returns the /TransformParams dictionary that follows the first matching transform method,
    // an empty dictionary when the method has no parameters, or null when the method is absent.
    private static IReadOnlyDictionary<string, string>? ReadTransformParameters(string source, Regex transform)
    {
        Match method = transform.Match(source);
        if (!method.Success)
        {
            return null;
        }

        // Dictionary keys are unordered, so the parameters may precede or follow the method.
        Match parameters = TransformParams().Match(source, method.Index + method.Length);
        if (!parameters.Success || parameters.Index - method.Index > 1024)
        {
            int windowStart = Math.Max(0, method.Index - 1024);
            parameters = TransformParams().Matches(source[windowStart..method.Index]) is { Count: > 0 } before
                ? TransformParams().Match(source, windowStart + before[^1].Index)
                : Match.Empty;
        }

        if (!parameters.Success)
        {
            return new Dictionary<string, string>();
        }

        int start = parameters.Index + parameters.Length;
        int end = PdfSyntax.FindDictionaryEnd(source, start);
        return end < 0 ? new Dictionary<string, string>() : PdfSyntax.ParseDictionary(source[start..end]);
    }

    [GeneratedRegex(@"/TransformMethod\s*/DocMDP\b")]
    private static partial Regex DocMdpTransform();

    [GeneratedRegex(@"/TransformMethod\s*/FieldMDP\b")]
    private static partial Regex FieldMdpTransform();

    [GeneratedRegex(@"/TransformParams\s*(?=<<)")]
    private static partial Regex TransformParams();
}
