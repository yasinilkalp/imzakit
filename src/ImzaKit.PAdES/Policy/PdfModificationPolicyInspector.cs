using System.Text;

namespace ImzaKit.PAdES.Policy;

public static class PdfModificationPolicyInspector
{
    public static PdfModificationPolicy Inspect(ReadOnlySpan<byte> pdf)
    {
        string source = Encoding.ASCII.GetString(pdf);
        PdfCertificationChangeLevel certification = ReadCertificationPermission(source);
        PdfFieldLockAction fieldAction = ReadFieldLockAction(source);
        string[] fieldNames = fieldAction == PdfFieldLockAction.None
            ? []
            : ReadFieldNames(source);
        return new PdfModificationPolicy(certification, fieldAction, fieldNames);
    }

    private static PdfCertificationChangeLevel ReadCertificationPermission(string source)
    {
        int transformIndex = source.IndexOf("/TransformMethod /DocMDP", StringComparison.Ordinal);
        if (transformIndex < 0)
        {
            return PdfCertificationChangeLevel.None;
        }

        int parametersIndex = source.IndexOf("/TransformParams", transformIndex, StringComparison.Ordinal);
        int permissionIndex = source.IndexOf("/P", parametersIndex, StringComparison.Ordinal);
        if (parametersIndex < 0 || permissionIndex < 0)
        {
            return PdfCertificationChangeLevel.NoChanges;
        }

        ReadOnlySpan<char> value = source.AsSpan(permissionIndex + 2).TrimStart();
        return value.Length == 0 ? PdfCertificationChangeLevel.NoChanges : value[0] switch
        {
            '2' => PdfCertificationChangeLevel.FormFillAndSign,
            '3' => PdfCertificationChangeLevel.FormFillSignAndAnnotate,
            _ => PdfCertificationChangeLevel.NoChanges,
        };
    }

    private static PdfFieldLockAction ReadFieldLockAction(string source)
    {
        int transformIndex = source.IndexOf("/TransformMethod /FieldMDP", StringComparison.Ordinal);
        if (transformIndex < 0)
        {
            return PdfFieldLockAction.None;
        }

        int actionIndex = source.IndexOf("/Action /", transformIndex, StringComparison.Ordinal);
        if (actionIndex < 0)
        {
            return PdfFieldLockAction.All;
        }

        ReadOnlySpan<char> action = source.AsSpan(actionIndex + "/Action /".Length);
        if (action.StartsWith("Include", StringComparison.Ordinal))
        {
            return PdfFieldLockAction.Include;
        }

        return action.StartsWith("Exclude", StringComparison.Ordinal)
            ? PdfFieldLockAction.Exclude
            : PdfFieldLockAction.All;
    }

    private static string[] ReadFieldNames(string source)
    {
        int fieldsIndex = source.IndexOf("/Fields [", StringComparison.Ordinal);
        if (fieldsIndex < 0)
        {
            return [];
        }

        int endIndex = source.IndexOf(']', fieldsIndex);
        if (endIndex < 0)
        {
            return [];
        }

        List<string> fields = [];
        int index = fieldsIndex + "/Fields [".Length;
        while (index < endIndex)
        {
            int start = source.IndexOf('(', index, endIndex - index);
            if (start < 0)
            {
                break;
            }

            int end = source.IndexOf(')', start + 1, endIndex - start - 1);
            if (end < 0)
            {
                break;
            }

            fields.Add(source[(start + 1)..end]);
            index = end + 1;
        }

        return fields.ToArray();
    }
}
