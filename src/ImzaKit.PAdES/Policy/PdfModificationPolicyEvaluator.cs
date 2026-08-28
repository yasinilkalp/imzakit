using System.Text;
using System.Text.RegularExpressions;

namespace ImzaKit.PAdES.Policy;

public static class PdfModificationPolicyEvaluator
{
    public static PdfModificationPolicyEvaluation Evaluate(ReadOnlySpan<byte> pdf, int coveredLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(coveredLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(coveredLength, pdf.Length);

        PdfModificationPolicy policy = PdfModificationPolicyInspector.Inspect(pdf);
        string tail = Encoding.ASCII.GetString(pdf[coveredLength..]);
        List<PdfModificationPolicyViolation> violations = [];
        AddDocMdpViolations(policy, tail, violations);
        AddFieldMdpViolations(policy, tail, violations);
        return new PdfModificationPolicyEvaluation(policy, violations);
    }

    private static void AddDocMdpViolations(
        PdfModificationPolicy policy,
        string tail,
        List<PdfModificationPolicyViolation> violations)
    {
        if (policy.CertificationPermission != PdfCertificationChangeLevel.NoChanges
            || IsEmptyTail(tail))
        {
            return;
        }

        if (!IsPreservationTail(tail))
        {
            violations.Add(new(
                "DocMdpViolation",
                "The document was changed after a DocMDP certification that forbids changes."));
        }
    }

    private static void AddFieldMdpViolations(
        PdfModificationPolicy policy,
        string tail,
        List<PdfModificationPolicyViolation> violations)
    {
        if (policy.FieldLockAction == PdfFieldLockAction.None || IsEmptyTail(tail))
        {
            return;
        }

        HashSet<string> reported = new(StringComparer.Ordinal);
        foreach (Match match in Regex.Matches(tail, @"/T\s*\(([^)]+)\)"))
        {
            string fieldName = match.Groups[1].Value;
            if (fieldName.StartsWith("DocTimeStamp", StringComparison.Ordinal)
                || !Locks(policy, fieldName)
                || !reported.Add(fieldName))
            {
                continue;
            }

            violations.Add(new(
                "FieldMdpViolation",
                $"FieldMDP forbids changing the locked field '{fieldName}'.",
                fieldName));
        }
    }

    private static bool IsPreservationTail(string tail) =>
        !tail.Contains("/SubFilter /ETSI.CAdES.detached", StringComparison.Ordinal)
        && !tail.Contains("/FT /Tx", StringComparison.Ordinal)
        && !tail.Contains("/FT /Btn", StringComparison.Ordinal)
        && !tail.Contains("/FT /Ch", StringComparison.Ordinal)
        && !tail.Contains("/Type /Page", StringComparison.Ordinal)
        && (tail.Contains("/Type /DSS", StringComparison.Ordinal)
            || tail.Contains("/Type /DocTimeStamp", StringComparison.Ordinal)
            || tail.Contains("/SubFilter /ETSI.RFC3161", StringComparison.Ordinal));

    private static bool Locks(PdfModificationPolicy policy, string fieldName)
    {
        bool listed = policy.FieldNames.Contains(fieldName, StringComparer.Ordinal);
        return policy.FieldLockAction switch
        {
            PdfFieldLockAction.All => true,
            PdfFieldLockAction.Include => listed,
            PdfFieldLockAction.Exclude => !listed,
            _ => false,
        };
    }

    private static bool IsEmptyTail(string tail) => string.IsNullOrWhiteSpace(tail);
}
