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
        if (IsEmptyTail(tail))
        {
            return new PdfModificationPolicyEvaluation(policy, []);
        }

        PdfRevisionChanges changes = PdfRevisionChanges.Compare(pdf, coveredLength);
        List<PdfModificationPolicyViolation> violations = [];
        AddDocMdpViolations(policy, changes, violations);
        AddFieldMdpViolations(policy, tail, violations);
        return new PdfModificationPolicyEvaluation(policy, violations, changes.Complete);
    }

    private static void AddDocMdpViolations(
        PdfModificationPolicy policy,
        PdfRevisionChanges changes,
        List<PdfModificationPolicyViolation> violations)
    {
        // P=1 forbids every addition except DSS and document time-stamps. Higher levels and
        // approval-only documents are judged by what changed in objects the signer saw.
        PdfChange? forbidden = policy.CertificationPermission switch
        {
            PdfCertificationChangeLevel.NoChanges => changes.Changes
                .FirstOrDefault(change => change.Kind > PdfChangeKind.Preservation),
            PdfCertificationChangeLevel.FormFillAndSign => FirstModification(changes, PdfChangeKind.Annotation),
            _ => FirstModification(changes, PdfChangeKind.Content),
        };
        if (forbidden is null)
        {
            return;
        }

        violations.Add(policy.CertificationPermission == PdfCertificationChangeLevel.None
            ? new(
                "ContentModifiedAfterSigning",
                $"The signed document content was changed by a later revision ({forbidden.Description}).")
            : new(
                "DocMdpViolation",
                $"The document was changed after a DocMDP certification that does not permit it ({forbidden.Description})."));
    }

    private static PdfChange? FirstModification(PdfRevisionChanges changes, PdfChangeKind minimum) =>
        changes.Changes.FirstOrDefault(change => change.ModifiesExistingObject && change.Kind >= minimum);

    private static void AddFieldMdpViolations(
        PdfModificationPolicy policy,
        string tail,
        List<PdfModificationPolicyViolation> violations)
    {
        if (policy.FieldLockAction == PdfFieldLockAction.None)
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
