namespace ImzaKit.PAdES.Policy;

public sealed class PdfModificationPolicyViolation
{
    public PdfModificationPolicyViolation(string code, string message, string? fieldName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        Code = code;
        Message = message;
        FieldName = fieldName;
    }

    public string Code { get; }

    public string Message { get; }

    public string? FieldName { get; }
}

public sealed class PdfModificationPolicyEvaluation
{
    public PdfModificationPolicyEvaluation(
        PdfModificationPolicy policy,
        IEnumerable<PdfModificationPolicyViolation> violations)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(violations);
        Policy = policy;
        Violations = [.. violations];
    }

    public PdfModificationPolicy Policy { get; }

    public IReadOnlyList<PdfModificationPolicyViolation> Violations { get; }
}
