namespace ImzaKit.Verify.Validation;

public sealed record ValidationFinding(string Code, string Message)
{
    public ValidationReasonCode? ReasonCode { get; init; }
}
