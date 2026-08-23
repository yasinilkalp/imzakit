namespace ImzaKit.Api.Operations;

public sealed record SignatureOperationResult(
    OperationMutationStatus Status,
    SignatureOperation? Operation = null,
    string? ProblemCode = null);
