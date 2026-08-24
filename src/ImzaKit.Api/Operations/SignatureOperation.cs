namespace ImzaKit.Api.Operations;

public sealed record SignatureOperation(
    Guid Id,
    SignatureOperationState State,
    int Version,
    DateTimeOffset CreatedAt,
    string DocumentDigest = "",
    DateTimeOffset? ExpiresAt = null,
    string? ResultObjectKey = null);

