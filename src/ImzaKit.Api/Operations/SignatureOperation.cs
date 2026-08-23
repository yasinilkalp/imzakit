namespace ImzaKit.Api.Operations;

public sealed record SignatureOperation(Guid Id, SignatureOperationState State, int Version, DateTimeOffset CreatedAt);
