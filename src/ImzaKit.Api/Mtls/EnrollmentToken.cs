namespace ImzaKit.Api.Mtls;

public sealed record EnrollmentToken(
    string Value,
    string TenantId,
    string ApplicationId,
    DateTimeOffset ExpiresAt);
