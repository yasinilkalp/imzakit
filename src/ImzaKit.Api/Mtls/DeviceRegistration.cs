namespace ImzaKit.Api.Mtls;

public sealed record DeviceRegistration(
    Guid DeviceId,
    string TenantId,
    string ApplicationId,
    string CertificateThumbprintSha256,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    bool Revoked);
