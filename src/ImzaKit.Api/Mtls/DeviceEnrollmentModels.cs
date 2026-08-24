namespace ImzaKit.Api.Mtls;

public enum DeviceEnrollmentStatus
{
    Succeeded,
    InvalidToken,
    TokenConsumed,
    TokenExpired,
    TooEarlyToRenew,
    UnknownDevice,
    Revoked,
    Expired
}

public enum DeviceAuthenticationStatus
{
    Passed,
    MissingCertificate,
    Unknown,
    Revoked,
    Expired
}

public sealed record DeviceEnrollmentResult(
    DeviceEnrollmentStatus Status,
    DeviceRegistration? Device = null,
    byte[]? CertificateDer = null);

public sealed record DeviceAuthenticationResult(
    DeviceAuthenticationStatus Status,
    DeviceRegistration? Device = null);
