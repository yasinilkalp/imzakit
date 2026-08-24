using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.Api.Mtls;

public sealed class DeviceEnrollmentAuthority
{
    public const int MaximumCertificateLifetimeDays = 30;

    private readonly TimeProvider _timeProvider;
    private readonly X509Certificate2 _caCertificate;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, StoredToken> _tokens = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Guid> _thumbprints = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, DeviceRegistration> _devices = [];

    public DeviceEnrollmentAuthority(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _caCertificate = CreateCaCertificate(_timeProvider.GetUtcNow());
    }

    public EnrollmentToken IssueAdminToken(string tenantId, string applicationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationId);
        DateTimeOffset now = _timeProvider.GetUtcNow();
        EnrollmentToken token = new(
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            tenantId,
            applicationId,
            now.AddMinutes(15));
        lock (_gate)
        {
            _tokens[token.Value] = new StoredToken(token, Consumed: false);
        }

        return token;
    }

    public DeviceEnrollmentResult Enroll(string tokenValue, byte[] subjectPublicKeyInfo)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenValue);
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);
        lock (_gate)
        {
            if (!_tokens.TryGetValue(tokenValue, out StoredToken? stored))
            {
                return new DeviceEnrollmentResult(DeviceEnrollmentStatus.InvalidToken);
            }

            if (stored.Consumed)
            {
                return new DeviceEnrollmentResult(DeviceEnrollmentStatus.TokenConsumed);
            }

            DateTimeOffset now = _timeProvider.GetUtcNow();
            if (stored.Token.ExpiresAt <= now)
            {
                return new DeviceEnrollmentResult(DeviceEnrollmentStatus.TokenExpired);
            }

            _tokens[tokenValue] = stored with { Consumed = true };
            return IssueCertificate(Guid.NewGuid(), stored.Token.TenantId, stored.Token.ApplicationId, subjectPublicKeyInfo, now);
        }
    }

    public DeviceEnrollmentResult Renew(byte[] currentCertificateDer, byte[] newSubjectPublicKeyInfo)
    {
        ArgumentNullException.ThrowIfNull(currentCertificateDer);
        ArgumentNullException.ThrowIfNull(newSubjectPublicKeyInfo);
        lock (_gate)
        {
            DeviceAuthenticationResult current = AuthenticateCore(currentCertificateDer);
            if (current.Status == DeviceAuthenticationStatus.Unknown)
            {
                return new DeviceEnrollmentResult(DeviceEnrollmentStatus.UnknownDevice);
            }

            if (current.Status == DeviceAuthenticationStatus.Revoked)
            {
                return new DeviceEnrollmentResult(DeviceEnrollmentStatus.Revoked);
            }

            if (current.Status == DeviceAuthenticationStatus.Expired)
            {
                return new DeviceEnrollmentResult(DeviceEnrollmentStatus.Expired);
            }

            DeviceRegistration device = current.Device!;
            if (!ShouldRenewCore(device))
            {
                return new DeviceEnrollmentResult(DeviceEnrollmentStatus.TooEarlyToRenew);
            }

            _thumbprints.Remove(device.CertificateThumbprintSha256);
            return IssueCertificate(device.DeviceId, device.TenantId, device.ApplicationId, newSubjectPublicKeyInfo, _timeProvider.GetUtcNow());
        }
    }

    public void Revoke(Guid deviceId)
    {
        lock (_gate)
        {
            if (_devices.TryGetValue(deviceId, out DeviceRegistration? device))
            {
                _devices[deviceId] = device with { Revoked = true };
            }
        }
    }

    public DeviceAuthenticationResult Authenticate(byte[]? certificateDer)
    {
        lock (_gate)
        {
            return AuthenticateCore(certificateDer);
        }
    }

    public bool ShouldRenew(DeviceRegistration device)
    {
        ArgumentNullException.ThrowIfNull(device);
        lock (_gate)
        {
            DeviceRegistration current = _devices.GetValueOrDefault(device.DeviceId) ?? device;
            return ShouldRenewCore(current);
        }
    }

    private DeviceEnrollmentResult IssueCertificate(
        Guid deviceId,
        string tenantId,
        string applicationId,
        byte[] subjectPublicKeyInfo,
        DateTimeOffset now)
    {
        DateTimeOffset notAfter = now.AddDays(MaximumCertificateLifetimeDays);
        byte[] der = DeviceCertificateIssuer.Issue(_caCertificate, deviceId, subjectPublicKeyInfo, now, notAfter);
        DeviceRegistration registration = new(
            deviceId,
            tenantId,
            applicationId,
            Convert.ToHexString(SHA256.HashData(der)),
            now,
            notAfter,
            Revoked: false);
        _devices[deviceId] = registration;
        _thumbprints[registration.CertificateThumbprintSha256] = deviceId;
        return new DeviceEnrollmentResult(DeviceEnrollmentStatus.Succeeded, registration, der);
    }

    private DeviceAuthenticationResult AuthenticateCore(byte[]? certificateDer)
    {
        if (certificateDer is not { Length: > 0 })
        {
            return new DeviceAuthenticationResult(DeviceAuthenticationStatus.MissingCertificate);
        }

        string thumbprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        if (!_thumbprints.TryGetValue(thumbprint, out Guid deviceId) ||
            !_devices.TryGetValue(deviceId, out DeviceRegistration? device))
        {
            return new DeviceAuthenticationResult(DeviceAuthenticationStatus.Unknown);
        }

        if (device.Revoked)
        {
            return new DeviceAuthenticationResult(DeviceAuthenticationStatus.Revoked, device);
        }

        if (_timeProvider.GetUtcNow() >= device.NotAfter)
        {
            return new DeviceAuthenticationResult(DeviceAuthenticationStatus.Expired, device);
        }

        return new DeviceAuthenticationResult(DeviceAuthenticationStatus.Passed, device);
    }

    private bool ShouldRenewCore(DeviceRegistration device)
    {
        if (device.Revoked || _timeProvider.GetUtcNow() >= device.NotAfter)
        {
            return false;
        }

        long lifetimeTicks = (device.NotAfter - device.NotBefore).Ticks;
        DateTimeOffset renewAt = device.NotBefore.AddTicks(lifetimeTicks * 2 / 3);
        return _timeProvider.GetUtcNow() >= renewAt;
    }

    private static X509Certificate2 CreateCaCertificate(DateTimeOffset now)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=ImzaKit Agent Enrollment CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));
    }

    private sealed record StoredToken(EnrollmentToken Token, bool Consumed);
}
