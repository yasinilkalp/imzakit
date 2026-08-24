using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Agent.Mtls;
using ImzaKit.Api.Mtls;

namespace ImzaKit.Api.Tests.Mtls;

public sealed class DeviceEnrollmentAuthorityTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 24, 7, 0, 0, TimeSpan.Zero);

    [Fact]
    public void AdminTokenIsSingleUseAndIssuesThirtyDayClientCertificate()
    {
        MutableClock clock = new(Start);
        DeviceEnrollmentAuthority authority = new(clock);
        using AgentDeviceIdentity device = AgentDeviceIdentity.Create();
        EnrollmentToken token = authority.IssueAdminToken("tenant-1", "app-1");

        DeviceEnrollmentResult first = authority.Enroll(token.Value, device.ExportSubjectPublicKeyInfo());
        DeviceEnrollmentResult replay = authority.Enroll(token.Value, device.ExportSubjectPublicKeyInfo());

        Assert.Equal(DeviceEnrollmentStatus.Succeeded, first.Status);
        Assert.Equal(DeviceEnrollmentStatus.TokenConsumed, replay.Status);
        Assert.Equal("tenant-1", first.Device!.TenantId);
        Assert.Equal("app-1", first.Device.ApplicationId);
        Assert.Equal(Start.AddDays(30), first.Device.NotAfter);
        Assert.True(first.CertificateDer!.Length > 0);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(first.CertificateDer)),
            first.Device.CertificateThumbprintSha256);
    }

    [Fact]
    public void UnknownTokenIsRejected()
    {
        DeviceEnrollmentAuthority authority = new(new MutableClock(Start));
        using AgentDeviceIdentity device = AgentDeviceIdentity.Create();

        DeviceEnrollmentResult result = authority.Enroll("not-a-real-enrollment-token-value", device.ExportSubjectPublicKeyInfo());

        Assert.Equal(DeviceEnrollmentStatus.InvalidToken, result.Status);
        Assert.Null(result.CertificateDer);
    }

    [Fact]
    public void CertificateIsRenewedAtTwoThirdsOfLifetimeAndOldThumbprintStopsAuthenticating()
    {
        MutableClock clock = new(Start);
        DeviceEnrollmentAuthority authority = new(clock);
        using AgentDeviceIdentity original = AgentDeviceIdentity.Create();
        EnrollmentToken token = authority.IssueAdminToken("tenant-1", "app-1");
        DeviceEnrollmentResult enrolled = authority.Enroll(token.Value, original.ExportSubjectPublicKeyInfo());

        clock.UtcNow = Start.AddDays(19);
        Assert.False(authority.ShouldRenew(enrolled.Device!));
        DeviceEnrollmentResult tooEarly = authority.Renew(enrolled.CertificateDer!, original.ExportSubjectPublicKeyInfo());
        Assert.Equal(DeviceEnrollmentStatus.TooEarlyToRenew, tooEarly.Status);

        clock.UtcNow = Start.AddDays(20);
        Assert.True(authority.ShouldRenew(enrolled.Device!));
        using AgentDeviceIdentity rotated = AgentDeviceIdentity.Create();
        DeviceEnrollmentResult renewed = authority.Renew(enrolled.CertificateDer!, rotated.ExportSubjectPublicKeyInfo());

        Assert.Equal(DeviceEnrollmentStatus.Succeeded, renewed.Status);
        Assert.Equal(clock.UtcNow.AddDays(30), renewed.Device!.NotAfter);
        Assert.NotEqual(enrolled.Device!.CertificateThumbprintSha256, renewed.Device.CertificateThumbprintSha256);
        Assert.Equal(DeviceAuthenticationStatus.Unknown, authority.Authenticate(enrolled.CertificateDer).Status);
        Assert.Equal(DeviceAuthenticationStatus.Passed, authority.Authenticate(renewed.CertificateDer).Status);
    }

    [Fact]
    public void RevokedAndExpiredCertificatesAreRejected()
    {
        MutableClock clock = new(Start);
        DeviceEnrollmentAuthority authority = new(clock);
        using AgentDeviceIdentity device = AgentDeviceIdentity.Create();
        EnrollmentToken token = authority.IssueAdminToken("tenant-1", "app-1");
        DeviceEnrollmentResult enrolled = authority.Enroll(token.Value, device.ExportSubjectPublicKeyInfo());

        authority.Revoke(enrolled.Device!.DeviceId);
        Assert.Equal(DeviceAuthenticationStatus.Revoked, authority.Authenticate(enrolled.CertificateDer).Status);

        EnrollmentToken next = authority.IssueAdminToken("tenant-1", "app-1");
        using AgentDeviceIdentity other = AgentDeviceIdentity.Create();
        DeviceEnrollmentResult second = authority.Enroll(next.Value, other.ExportSubjectPublicKeyInfo());
        clock.UtcNow = Start.AddDays(30);
        Assert.Equal(DeviceAuthenticationStatus.Expired, authority.Authenticate(second.CertificateDer).Status);
    }

    [Fact]
    public void ForeignCertificateIsUnknown()
    {
        DeviceEnrollmentAuthority authority = new(new MutableClock(Start));
        using ECDsa foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=stranger", foreign, HashAlgorithmName.SHA256);
        using X509Certificate2 stranger = request.CreateSelfSigned(Start, Start.AddDays(30));

        DeviceAuthenticationResult result = authority.Authenticate(stranger.Export(X509ContentType.Cert));

        Assert.Equal(DeviceAuthenticationStatus.Unknown, result.Status);
    }

    private sealed class MutableClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
