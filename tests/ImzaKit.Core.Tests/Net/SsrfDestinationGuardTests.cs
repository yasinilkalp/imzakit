using System.Net;
using ImzaKit.Core.Net;

namespace ImzaKit.Core.Tests.Net;

public sealed class SsrfDestinationGuardTests
{
    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://example.com/tsa")]
    [InlineData("http://127.0.0.1/tsa")]
    [InlineData("http://localhost/tsa")]
    [InlineData("http://[::1]/tsa")]
    [InlineData("http://10.0.0.8/ocsp")]
    [InlineData("http://192.168.1.1/crl")]
    [InlineData("http://172.16.5.4/ocsp")]
    [InlineData("http://169.254.169.254/latest/meta-data")]
    [InlineData("http://[::ffff:127.0.0.1]/tsa")]
    [InlineData("http://metadata.google.internal/")]
    public void RejectsPrivateLoopbackMetadataAndNonHttpSchemes(string uri)
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() =>
            SsrfDestinationGuard.EnsureAllowed(new Uri(uri)));

        Assert.Equal("IMZAKIT.NET.SSRF_BLOCKED", error.Message);
    }

    [Fact]
    public void AllowsPublicHttpsHostnameBeforeDns()
    {
        SsrfDestinationGuard.EnsureAllowed(new Uri("https://tsa.example/rfc3161"));
    }

    [Fact]
    public void RejectsPublicMulticastAndCgnatLiterals()
    {
        Assert.Throws<InvalidOperationException>(() =>
            SsrfDestinationGuard.EnsureAllowed(IPAddress.Parse("224.0.0.1")));
        Assert.Throws<InvalidOperationException>(() =>
            SsrfDestinationGuard.EnsureAllowed(IPAddress.Parse("100.64.1.1")));
        SsrfDestinationGuard.EnsureAllowed(IPAddress.Parse("8.8.8.8"));
    }
}
