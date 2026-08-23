using System.Net;
using System.Text.Json;
using ImzaKit.Agent.Configuration;
using ImzaKit.Agent.Hosting;
using ImzaKit.Agent.Native;
using ImzaKit.Agent.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace ImzaKit.Agent.Tests.Hosting;

public sealed class AgentSignRequestHandlerTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void NonLoopbackCallerIsRejectedBeforeTicketValidation()
    {
        HandlerFixture fixture = new();

        AgentHttpResponse response = fixture.Handler.Handle(fixture.CreateHttpRequest(
            remoteAddress: IPAddress.Parse("192.168.1.20")));

        Assert.Equal(403, response.StatusCode);
        Assert.Contains("loopback", response.Body, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, fixture.Consent.Calls);
        Assert.True(fixture.NonceStore.TryConsume("nonce-001", Now.AddMinutes(2)));
    }

    [Fact]
    public void PinInHttpBodyIsRejectedAndNeverForwardedToNativeUi()
    {
        HandlerFixture fixture = new();
        AgentHttpRequest request = fixture.CreateHttpRequest(bodyOverride: fixture.CreateBody(pin: "1234"));

        AgentHttpResponse response = fixture.Handler.Handle(request);

        Assert.Equal(400, response.StatusCode);
        Assert.Contains("pin", response.Body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("1234", response.Body, StringComparison.Ordinal);
        Assert.Equal(0, fixture.Consent.Calls);
        Assert.Equal(0, fixture.Pin.Calls);
    }

    [Fact]
    public void OriginMismatchDoesNotPromptNativeUi()
    {
        HandlerFixture fixture = new();

        AgentHttpResponse response = fixture.Handler.Handle(
            fixture.CreateHttpRequest(origin: "https://evil.example"));

        Assert.Equal(401, response.StatusCode);
        Assert.Equal(0, fixture.Consent.Calls);
        Assert.Equal(0, fixture.Pin.Calls);
    }

    [Fact]
    public void DeniedConsentDoesNotAcquirePin()
    {
        HandlerFixture fixture = new();
        fixture.Consent.Decision = NativeConsentDecision.Denied;

        AgentHttpResponse response = fixture.Handler.Handle(fixture.CreateHttpRequest());

        Assert.Equal(403, response.StatusCode);
        Assert.Equal(1, fixture.Consent.Calls);
        Assert.Equal("contract.pdf", fixture.Consent.LastRequest?.DocumentName);
        Assert.Equal("AABB", fixture.Consent.LastRequest?.DocumentSha256);
        Assert.Equal("https://app.example", fixture.Consent.LastRequest?.CallingOrigin);
        Assert.Equal(0, fixture.Pin.Calls);
    }

    [Fact]
    public void ApprovedConsentAcquiresPinLocallyAndOmitsItFromHttpResponse()
    {
        HandlerFixture fixture = new();

        AgentHttpResponse response = fixture.Handler.Handle(fixture.CreateHttpRequest());

        Assert.Equal(200, response.StatusCode);
        Assert.Contains("consent_granted", response.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("1234", response.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("pin", response.Body, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, fixture.Consent.Calls);
        Assert.Equal(1, fixture.Pin.Calls);
        Assert.Equal("https://app.example", response.AccessControlAllowOrigin);
        Assert.NotEqual("*", response.AccessControlAllowOrigin);
    }

    [Fact]
    public void OptionsPreflightNeverUsesWildcardCors()
    {
        HandlerFixture fixture = new();
        AgentHttpRequest request = new()
        {
            Method = "OPTIONS",
            Path = "/v1/sign",
            RemoteAddress = IPAddress.Loopback,
            Origin = "https://app.example",
            Body = ""
        };

        AgentHttpResponse response = fixture.Handler.Handle(request);

        Assert.Equal(204, response.StatusCode);
        Assert.Equal("https://app.example", response.AccessControlAllowOrigin);
        Assert.NotEqual("*", response.AccessControlAllowOrigin);
        Assert.Equal(0, fixture.Consent.Calls);
    }

    [Fact]
    public void LoopbackHostPrefixesAreLiteralLoopbackHttpUrls()
    {
        AgentLoopbackHost host = new(
            new AgentLoopbackOptions([new(IPAddress.Loopback, 17651), new(IPAddress.IPv6Loopback, 17651)]),
            new HandlerFixture().Handler);

        Assert.Equal(["http://127.0.0.1:17651/", "http://[::1]:17651/"], host.Prefixes);
        Assert.All(host.Prefixes, prefix => Assert.DoesNotContain("*", prefix, StringComparison.Ordinal));
    }

    private sealed class HandlerFixture
    {
        private readonly Ed25519PrivateKeyParameters _privateKey = new(new SecureRandom());
        public InMemoryNonceStore NonceStore { get; } = new();
        public RecordingConsentPrompt Consent { get; } = new();
        public RecordingPinPrompt Pin { get; } = new();
        public AgentSignRequestHandler Handler { get; }

        public HandlerFixture()
        {
            AgentTicketValidator validator = new(
                _privateKey.GeneratePublicKey().GetEncoded(),
                NonceStore,
                new FixedTimeProvider(Now));
            Handler = new AgentSignRequestHandler(validator, Consent, Pin);
        }

        public AgentHttpRequest CreateHttpRequest(
            IPAddress? remoteAddress = null,
            string origin = "https://app.example",
            string? bodyOverride = null) =>
            new()
            {
                Method = "POST",
                Path = "/v1/sign",
                RemoteAddress = remoteAddress ?? IPAddress.Loopback,
                Origin = origin,
                Body = bodyOverride ?? CreateBody()
            };

        public string CreateBody(string? pin = null)
        {
            AgentTicket ticket = CreateTicket();
            Dictionary<string, object?> payload = new()
            {
                ["documentName"] = "contract.pdf",
                ["documentSha256"] = "AABB",
                ["certificateLabel"] = "Test NES",
                ["algorithm"] = "SHA256withRSA",
                ["ticket"] = new Dictionary<string, object?>
                {
                    ["issuer"] = ticket.Issuer,
                    ["audience"] = ticket.Audience,
                    ["origin"] = ticket.Origin,
                    ["operationId"] = ticket.OperationId.ToString("D"),
                    ["tenantId"] = ticket.TenantId,
                    ["applicationId"] = ticket.ApplicationId,
                    ["documentSha256"] = ticket.DocumentSha256,
                    ["action"] = ticket.Action,
                    ["nonce"] = ticket.Nonce,
                    ["issuedAt"] = ticket.IssuedAt.ToString("O"),
                    ["expiresAt"] = ticket.ExpiresAt.ToString("O"),
                    ["signature"] = Convert.ToBase64String(ticket.Signature)
                }
            };
            if (pin is not null)
            {
                payload["pin"] = pin;
            }

            return JsonSerializer.Serialize(payload);
        }

        private AgentTicket CreateTicket()
        {
            AgentTicket unsigned = new(
                "imzakit-api", "imzakit-agent", "https://app.example",
                Guid.Parse("11111111-2222-3333-4444-555555555555"),
                "tenant-1", "app-1", "AABB", "sign", "nonce-001",
                Now.AddSeconds(-1), Now.AddSeconds(119), []);
            Ed25519Signer signer = new();
            signer.Init(true, _privateKey);
            byte[] payload = unsigned.GetCanonicalPayload();
            signer.BlockUpdate(payload, 0, payload.Length);
            return unsigned with { Signature = signer.GenerateSignature() };
        }
    }

    private sealed class RecordingConsentPrompt : INativeConsentPrompt
    {
        public NativeConsentDecision Decision { get; set; } = NativeConsentDecision.Approved;
        public int Calls { get; private set; }
        public NativeConsentRequest? LastRequest { get; private set; }

        public NativeConsentDecision Prompt(NativeConsentRequest request)
        {
            Calls++;
            LastRequest = request;
            return Decision;
        }
    }

    private sealed class RecordingPinPrompt : INativePinPrompt
    {
        public int Calls { get; private set; }

        public NativePinSession? Acquire()
        {
            Calls++;
            return new NativePinSession("1234");
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
