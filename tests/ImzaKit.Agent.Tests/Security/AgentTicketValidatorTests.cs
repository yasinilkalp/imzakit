using System.Net;
using ImzaKit.Agent.Configuration;
using ImzaKit.Agent.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace ImzaKit.Agent.Tests.Security;

public sealed class AgentTicketValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ValidTicketIsAcceptedAndNonceIsConsumed()
    {
        TicketFixture fixture = new();

        AgentTicketValidationResult result = fixture.Validate(fixture.CreateTicket());

        Assert.Equal(AgentTicketValidationStatus.Passed, result.Status);
        Assert.False(fixture.NonceStore.TryConsume("nonce-001", Now.AddMinutes(2)));
    }

    [Theory]
    [InlineData("expired", AgentTicketValidationStatus.Expired)]
    [InlineData("too-long", AgentTicketValidationStatus.LifetimeTooLong)]
    public void InvalidLifetimeIsRejectedWithoutConsumingNonce(string scenario, AgentTicketValidationStatus expected)
    {
        TicketFixture fixture = new();
        AgentTicket ticket = scenario == "expired"
            ? fixture.CreateTicket(issuedAt: Now.AddMinutes(-3), expiresAt: Now.AddMinutes(-1))
            : fixture.CreateTicket(issuedAt: Now, expiresAt: Now.AddSeconds(121));

        AgentTicketValidationResult result = fixture.Validate(ticket);

        Assert.Equal(expected, result.Status);
        Assert.True(fixture.NonceStore.TryConsume("nonce-001", Now.AddMinutes(2)));
    }

    [Fact]
    public void ReplayedTicketIsRejected()
    {
        TicketFixture fixture = new();
        AgentTicket ticket = fixture.CreateTicket();
        Assert.Equal(AgentTicketValidationStatus.Passed, fixture.Validate(ticket).Status);

        AgentTicketValidationResult replay = fixture.Validate(ticket);

        Assert.Equal(AgentTicketValidationStatus.Replayed, replay.Status);
    }

    [Theory]
    [InlineData("https://evil.example", "AABB", "sign", AgentTicketValidationStatus.OriginMismatch)]
    [InlineData("https://app.example", "FFFF", "sign", AgentTicketValidationStatus.DigestMismatch)]
    [InlineData("https://app.example", "AABB", "delete", AgentTicketValidationStatus.ActionMismatch)]
    public void ContextMismatchIsRejected(
        string origin, string digest, string action, AgentTicketValidationStatus expected)
    {
        TicketFixture fixture = new();

        AgentTicketValidationResult result = fixture.Validator.ValidateAndConsume(
            fixture.CreateTicket(), origin, digest, action);

        Assert.Equal(expected, result.Status);
        Assert.True(fixture.NonceStore.TryConsume("nonce-001", Now.AddMinutes(2)));
    }

    [Fact]
    public void InvalidSignatureIsRejectedBeforeNonceConsumption()
    {
        TicketFixture fixture = new();
        AgentTicket ticket = fixture.CreateTicket() with { Signature = new byte[64] };

        AgentTicketValidationResult result = fixture.Validate(ticket);

        Assert.Equal(AgentTicketValidationStatus.InvalidSignature, result.Status);
        Assert.True(fixture.NonceStore.TryConsume("nonce-001", Now.AddMinutes(2)));
    }

    [Fact]
    public void LoopbackConfigurationAcceptsOnlyLiteralLoopbackAddresses()
    {
        AgentLoopbackOptions valid = new([new(IPAddress.Loopback, 50443), new(IPAddress.IPv6Loopback, 50443)]);
        Assert.Equal(2, valid.Endpoints.Count);

        Assert.Throws<ArgumentException>(() => new AgentLoopbackOptions([new(IPAddress.Any, 50443)]));
        Assert.Throws<ArgumentException>(() => new AgentLoopbackOptions([new(IPAddress.Parse("192.168.1.10"), 50443)]));
    }

    private sealed class TicketFixture
    {
        private readonly Ed25519PrivateKeyParameters _privateKey = new(new SecureRandom());
        public InMemoryNonceStore NonceStore { get; } = new();
        public AgentTicketValidator Validator { get; }

        public TicketFixture() => Validator = new(_privateKey.GeneratePublicKey().GetEncoded(), NonceStore, new FixedTimeProvider(Now));

        public AgentTicket CreateTicket(DateTimeOffset? issuedAt = null, DateTimeOffset? expiresAt = null)
        {
            AgentTicket unsigned = new(
                "imzakit-api", "imzakit-agent", "https://app.example", Guid.Parse("11111111-2222-3333-4444-555555555555"),
                "tenant-1", "app-1", "AABB", "sign", "nonce-001", issuedAt ?? Now.AddSeconds(-1), expiresAt ?? Now.AddSeconds(119), []);
            Ed25519Signer signer = new();
            signer.Init(true, _privateKey);
            byte[] payload = unsigned.GetCanonicalPayload();
            signer.BlockUpdate(payload, 0, payload.Length);
            return unsigned with { Signature = signer.GenerateSignature() };
        }

        public AgentTicketValidationResult Validate(AgentTicket ticket) =>
            Validator.ValidateAndConsume(ticket, "https://app.example", "AABB", "sign");
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
