using ImzaKit.Agent.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ImzaKit.Agent.Tests.Security;

public sealed class AgentTicketIssuerTests
{
    [Fact]
    public void IssuedTicketValidatesAgainstMatchingPublicKey()
    {
        Ed25519PrivateKeyParameters privateKey = new(new SecureRandom());
        DateTimeOffset now = new(2026, 8, 24, 8, 0, 0, TimeSpan.Zero);
        FixedTimeProvider clock = new(now);
        AgentTicketIssuer issuer = new(privateKey.GetEncoded(), clock);
        InMemoryNonceStore nonces = new();
        AgentTicketValidator validator = new(issuer.PublicKey, nonces, clock);

        AgentTicket ticket = issuer.Issue(
            "https://app.example",
            Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            "tenant-1",
            "app-1",
            "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899");

        AgentTicketValidationResult result = validator.ValidateAndConsume(
            ticket, "https://app.example", ticket.DocumentSha256, "sign");

        Assert.Equal(AgentTicketValidationStatus.Passed, result.Status);
        Assert.Equal(now.AddSeconds(120), ticket.ExpiresAt);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
