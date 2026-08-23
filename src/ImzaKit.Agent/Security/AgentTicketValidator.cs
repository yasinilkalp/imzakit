using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace ImzaKit.Agent.Security;

public sealed class AgentTicketValidator
{
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromSeconds(120);
    private readonly Ed25519PublicKeyParameters _publicKey;
    private readonly INonceStore _nonceStore;
    private readonly TimeProvider _timeProvider;
    private readonly string _expectedIssuer;
    private readonly string _expectedAudience;

    public AgentTicketValidator(
        ReadOnlySpan<byte> publicKey,
        INonceStore nonceStore,
        TimeProvider? timeProvider = null,
        string expectedIssuer = "imzakit-api",
        string expectedAudience = "imzakit-agent")
    {
        _publicKey = new Ed25519PublicKeyParameters(publicKey.ToArray());
        _nonceStore = nonceStore;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _expectedIssuer = expectedIssuer;
        _expectedAudience = expectedAudience;
    }

    public AgentTicketValidationResult ValidateAndConsume(
        AgentTicket ticket,
        string expectedOrigin,
        string expectedDocumentSha256,
        string expectedAction)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        byte[] payload = ticket.GetCanonicalPayload();
        Ed25519Signer verifier = new();
        verifier.Init(false, _publicKey);
        verifier.BlockUpdate(payload, 0, payload.Length);
        if (!verifier.VerifySignature(ticket.Signature)) return Result(AgentTicketValidationStatus.InvalidSignature);
        if (!StringComparer.Ordinal.Equals(ticket.Issuer, _expectedIssuer)) return Result(AgentTicketValidationStatus.IssuerMismatch);
        if (!StringComparer.Ordinal.Equals(ticket.Audience, _expectedAudience)) return Result(AgentTicketValidationStatus.AudienceMismatch);

        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (ticket.ExpiresAt <= now) return Result(AgentTicketValidationStatus.Expired);
        if (ticket.IssuedAt > now) return Result(AgentTicketValidationStatus.NotYetValid);
        if (ticket.ExpiresAt - ticket.IssuedAt > MaximumLifetime) return Result(AgentTicketValidationStatus.LifetimeTooLong);
        if (!StringComparer.Ordinal.Equals(ticket.Origin, expectedOrigin)) return Result(AgentTicketValidationStatus.OriginMismatch);
        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(ticket.DocumentSha256),
                System.Text.Encoding.ASCII.GetBytes(expectedDocumentSha256)))
        {
            return Result(AgentTicketValidationStatus.DigestMismatch);
        }
        if (!StringComparer.Ordinal.Equals(ticket.Action, expectedAction)) return Result(AgentTicketValidationStatus.ActionMismatch);
        return _nonceStore.TryConsume(ticket.Nonce, ticket.ExpiresAt)
            ? Result(AgentTicketValidationStatus.Passed)
            : Result(AgentTicketValidationStatus.Replayed);
    }

    private static AgentTicketValidationResult Result(AgentTicketValidationStatus status) => new(status);
}
