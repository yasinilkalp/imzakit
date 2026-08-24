using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace ImzaKit.Agent.Security;

public sealed class AgentTicketIssuer
{
    private readonly Ed25519PrivateKeyParameters _privateKey;
    private readonly TimeProvider _timeProvider;
    private readonly string _issuer;
    private readonly string _audience;

    public AgentTicketIssuer(
        ReadOnlySpan<byte> privateKey,
        TimeProvider? timeProvider = null,
        string issuer = "imzakit-api",
        string audience = "imzakit-agent")
    {
        _privateKey = new Ed25519PrivateKeyParameters(privateKey.ToArray(), 0);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _issuer = issuer;
        _audience = audience;
    }

    public byte[] PublicKey => _privateKey.GeneratePublicKey().GetEncoded();

    public AgentTicket Issue(
        string origin,
        Guid operationId,
        string tenantId,
        string applicationId,
        string documentSha256,
        string action = "sign")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(origin);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationId);
        ArgumentException.ThrowIfNullOrWhiteSpace(documentSha256);
        DateTimeOffset issuedAt = _timeProvider.GetUtcNow();
        AgentTicket unsigned = new(
            _issuer,
            _audience,
            origin,
            operationId,
            tenantId,
            applicationId,
            documentSha256,
            action,
            Guid.NewGuid().ToString("N"),
            issuedAt,
            issuedAt.AddSeconds(120),
            []);
        Ed25519Signer signer = new();
        signer.Init(true, _privateKey);
        byte[] payload = unsigned.GetCanonicalPayload();
        signer.BlockUpdate(payload, 0, payload.Length);
        return unsigned with { Signature = signer.GenerateSignature() };
    }
}
