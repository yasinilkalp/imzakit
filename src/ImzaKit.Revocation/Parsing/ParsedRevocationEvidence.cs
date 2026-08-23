using ImzaKit.Revocation.Models;

namespace ImzaKit.Revocation.Parsing;

public sealed record ParsedRevocationEvidence(
    RevocationStatus Status,
    bool TargetMatches,
    bool SignatureValid,
    bool ResponderAuthorized,
    DateTimeOffset? ThisUpdateUtc,
    DateTimeOffset? NextUpdateUtc,
    string? RevocationReason);
