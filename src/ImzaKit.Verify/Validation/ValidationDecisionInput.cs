using ImzaKit.Revocation.Models;

namespace ImzaKit.Verify.Validation;

public sealed record ValidationDecisionInput(
    ValidationStatus ByteRangeStatus,
    ValidationStatus CryptographicStatus,
    ValidationStatus ChainStatus,
    ValidationStatus TrustStatus,
    ValidationStatus PolicyStatus,
    RevocationStatus RevocationStatus);
