namespace ImzaKit.Verify.Validation;

public enum ValidationReasonCode
{
    CertificateExpired,
    CertificateNotYetValid,
    CertificateChainIncomplete,
    CertificateChainInvalid,
    TrustAnchorNotFound,
    CertificatePolicyNotAllowed,
    RevocationDataUnavailable,
    RevocationDataStale,
    RevocationDataInvalid,
    CertificateRevoked,
    CertificateSuspended,
    ValidationTimeUntrusted,
    AlgorithmDisallowed
}
