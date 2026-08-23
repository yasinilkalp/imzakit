namespace ImzaKit.Certificate.Validation;

public enum CertificateValidationFailure
{
    Expired,
    NotYetValid,
    InvalidSignature,
    IssuerIsNotCa,
    IssuerKeyCertSignMissing,
    LeafDigitalSignatureMissing,
    AlgorithmDisallowed
}
