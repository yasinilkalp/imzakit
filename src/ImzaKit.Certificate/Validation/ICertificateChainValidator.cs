namespace ImzaKit.Certificate.Validation;

public interface ICertificateChainValidator
{
    CertificateChainValidationResult Validate(CertificateChainValidationRequest request);
}
