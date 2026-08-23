namespace ImzaKit.Core.Signing;

public sealed class SignatureCompletion
{
    private readonly byte[] signatureValue;

    private SignatureCompletion(
        Guid operationId,
        int prepareVersion,
        string certificateFingerprintSha256,
        byte[] signatureValue)
    {
        OperationId = operationId;
        PrepareVersion = prepareVersion;
        CertificateFingerprintSha256 = certificateFingerprintSha256;
        this.signatureValue = (byte[])signatureValue.Clone();
    }

    public Guid OperationId { get; }

    public int PrepareVersion { get; }

    public string CertificateFingerprintSha256 { get; }

    public ReadOnlyMemory<byte> SignatureValue => signatureValue;

    public static SignatureCompletion Create(
        Guid operationId,
        int prepareVersion,
        string certificateFingerprintSha256,
        byte[] signatureValue)
    {
        ArgumentNullException.ThrowIfNull(signatureValue);
        if (signatureValue.Length == 0)
        {
            throw new ArgumentException("Signature value cannot be empty.", nameof(signatureValue));
        }

        return new(operationId, prepareVersion, certificateFingerprintSha256, signatureValue);
    }
}
