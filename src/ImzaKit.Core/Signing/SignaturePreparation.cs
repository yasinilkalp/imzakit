using ImzaKit.Core.Cryptography;

namespace ImzaKit.Core.Signing;

public sealed class SignaturePreparation
{
    private readonly byte[] dataToBeSigned;

    private SignaturePreparation(
        Guid operationId,
        string documentSha256,
        byte[] dataToBeSigned,
        SignatureAlgorithmProfile algorithm,
        string certificateFingerprintSha256,
        int prepareVersion)
    {
        OperationId = operationId;
        DocumentSha256 = documentSha256;
        this.dataToBeSigned = (byte[])dataToBeSigned.Clone();
        Algorithm = algorithm;
        CertificateFingerprintSha256 = certificateFingerprintSha256;
        PrepareVersion = prepareVersion;
    }

    public Guid OperationId { get; }

    public string DocumentSha256 { get; }

    public ReadOnlyMemory<byte> DataToBeSigned => dataToBeSigned;

    public SignatureAlgorithmProfile Algorithm { get; }

    public string CertificateFingerprintSha256 { get; }

    public int PrepareVersion { get; }

    public static SignaturePreparation Create(
        Guid operationId,
        string documentSha256,
        byte[] dataToBeSigned,
        SignatureAlgorithmProfile algorithm,
        string certificateFingerprintSha256,
        int prepareVersion)
    {
        ArgumentNullException.ThrowIfNull(dataToBeSigned);
        if (dataToBeSigned.Length == 0)
        {
            throw new ArgumentException("Data to be signed cannot be empty.", nameof(dataToBeSigned));
        }

        return new(
            operationId,
            documentSha256,
            dataToBeSigned,
            algorithm,
            certificateFingerprintSha256,
            prepareVersion);
    }
}
