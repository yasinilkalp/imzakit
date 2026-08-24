namespace ImzaKit.Api.Hosting;

public sealed record SignaturePrepareResult(
    int PrepareVersion,
    string DataToBeSignedBase64,
    string DataToBeSignedSha256,
    string Algorithm,
    string CompletionToken,
    DateTimeOffset ExpiresAt);

public sealed record StoredValidationReport(
    Guid ValidationId,
    string Outcome,
    bool OnlineRevocationChecked,
    string? TrustStoreVersion,
    IReadOnlyList<StoredRevisionResult> Signatures);

public sealed record StoredRevisionResult(int Revision, string Outcome, string DocumentSha256);

public interface ISignatureWorkflow
{
    SignaturePrepareResult Prepare(Guid operationId, string certificateDerBase64, string fingerprintSha256);
    bool Complete(string completionToken, int prepareVersion, string certificateFingerprintSha256);
    StoredValidationReport Validate(string objectKey, string sha256, string validationProfile);
}

public sealed class InMemorySignatureWorkflow(TimeProvider? timeProvider = null) : ISignatureWorkflow
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly Dictionary<string, (int Version, string Fingerprint)> _tokens = [];

    public SignaturePrepareResult Prepare(Guid operationId, string certificateDerBase64, string fingerprintSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateDerBase64);
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprintSha256);
        byte[] data = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(operationId.ToString("D") + fingerprintSha256));
        string token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        _tokens[token] = (1, fingerprintSha256);
        return new SignaturePrepareResult(
            1,
            Convert.ToBase64String(data),
            Convert.ToHexString(data),
            "RSA-SHA256",
            token,
            _timeProvider.GetUtcNow().AddMinutes(5));
    }

    public bool Complete(string completionToken, int prepareVersion, string certificateFingerprintSha256)
    {
        return _tokens.TryGetValue(completionToken, out (int Version, string Fingerprint) stored) &&
               stored.Version == prepareVersion &&
               string.Equals(stored.Fingerprint, certificateFingerprintSha256, StringComparison.OrdinalIgnoreCase);
    }

    public StoredValidationReport Validate(string objectKey, string sha256, string validationProfile)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(objectKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(validationProfile);
        return new StoredValidationReport(
            Guid.NewGuid(),
            "INDETERMINATE",
            false,
            "in-memory",
            [new StoredRevisionResult(1, "INDETERMINATE", sha256)]);
    }
}
