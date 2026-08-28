namespace ImzaKit.Api.Hosting;

public enum SignatureExtensionStatus
{
    Succeeded,
    DocumentNotFound,
    DigestMismatch,
    UnsupportedTransition,
    Unprocessable,
    DependencyUnavailable
}

public sealed record SignatureExtensionAuthority(string Name, Uri Url);

public sealed record SignatureExtensionRequest(
    string TenantId,
    string ObjectKey,
    string Sha256,
    long Size,
    string TargetLevel,
    string ValidationProfile,
    IReadOnlyList<SignatureExtensionAuthority> TimeStampAuthorities,
    IReadOnlyList<byte[]> Certificates,
    IReadOnlyList<byte[]> OcspResponses,
    IReadOnlyList<byte[]> CertificateRevocationLists);

public sealed record SignatureExtensionResult(
    Guid ExtensionId,
    string FromLevel,
    string ToLevel,
    string ResultObjectKey,
    string ResultSha256,
    long ResultSize);

public sealed record SignatureExtensionOutcome(
    SignatureExtensionStatus Status,
    SignatureExtensionResult? Result = null);

public interface ISignatureExtensionWorkflow
{
    SignatureExtensionOutcome Extend(SignatureExtensionRequest request);
}

public sealed class UnavailableSignatureExtensionWorkflow : ISignatureExtensionWorkflow
{
    public SignatureExtensionOutcome Extend(SignatureExtensionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new(SignatureExtensionStatus.DocumentNotFound);
    }
}
