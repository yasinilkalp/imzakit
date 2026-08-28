using System.Security.Cryptography;
using ImzaKit.Api.Hosting;
using ImzaKit.Api.Storage;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.Revocation.Online;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.DependencyInjection;

public sealed class PadesDocumentExtensionWorkflow(
    IDocumentStore documents,
    Rfc3161TimeStampClient timeStampClient,
    OnlineRevocationClient revocationClient) : ISignatureExtensionWorkflow
{
    public SignatureExtensionOutcome Extend(SignatureExtensionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(documents);
        ArgumentNullException.ThrowIfNull(timeStampClient);

        if (!documents.TryGet(request.TenantId, request.ObjectKey, out byte[] pdf))
        {
            return new(SignatureExtensionStatus.DocumentNotFound);
        }

        if (pdf.Length != request.Size
            || !string.Equals(
                Convert.ToHexString(SHA256.HashData(pdf)),
                request.Sha256,
                StringComparison.OrdinalIgnoreCase))
        {
            return new(SignatureExtensionStatus.DigestMismatch);
        }

        PadesValidationMaterial? material = request.Certificates.Count == 0
            ? null
            : new PadesValidationMaterial(
                request.Certificates,
                request.OcspResponses,
                request.CertificateRevocationLists);
        TimeStampAuthority[] authorities = [.. request.TimeStampAuthorities
            .Select(authority => new TimeStampAuthority(authority.Name, authority.Url))];

        try
        {
            string fromLevel = PadesSignatureExtender.DetectLevel(pdf);
            byte[] extended = PadesSignatureExtender.ExtendAsync(
                pdf,
                request.TargetLevel,
                timeStampClient,
                authorities,
                material,
                revocationClient,
                validationTimeUtc: DateTimeOffset.UtcNow,
                documentTimestampCapacity: 8192,
                CancellationToken.None).GetAwaiter().GetResult();
            DocumentObject stored = documents.Put(request.TenantId, extended, "application/pdf");
            return new(
                SignatureExtensionStatus.Succeeded,
                new SignatureExtensionResult(
                    Guid.NewGuid(),
                    fromLevel,
                    request.TargetLevel,
                    stored.ObjectKey,
                    stored.Sha256,
                    stored.Size));
        }
        catch (InvalidOperationException exception) when (
            exception.Message.StartsWith("Unsupported PAdES level transition", StringComparison.Ordinal))
        {
            return new(SignatureExtensionStatus.UnsupportedTransition);
        }
        catch (InvalidOperationException exception) when (
            exception.Message is "IMZAKIT.TS.AUTHORITY_UNAVAILABLE" or "IMZAKIT.NET.TRANSIENT_HTTP")
        {
            return new(SignatureExtensionStatus.DependencyUnavailable);
        }
        catch (InvalidOperationException)
        {
            return new(SignatureExtensionStatus.Unprocessable);
        }
        catch (ArgumentException)
        {
            return new(SignatureExtensionStatus.Unprocessable);
        }
    }
}
