using System.Text.Json;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Problems;

namespace ImzaKit.Api.Hosting;

public sealed partial class SignatureApiRequestHandler
{
    private ApiHttpResponse ExtendSignature(ApiHttpRequest request, ApiCallerIdentity caller, string correlationId)
    {
        if (!TryReadIdempotencyKey(request, out string idempotencyKey, out ApiHttpResponse? missingKey))
        {
            return missingKey!;
        }

        string hash = CanonicalRequestHasher.Hash(request.Method, request.Path, request.Body);
        IdempotencyLookup replay = _extendIdempotency.Find(idempotencyKey, hash);
        if (replay.Status == IdempotencyLookupStatus.Conflict)
        {
            return Problem(ApiProblemKind.IdempotencyConflict, correlationId);
        }

        if (replay.Status == IdempotencyLookupStatus.Match
            && replay.Response is SignatureExtensionResult replayed)
        {
            return JsonResult(200, SerializeExtension(replayed), correlationId);
        }

        if (!TryReadExtendBody(request.Body, out ExtendBody body, out ApiProblemKind? problem))
        {
            return Problem(problem!.Value, correlationId);
        }

        SignatureExtensionOutcome outcome = _extensions.Extend(new SignatureExtensionRequest(
            caller.TenantId,
            body.ObjectKey,
            body.Sha256,
            body.Size,
            body.TargetLevel,
            body.Profile,
            body.Authorities,
            body.Certificates,
            body.OcspResponses,
            body.CertificateRevocationLists));
        return outcome.Status switch
        {
            SignatureExtensionStatus.Succeeded when outcome.Result is not null => StoreAndReturn(
                idempotencyKey, hash, outcome.Result, correlationId),
            SignatureExtensionStatus.DocumentNotFound => Problem(ApiProblemKind.NotFound, correlationId),
            SignatureExtensionStatus.DependencyUnavailable =>
                ProblemDetailsFactory.Create(ApiProblemKind.DependencyUnavailable, correlationId, retryable: true),
            SignatureExtensionStatus.UnsupportedTransition or
            SignatureExtensionStatus.DigestMismatch or
            SignatureExtensionStatus.Unprocessable => Problem(ApiProblemKind.Unprocessable, correlationId),
            _ => Problem(ApiProblemKind.Unprocessable, correlationId)
        };
    }

    private ApiHttpResponse StoreAndReturn(
        string idempotencyKey,
        string hash,
        SignatureExtensionResult result,
        string correlationId)
    {
        _extendIdempotency.Store(idempotencyKey, hash, result);
        return JsonResult(200, SerializeExtension(result), correlationId);
    }

    private static string SerializeExtension(SignatureExtensionResult result) =>
        JsonSerializer.Serialize(
            new
            {
                extensionId = result.ExtensionId,
                fromLevel = result.FromLevel,
                toLevel = result.ToLevel,
                result = new
                {
                    objectKey = result.ResultObjectKey,
                    sha256 = result.ResultSha256,
                    size = result.ResultSize,
                    contentType = "application/pdf"
                }
            },
            Json);

    private static bool TryReadExtendBody(string body, out ExtendBody parsed, out ApiProblemKind? problem)
    {
        parsed = default!;
        problem = ApiProblemKind.Unprocessable;
        try
        {
            using JsonDocument document = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
            JsonElement root = document.RootElement;
            if (!root.TryGetProperty("document", out JsonElement documentElement) ||
                !TryString(documentElement, "objectKey", out string? objectKey) ||
                !TryString(documentElement, "sha256", out string? sha256) ||
                !documentElement.TryGetProperty("size", out JsonElement sizeElement) ||
                !sizeElement.TryGetInt64(out long size) ||
                !TryString(root, "targetLevel", out string? targetLevel) ||
                targetLevel is not ("B-T" or "B-LT" or "B-LTA") ||
                !TryString(root, "validationProfile", out string? profile) ||
                profile is not ("TurkiyeNes" or "GenelX509") ||
                !Sha256Pattern.IsMatch(sha256!))
            {
                return false;
            }

            if (size < 1 || size > MaxDocumentBytes)
            {
                problem = ApiProblemKind.PayloadTooLarge;
                return false;
            }

            if (!TryReadAuthorities(root, out List<SignatureExtensionAuthority> authorities)
                || !TryReadBase64Array(root, "certificatesDerBase64", out List<byte[]> certificates)
                || !TryReadBase64Array(root, "ocspResponsesBase64", out List<byte[]> ocsp)
                || !TryReadBase64Array(root, "certificateRevocationListsBase64", out List<byte[]> crls))
            {
                return false;
            }

            parsed = new ExtendBody(
                objectKey!,
                sha256!,
                size,
                targetLevel!,
                profile!,
                authorities,
                certificates,
                ocsp,
                crls);
            problem = null;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryReadAuthorities(JsonElement root, out List<SignatureExtensionAuthority> authorities)
    {
        authorities = [];
        if (!root.TryGetProperty("timeStampAuthorities", out JsonElement array))
        {
            return true;
        }

        if (array.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (JsonElement item in array.EnumerateArray())
        {
            if (!TryString(item, "name", out string? name)
                || !TryString(item, "url", out string? url)
                || !Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)
                || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                return false;
            }

            authorities.Add(new SignatureExtensionAuthority(name!, uri));
        }

        return true;
    }

    private static bool TryReadBase64Array(JsonElement root, string name, out List<byte[]> values)
    {
        values = [];
        if (!root.TryGetProperty(name, out JsonElement array))
        {
            return true;
        }

        if (array.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (JsonElement item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            try
            {
                byte[] bytes = Convert.FromBase64String(item.GetString() ?? "");
                if (bytes.Length == 0)
                {
                    return false;
                }

                values.Add(bytes);
            }
            catch (FormatException)
            {
                return false;
            }
        }

        return true;
    }

    private sealed record ExtendBody(
        string ObjectKey,
        string Sha256,
        long Size,
        string TargetLevel,
        string Profile,
        List<SignatureExtensionAuthority> Authorities,
        List<byte[]> Certificates,
        List<byte[]> OcspResponses,
        List<byte[]> CertificateRevocationLists);
}
