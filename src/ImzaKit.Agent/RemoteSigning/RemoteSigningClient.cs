using System.Text.Json;
using System.Text.RegularExpressions;
using ImzaKit.Core.Net;

namespace ImzaKit.Agent.RemoteSigning;

public sealed class RemoteSigningClient(
    IExternalResourceFetcher fetcher,
    IRemoteSigningCredentialStore credentials)
{
    private static readonly Regex Sha256Pattern = new("^[A-Fa-f0-9]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<RemoteSigningResult> SignAsync(
        RemoteSigningRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fetcher);
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.ProviderName);
        if (!Sha256Pattern.IsMatch(request.DataToBeSignedSha256))
        {
            return Fail(RemoteSigningStatus.Unprocessable, RemoteSigningProblemCodes.Unprocessable);
        }

        RemoteSigningCredential? credential = await credentials
            .GetAsync(request.ProviderName, cancellationToken)
            .ConfigureAwait(false);
        if (credential is null)
        {
            return Fail(RemoteSigningStatus.CredentialMissing, RemoteSigningProblemCodes.CredentialMissing);
        }

        byte[] body = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                dataToBeSignedSha256 = request.DataToBeSignedSha256,
                algorithm = "RSA-SHA256"
            },
            Json);

        try
        {
            ExternalResourceFetchResult fetched = await fetcher.FetchAsync(
                new ExternalResourceFetchRequest(
                    request.Endpoint,
                    "POST",
                    body,
                    "application/json",
                    ["application/json"],
                    MaxResponseBytes: 65536,
                    Timeout: TimeSpan.FromSeconds(15),
                    MaxRedirects: 0,
                    Headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Authorization"] = credential.AuthorizationHeader
                    }),
                cancellationToken).ConfigureAwait(false);
            return ReadSignature(fetched.Body);
        }
        catch (InvalidOperationException exception) when (exception.Message == "IMZAKIT.NET.TRANSIENT_HTTP")
        {
            return Fail(RemoteSigningStatus.Unavailable, RemoteSigningProblemCodes.Unavailable);
        }
        catch (InvalidOperationException exception) when (exception.Message is "IMZAKIT.NET.HTTP_ERROR"
            or "IMZAKIT.NET.UNEXPECTED_CONTENT_TYPE")
        {
            return Fail(RemoteSigningStatus.Rejected, RemoteSigningProblemCodes.Rejected);
        }
    }

    private static RemoteSigningResult ReadSignature(byte[] body)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement root = document.RootElement;
            if (!TryBase64(root, "signatureValueBase64", out byte[]? signature)
                || signature.Length == 0
                || !TryBase64(root, "certificateDerBase64", out byte[]? certificate)
                || certificate.Length == 0)
            {
                return Fail(RemoteSigningStatus.Unprocessable, RemoteSigningProblemCodes.Unprocessable);
            }

            return new(RemoteSigningStatus.Succeeded, signature, certificate);
        }
        catch (JsonException)
        {
            return Fail(RemoteSigningStatus.Unprocessable, RemoteSigningProblemCodes.Unprocessable);
        }
    }

    private static bool TryBase64(JsonElement root, string name, out byte[] value)
    {
        value = [];
        if (!root.TryGetProperty(name, out JsonElement property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            return false;
        }

        try
        {
            value = Convert.FromBase64String(property.GetString()!);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static RemoteSigningResult Fail(RemoteSigningStatus status, string code) => new(status, ProblemCode: code);
}
