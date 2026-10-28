using System.Security.Cryptography;
using ImzaKit.Core.Net;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;

namespace ImzaKit.Timestamp.Rfc3161;

public sealed class Rfc3161TimeStampClient(
    IExternalResourceFetcher fetcher,
    ITsaCredentialStore? credentials = null)
{
    private const int Granted = 0;
    private const int GrantedWithMods = 1;

    public async Task<Rfc3161TimeStampResult> RequestAsync(
        ReadOnlyMemory<byte> messageImprintSha256,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fetcher);
        ArgumentNullException.ThrowIfNull(authorities);
        if (messageImprintSha256.Length != 32)
        {
            throw new ArgumentException("SHA-256 message imprint must be 32 bytes.", nameof(messageImprintSha256));
        }

        if (authorities.Count == 0)
        {
            throw new ArgumentException("At least one TSA is required.", nameof(authorities));
        }

        byte[] nonce = RandomNumberGenerator.GetBytes(32);
        TimeStampRequestGenerator generator = new();
        generator.SetCertReq(true);
        TimeStampRequest request = generator.Generate(
            TspAlgorithms.Sha256,
            messageImprintSha256.ToArray(),
            new BigInteger(1, nonce));
        byte[] requestDer = request.GetEncoded();

        InvalidOperationException? lastTransient = null;
        for (int index = 0; index < authorities.Count; index++)
        {
            TimeStampAuthority authority = authorities[index];
            ArgumentNullException.ThrowIfNull(authority);
            Dictionary<string, string>? headers = await ResolveAuthorizationAsync(authority.Name, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                ExternalResourceFetchResult fetched = await fetcher.FetchAsync(
                    new ExternalResourceFetchRequest(
                        authority.Url,
                        "POST",
                        requestDer,
                        "application/timestamp-query",
                        ["application/timestamp-reply"],
                        MaxResponseBytes: 65536,
                        Timeout: TimeSpan.FromSeconds(15),
                        MaxRedirects: 0,
                        Headers: headers),
                    cancellationToken).ConfigureAwait(false);
                return ReadGrantedToken(request, fetched.Body, nonce);
            }
            catch (InvalidOperationException exception) when (
                IsTransient(exception.Message) && index < authorities.Count - 1)
            {
                lastTransient = exception;
            }
            catch (InvalidOperationException exception) when (exception.Message == "IMZAKIT.NET.HTTP_ERROR")
            {
                throw new InvalidOperationException("IMZAKIT.TS.REJECTED", exception);
            }
        }

        throw lastTransient is null
            ? new InvalidOperationException("IMZAKIT.TS.AUTHORITY_UNAVAILABLE")
            : new InvalidOperationException("IMZAKIT.TS.AUTHORITY_UNAVAILABLE", lastTransient);
    }

    private async Task<Dictionary<string, string>?> ResolveAuthorizationAsync(
        string authorityName,
        CancellationToken cancellationToken)
    {
        if (credentials is null)
        {
            return null;
        }

        TsaCredential? credential = await credentials.GetAsync(authorityName, cancellationToken).ConfigureAwait(false);
        return credential is null
            ? null
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = credential.AuthorizationHeader
            };
    }

    private static Rfc3161TimeStampResult ReadGrantedToken(TimeStampRequest request, byte[] responseDer, byte[] nonce)
    {
        TimeStampResponse response = new(responseDer);
        if (response.Status is not Granted and not GrantedWithMods)
        {
            throw new InvalidOperationException("IMZAKIT.TS.REJECTED");
        }

        try
        {
            response.Validate(request);
        }
        catch (TspException exception)
        {
            throw new InvalidOperationException("IMZAKIT.TS.INVALID_TOKEN", exception);
        }

        TimeStampToken token = response.TimeStampToken
            ?? throw new InvalidOperationException("IMZAKIT.TS.INVALID_TOKEN");
        if (Rfc3161TimeStampTokenVerifier.VerifySignature(token) is not null)
        {
            throw new InvalidOperationException("IMZAKIT.TS.INVALID_TOKEN");
        }

        return new Rfc3161TimeStampResult(token.GetEncoded(), nonce);
    }

    private static bool IsTransient(string code) =>
        code is "IMZAKIT.NET.TRANSIENT_HTTP" or "IMZAKIT.TS.AUTHORITY_UNAVAILABLE";
}
