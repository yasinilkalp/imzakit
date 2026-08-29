using System.Text;

namespace ImzaKit.Agent.RemoteSigning;

public enum RemoteSigningAuthScheme
{
    Basic,
    Bearer
}

public sealed class RemoteSigningCredential
{
    private RemoteSigningCredential(RemoteSigningAuthScheme scheme, string authorizationHeader)
    {
        Scheme = scheme;
        AuthorizationHeader = authorizationHeader;
    }

    public RemoteSigningAuthScheme Scheme { get; }

    public string AuthorizationHeader { get; }

    public static RemoteSigningCredential Basic(string userName, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        string token = Convert.ToBase64String(Encoding.UTF8.GetBytes(userName.Trim() + ":" + password));
        return new(RemoteSigningAuthScheme.Basic, "Basic " + token);
    }

    public static RemoteSigningCredential Bearer(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return new(RemoteSigningAuthScheme.Bearer, "Bearer " + token.Trim());
    }

    public override string ToString() => $"RemoteSigningCredential({Scheme})";
}

public interface IRemoteSigningCredentialStore
{
    ValueTask<RemoteSigningCredential?> GetAsync(string providerName, CancellationToken cancellationToken);
}

public sealed class EnvironmentRemoteSigningCredentialStore(Func<string, string?>? readVariable = null)
    : IRemoteSigningCredentialStore
{
    private readonly Func<string, string?> _readVariable = readVariable ?? Environment.GetEnvironmentVariable;

    public ValueTask<RemoteSigningCredential?> GetAsync(string providerName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        string prefix = ToVariablePrefix(providerName);
        string? bearer = _readVariable(prefix + "_BEARER");
        if (!string.IsNullOrWhiteSpace(bearer))
        {
            return ValueTask.FromResult<RemoteSigningCredential?>(RemoteSigningCredential.Bearer(bearer));
        }

        string? userName = _readVariable(prefix + "_USER");
        string? password = _readVariable(prefix + "_PASSWORD");
        if (string.IsNullOrWhiteSpace(userName) && string.IsNullOrWhiteSpace(password))
        {
            return ValueTask.FromResult<RemoteSigningCredential?>(null);
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException(RemoteSigningProblemCodes.CredentialInvalid);
        }

        return ValueTask.FromResult<RemoteSigningCredential?>(RemoteSigningCredential.Basic(userName, password));
    }

    private static string ToVariablePrefix(string providerName)
    {
        StringBuilder prefix = new("IMZAKIT_REMOTE_");
        foreach (char character in providerName.Trim())
        {
            prefix.Append(char.IsAsciiLetterOrDigit(character) ? char.ToUpperInvariant(character) : '_');
        }

        return prefix.ToString();
    }
}

public static class RemoteSigningProblemCodes
{
    public const string CredentialMissing = "IMZAKIT.REMOTE.CREDENTIAL_MISSING";
    public const string CredentialInvalid = "IMZAKIT.REMOTE.CREDENTIAL_INVALID";
    public const string Unavailable = "IMZAKIT.REMOTE.UNAVAILABLE";
    public const string Rejected = "IMZAKIT.REMOTE.REJECTED";
    public const string Unprocessable = "IMZAKIT.REMOTE.UNPROCESSABLE";
}

public enum RemoteSigningStatus
{
    Succeeded,
    CredentialMissing,
    Unavailable,
    Rejected,
    Unprocessable
}

public sealed record RemoteSigningRequest(Uri Endpoint, string ProviderName, string DataToBeSignedSha256);

public sealed record RemoteSigningResult(
    RemoteSigningStatus Status,
    byte[]? SignatureValue = null,
    byte[]? CertificateDer = null,
    string? ProblemCode = null);
