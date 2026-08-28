using System.Text;

namespace ImzaKit.Timestamp.Rfc3161;

public sealed class EnvironmentTsaCredentialStore(Func<string, string?>? readVariable = null) : ITsaCredentialStore
{
    private readonly Func<string, string?> _readVariable = readVariable ?? Environment.GetEnvironmentVariable;

    public ValueTask<TsaCredential?> GetAsync(string authorityName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authorityName);
        string prefix = ToVariablePrefix(authorityName);
        string? bearer = _readVariable(prefix + "_BEARER");
        if (!string.IsNullOrWhiteSpace(bearer))
        {
            return ValueTask.FromResult<TsaCredential?>(TsaCredential.Bearer(bearer));
        }

        string? userName = _readVariable(prefix + "_USER");
        string? password = _readVariable(prefix + "_PASSWORD");
        if (string.IsNullOrWhiteSpace(userName) && string.IsNullOrWhiteSpace(password))
        {
            return ValueTask.FromResult<TsaCredential?>(null);
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException("IMZAKIT.TS.CREDENTIAL_INVALID");
        }

        return ValueTask.FromResult<TsaCredential?>(TsaCredential.Basic(userName, password));
    }

    private static string ToVariablePrefix(string authorityName)
    {
        StringBuilder prefix = new("IMZAKIT_TSA_");
        foreach (char character in authorityName.Trim())
        {
            prefix.Append(char.IsAsciiLetterOrDigit(character) ? char.ToUpperInvariant(character) : '_');
        }

        return prefix.ToString();
    }
}
