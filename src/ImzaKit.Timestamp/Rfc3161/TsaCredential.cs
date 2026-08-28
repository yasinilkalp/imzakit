using System.Text;

namespace ImzaKit.Timestamp.Rfc3161;

public enum TsaAuthScheme
{
    Basic,
    Bearer
}

public sealed class TsaCredential
{
    private TsaCredential(TsaAuthScheme scheme, string authorizationHeader)
    {
        Scheme = scheme;
        AuthorizationHeader = authorizationHeader;
    }

    public TsaAuthScheme Scheme { get; }

    public string AuthorizationHeader { get; }

    public static TsaCredential Basic(string userName, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        string token = Convert.ToBase64String(Encoding.UTF8.GetBytes(userName.Trim() + ":" + password));
        return new(TsaAuthScheme.Basic, "Basic " + token);
    }

    public static TsaCredential Bearer(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return new(TsaAuthScheme.Bearer, "Bearer " + token.Trim());
    }

    public override string ToString() => $"TsaCredential({Scheme})";
}
