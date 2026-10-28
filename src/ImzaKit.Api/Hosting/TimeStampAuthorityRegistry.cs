using System.Diagnostics.CodeAnalysis;

namespace ImzaKit.Api.Hosting;

public sealed class TimeStampAuthorityRegistry
{
    private const string EnvironmentVariable = "IMZAKIT_TSA_AUTHORITIES";
    private readonly Dictionary<string, SignatureExtensionAuthority> _authorities =
        new(StringComparer.OrdinalIgnoreCase);

    public TimeStampAuthorityRegistry(IEnumerable<SignatureExtensionAuthority> authorities)
    {
        ArgumentNullException.ThrowIfNull(authorities);
        foreach (SignatureExtensionAuthority authority in authorities)
        {
            ArgumentNullException.ThrowIfNull(authority);
            ArgumentException.ThrowIfNullOrWhiteSpace(authority.Name);
            ArgumentNullException.ThrowIfNull(authority.Url);
            if (!authority.Url.IsAbsoluteUri ||
                (authority.Url.Scheme != Uri.UriSchemeHttps && authority.Url.Scheme != Uri.UriSchemeHttp))
            {
                throw new ArgumentException("TSA URL must be an absolute HTTP or HTTPS URI.", nameof(authorities));
            }

            string name = authority.Name.Trim();
            if (!_authorities.TryAdd(name, new SignatureExtensionAuthority(name, authority.Url)))
            {
                throw new ArgumentException($"TSA '{name}' is registered more than once.", nameof(authorities));
            }
        }
    }

    public static TimeStampAuthorityRegistry Empty { get; } = new([]);

    public IReadOnlyCollection<SignatureExtensionAuthority> Authorities => _authorities.Values;

    public bool TryResolve(string name, [NotNullWhen(true)] out SignatureExtensionAuthority? authority)
    {
        ArgumentNullException.ThrowIfNull(name);
        return _authorities.TryGetValue(name.Trim(), out authority);
    }

    // IMZAKIT_TSA_AUTHORITIES="kamusm=http://tzd.kamusm.gov.tr;backup=https://tsa.example/rfc3161"
    public static TimeStampAuthorityRegistry FromEnvironment(Func<string, string?>? readVariable = null)
    {
        string? value = (readVariable ?? Environment.GetEnvironmentVariable)(EnvironmentVariable);
        if (string.IsNullOrWhiteSpace(value))
        {
            return Empty;
        }

        List<SignatureExtensionAuthority> authorities = [];
        foreach (string entry in value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int separator = entry.IndexOf('=', StringComparison.Ordinal);
            if (separator <= 0 ||
                !Uri.TryCreate(entry[(separator + 1)..].Trim(), UriKind.Absolute, out Uri? url))
            {
                throw new InvalidOperationException("IMZAKIT.TS.REGISTRY_INVALID");
            }

            authorities.Add(new SignatureExtensionAuthority(entry[..separator].Trim(), url));
        }

        try
        {
            return new TimeStampAuthorityRegistry(authorities);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException("IMZAKIT.TS.REGISTRY_INVALID", exception);
        }
    }
}
