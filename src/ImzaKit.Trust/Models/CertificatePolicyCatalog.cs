namespace ImzaKit.Trust.Models;

public sealed class CertificatePolicyCatalog
{
    private readonly IReadOnlyList<CertificatePolicyEntry> _entries;

    public CertificatePolicyCatalog(string version, IEnumerable<CertificatePolicyEntry> entries)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            throw new ArgumentException("Policy catalog version cannot be blank.", nameof(version));
        }

        ArgumentNullException.ThrowIfNull(entries);
        CertificatePolicyEntry[] copiedEntries = entries.ToArray();
        if (copiedEntries.Distinct().Count() != copiedEntries.Length)
        {
            throw new ArgumentException("Policy catalog cannot contain duplicate entries.", nameof(entries));
        }

        Version = version.Trim();
        _entries = Array.AsReadOnly(copiedEntries);
    }

    public string Version { get; }

    public IReadOnlyList<CertificatePolicyEntry> Entries => _entries;
}
