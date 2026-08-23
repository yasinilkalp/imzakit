using ImzaKit.Pkcs11.Abstractions;

namespace ImzaKit.Pkcs11.Native;

public sealed class Pkcs11ProviderCatalog : IDisposable
{
    private readonly Dictionary<string, IPkcs11Provider> _providers = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    public IReadOnlyCollection<string> Names => _providers.Keys;

    public void Register(string name, IPkcs11Provider provider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(provider);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_providers.TryAdd(name, provider))
        {
            throw new InvalidOperationException($"PKCS#11 provider '{name}' is already registered.");
        }
    }

    public IPkcs11Provider GetRequired(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _providers.TryGetValue(name, out IPkcs11Provider? provider)
            ? provider
            : throw new KeyNotFoundException($"PKCS#11 provider '{name}' is not registered.");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        foreach (IPkcs11Provider provider in _providers.Values)
        {
            (provider as IDisposable)?.Dispose();
        }

        _providers.Clear();
        _disposed = true;
    }
}
