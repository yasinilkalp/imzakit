namespace ImzaKit.Api.Storage;

public sealed record DocumentObject(
    string ObjectKey,
    string Sha256,
    string ContentType,
    long Size,
    DateTimeOffset ExpiresAt);

public sealed record DocumentAccessUrl(string Url, DateTimeOffset ExpiresAt);

public interface IBlobStore
{
    void Put(string key, byte[] bytes);
    bool TryGet(string key, out byte[] bytes);
    bool Remove(string key);
}

public interface IDocumentStore
{
    DocumentObject Put(string tenantId, ReadOnlySpan<byte> content, string contentType, TimeSpan? ttl = null);
    bool TryGet(string tenantId, string objectKey, out byte[] content);
    DocumentAccessUrl CreateDownloadUrl(string tenantId, string objectKey, TimeSpan lifetime);
    bool TryRedeem(string url, out byte[] content);
    int SweepExpired();
}

public sealed class MemoryBlobStore : IBlobStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, byte[]> _items = new(StringComparer.Ordinal);

    public IReadOnlyList<byte[]> StoredValues
    {
        get
        {
            lock (_gate)
            {
                return [.. _items.Values];
            }
        }
    }

    public void Put(string key, byte[] bytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(bytes);
        lock (_gate)
        {
            _items[key] = bytes;
        }
    }

    public bool TryGet(string key, out byte[] bytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        lock (_gate)
        {
            if (_items.TryGetValue(key, out byte[]? value))
            {
                bytes = value;
                return true;
            }

            bytes = [];
            return false;
        }
    }

    public bool Remove(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        lock (_gate)
        {
            return _items.Remove(key);
        }
    }
}
