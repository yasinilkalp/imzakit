namespace ImzaKit.Api.Storage;

public interface IMetadataStore
{
    void Put(string logicalKey, ReadOnlySpan<byte> value, TimeSpan ttl);
    bool TryGet(string logicalKey, out byte[] value);
    bool Remove(string logicalKey);
    int SweepExpired();
}

public sealed class InMemoryMetadataStore(TimeProvider? timeProvider = null) : IMetadataStore
{
    public const int MaxValueBytes = 8192;

    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    public void Put(string logicalKey, ReadOnlySpan<byte> value, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalKey);
        if (ttl <= TimeSpan.Zero || ttl == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(ttl), "Metadata TTL is required and must be finite.");
        }

        if (value.Length > MaxValueBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Redis metadata cannot hold large payloads.");
        }

        if (value.StartsWith("%PDF"u8))
        {
            throw new InvalidOperationException("Redis must not store document content.");
        }

        lock (_gate)
        {
            _entries[logicalKey] = new(value.ToArray(), _timeProvider.GetUtcNow().Add(ttl));
        }
    }

    public bool TryGet(string logicalKey, out byte[] value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalKey);
        lock (_gate)
        {
            if (_entries.TryGetValue(logicalKey, out Entry? entry) && entry.ExpiresAt > _timeProvider.GetUtcNow())
            {
                value = entry.Value;
                return true;
            }

            value = [];
            return false;
        }
    }

    public bool Remove(string logicalKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalKey);
        lock (_gate)
        {
            return _entries.Remove(logicalKey);
        }
    }

    public int SweepExpired()
    {
        lock (_gate)
        {
            DateTimeOffset now = _timeProvider.GetUtcNow();
            List<string> expired = [.. _entries.Where(pair => pair.Value.ExpiresAt <= now).Select(pair => pair.Key)];
            foreach (string key in expired)
            {
                _entries.Remove(key);
            }

            return expired.Count;
        }
    }

    private sealed record Entry(byte[] Value, DateTimeOffset ExpiresAt);
}
