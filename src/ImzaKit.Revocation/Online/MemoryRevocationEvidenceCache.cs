using System.Collections.Concurrent;
using ImzaKit.Revocation.Models;

namespace ImzaKit.Revocation.Online;

public sealed class MemoryRevocationEvidenceCache : IRevocationEvidenceCache
{
    private readonly ConcurrentDictionary<string, CacheEntry> _items = new(StringComparer.Ordinal);

    public bool TryGet(string key, DateTimeOffset nowUtc, out RevocationEvidence evidence)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (_items.TryGetValue(key, out CacheEntry? entry) && entry is not null && entry.ExpiresUtc > nowUtc)
        {
            evidence = new(entry.Type, RevocationEvidenceSource.Local, entry.Encoded);
            return true;
        }

        evidence = null!;
        return false;
    }

    public void Store(
        string key,
        RevocationEvidenceType type,
        ReadOnlySpan<byte> encoded,
        DateTimeOffset nextUpdateUtc,
        DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (encoded.IsEmpty || nextUpdateUtc <= nowUtc)
        {
            return;
        }

        _items[key] = new(type, encoded.ToArray(), nextUpdateUtc);
    }

    private sealed record CacheEntry(RevocationEvidenceType Type, byte[] Encoded, DateTimeOffset ExpiresUtc);
}
