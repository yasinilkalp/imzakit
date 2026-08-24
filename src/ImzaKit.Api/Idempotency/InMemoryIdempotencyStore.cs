using System.Collections.Concurrent;
using ImzaKit.Api.Storage;

namespace ImzaKit.Api.Idempotency;

public sealed class InMemoryIdempotencyStore(TimeProvider? timeProvider = null, TimeSpan? ttl = null) : IIdempotencyStore
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly TimeSpan _ttl = ttl ?? StorageRetentionPolicy.Default.IncompleteOperation;

    public IdempotencyLookup Find(string key, string requestHash)
    {
        Validate(key, requestHash);
        if (!TryLive(key, out Entry? entry))
        {
            return new(IdempotencyLookupStatus.Missing);
        }

        return StringComparer.Ordinal.Equals(entry.RequestHash, requestHash)
            ? new(IdempotencyLookupStatus.Match, entry.Response)
            : new(IdempotencyLookupStatus.Conflict);
    }

    public void Store(string key, string requestHash, object response)
    {
        Validate(key, requestHash);
        ArgumentNullException.ThrowIfNull(response);
        DateTimeOffset expiresAt = _timeProvider.GetUtcNow().Add(_ttl);
        Entry next = new(requestHash, response, expiresAt);
        _entries.AddOrUpdate(key, next, (_, existing) =>
        {
            if (existing.ExpiresAt > _timeProvider.GetUtcNow())
            {
                throw new InvalidOperationException("The idempotency key is already stored.");
            }

            return next;
        });
    }

    private bool TryLive(string key, out Entry entry)
    {
        if (_entries.TryGetValue(key, out entry!) && entry.ExpiresAt > _timeProvider.GetUtcNow())
        {
            return true;
        }

        if (entry is not null)
        {
            _entries.TryRemove(key, out _);
        }

        entry = null!;
        return false;
    }

    private static void Validate(string key, string requestHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestHash);
    }

    private sealed record Entry(string RequestHash, object Response, DateTimeOffset ExpiresAt);
}
