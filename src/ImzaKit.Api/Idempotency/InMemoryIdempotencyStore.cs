using System.Collections.Concurrent;

namespace ImzaKit.Api.Idempotency;

public sealed class InMemoryIdempotencyStore : IIdempotencyStore
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    public IdempotencyLookup Find(string key, string requestHash)
    {
        Validate(key, requestHash);
        if (!_entries.TryGetValue(key, out Entry? entry)) return new(IdempotencyLookupStatus.Missing);
        return StringComparer.Ordinal.Equals(entry.RequestHash, requestHash)
            ? new(IdempotencyLookupStatus.Match, entry.Response)
            : new(IdempotencyLookupStatus.Conflict);
    }

    public void Store(string key, string requestHash, object response)
    {
        Validate(key, requestHash);
        ArgumentNullException.ThrowIfNull(response);
        if (!_entries.TryAdd(key, new(requestHash, response)))
            throw new InvalidOperationException("The idempotency key is already stored.");
    }

    private static void Validate(string key, string requestHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestHash);
    }

    private sealed record Entry(string RequestHash, object Response);
}
