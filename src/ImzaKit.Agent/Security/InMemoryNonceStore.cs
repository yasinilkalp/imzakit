using System.Collections.Concurrent;

namespace ImzaKit.Agent.Security;

public sealed class InMemoryNonceStore : INonceStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _consumed = new(StringComparer.Ordinal);

    public bool TryConsume(string nonce, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        return _consumed.TryAdd(nonce, expiresAt);
    }
}
