namespace ImzaKit.Api.Storage;

public interface IRedisCommands
{
    void SetValue(string key, ReadOnlySpan<byte> value, TimeSpan ttl);
    bool TryGet(string key, out byte[] value);
    bool Delete(string key);
}

public static class MetadataPayloadRules
{
    public const int MaxValueBytes = 8192;

    public static void Validate(ReadOnlySpan<byte> value, TimeSpan ttl)
    {
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
    }
}

public sealed class RedisMetadataStore(IRedisCommands redis) : IMetadataStore
{
    public void Put(string logicalKey, ReadOnlySpan<byte> value, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalKey);
        ArgumentNullException.ThrowIfNull(redis);
        MetadataPayloadRules.Validate(value, ttl);
        redis.SetValue(logicalKey, value, ttl);
    }

    public bool TryGet(string logicalKey, out byte[] value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalKey);
        return redis.TryGet(logicalKey, out value);
    }

    public bool Remove(string logicalKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logicalKey);
        return redis.Delete(logicalKey);
    }

    public int SweepExpired() => 0;
}

public sealed class FileSystemBlobStore : IBlobStore
{
    private readonly string _root;

    public FileSystemBlobStore(string rootDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        string full = Path.GetFullPath(rootDirectory);
        _root = full.EndsWith(Path.DirectorySeparatorChar)
            ? full
            : full + Path.DirectorySeparatorChar;
        Directory.CreateDirectory(_root);
    }

    public void Put(string key, byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        string path = Resolve(key);
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllBytes(path, bytes);
    }

    public bool TryGet(string key, out byte[] bytes)
    {
        string path = Resolve(key);
        if (!File.Exists(path))
        {
            bytes = [];
            return false;
        }

        bytes = File.ReadAllBytes(path);
        return true;
    }

    public bool Remove(string key)
    {
        string path = Resolve(key);
        if (!File.Exists(path))
        {
            return false;
        }

        File.Delete(path);
        return true;
    }

    private string Resolve(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (Path.IsPathRooted(key) ||
            key.Contains("..", StringComparison.Ordinal) ||
            key.Contains(':', StringComparison.Ordinal))
        {
            throw new ArgumentException("Blob key must stay inside the store root.", nameof(key));
        }

        string combined = Path.GetFullPath(Path.Combine(_root, key.Replace('/', Path.DirectorySeparatorChar)));
        string prefix = _root;
        if (!combined.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            !((combined + Path.DirectorySeparatorChar).StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("Blob key must stay inside the store root.", nameof(key));
        }

        return combined;
    }
}
