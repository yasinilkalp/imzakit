using ImzaKit.Api.Storage;

namespace ImzaKit.Api.Tests.Storage;

public sealed class HostStorageAdapterTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 24, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RedisAdapterRequiresTtlHashesNothingIntoPayloadAndRejectsPdf()
    {
        RecordingRedis redis = new();
        RedisMetadataStore store = new(redis);
        string tenantKey = MetadataKey.Operation("alice@example.com", Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));

        Assert.Throws<ArgumentOutOfRangeException>(() => store.Put(tenantKey, "meta"u8.ToArray(), TimeSpan.Zero));
        Assert.Throws<InvalidOperationException>(() => store.Put(tenantKey, "%PDF-1.7"u8.ToArray(), TimeSpan.FromHours(24)));
        store.Put(tenantKey, "op-state"u8.ToArray(), TimeSpan.FromHours(24));

        Assert.True(store.TryGet(tenantKey, out byte[] value));
        Assert.Equal("op-state"u8.ToArray(), value);
        Assert.Equal(TimeSpan.FromHours(24), redis.LastTtl);
        Assert.DoesNotContain("alice", redis.LastKey, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("imzakit:op:", redis.LastKey, StringComparison.Ordinal);
    }

    [Fact]
    public void FileSystemBlobStoreKeepsObjectsInsideRootAndRejectsTraversal()
    {
        string root = Path.Combine(Path.GetTempPath(), "imzakit-blobs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            FileSystemBlobStore store = new(root);
            store.Put("ab/cd", "cipher"u8.ToArray());
            Assert.True(store.TryGet("ab/cd", out byte[] bytes));
            Assert.Equal("cipher"u8.ToArray(), bytes);
            Assert.True(File.Exists(Path.Combine(root, "ab", "cd")));
            Assert.Throws<ArgumentException>(() => store.Put("..\\windows", "x"u8.ToArray()));
            Assert.Throws<ArgumentException>(() => store.Put("/etc/passwd", "x"u8.ToArray()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class RecordingRedis : IRedisCommands
    {
        private readonly Dictionary<string, byte[]> _values = new(StringComparer.Ordinal);
        public string LastKey { get; private set; } = "";
        public TimeSpan LastTtl { get; private set; }

        public void SetValue(string key, ReadOnlySpan<byte> value, TimeSpan ttl)
        {
            LastKey = key;
            LastTtl = ttl;
            _values[key] = value.ToArray();
        }

        public bool TryGet(string key, out byte[] value) => _values.TryGetValue(key, out value!);

        public bool Delete(string key) => _values.Remove(key);
    }
}
