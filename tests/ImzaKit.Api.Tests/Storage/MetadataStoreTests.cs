using ImzaKit.Api.Storage;

namespace ImzaKit.Api.Tests.Storage;

public sealed class MetadataStoreTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 24, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void KeysHashTenantAndNeverEmbedRawPii()
    {
        string tenant = "alice@example.com";
        string key = MetadataKey.Operation(tenant, Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));

        Assert.StartsWith("imzakit:op:", key, StringComparison.Ordinal);
        Assert.DoesNotContain(tenant, key, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("alice", key, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(key, MetadataKey.Operation(tenant, Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")));
        Assert.NotEqual(key, MetadataKey.Operation("bob@example.com", Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")));
    }

    [Fact]
    public void SetRequiresTtlAndRejectsDocumentPayloads()
    {
        InMemoryMetadataStore store = new(new MutableClock(Start));

        Assert.Throws<ArgumentOutOfRangeException>(() =>         store.Put("imzakit:op:a", "meta"u8.ToArray(), TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Put("imzakit:op:a", "meta"u8.ToArray(), Timeout.InfiniteTimeSpan));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            store.Put("imzakit:op:a", new byte[InMemoryMetadataStore.MaxValueBytes + 1], TimeSpan.FromHours(24)));
        Assert.Throws<InvalidOperationException>(() =>
            store.Put("imzakit:op:a", "%PDF-1.7 document-bytes"u8.ToArray(), TimeSpan.FromHours(24)));
    }

    [Fact]
    public void ExpiredEntriesAreRemovedAndKeyCanBeReused()
    {
        MutableClock clock = new(Start);
        InMemoryMetadataStore store = new(clock);
        store.Put("imzakit:op:a", "v1"u8.ToArray(), TimeSpan.FromHours(24));

        clock.UtcNow = Start.AddHours(24);
        Assert.Equal(1, store.SweepExpired());
        Assert.False(store.TryGet("imzakit:op:a", out _));

        store.Put("imzakit:op:a", "v2"u8.ToArray(), TimeSpan.FromHours(24));
        Assert.True(store.TryGet("imzakit:op:a", out byte[] value));
        Assert.Equal("v2"u8.ToArray(), value);
    }

    private sealed class MutableClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
