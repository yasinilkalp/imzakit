using System.Text;
using ImzaKit.Api.Storage;

namespace ImzaKit.Api.Tests.Storage;

public sealed class DocumentStoreTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 24, 8, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    [Fact]
    public void PutEncryptsContentAndIsolatesTenants()
    {
        MemoryBlobStore blobs = new();
        EncryptedDocumentStore store = new(blobs, Key, new MutableClock(Start));
        byte[] pdf = "%PDF-1.7 tenant-secret-name"u8.ToArray();

        DocumentObject stored = store.Put("tenant-secret-name", pdf, "application/pdf");

        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(pdf)), stored.Sha256);
        Assert.Equal(pdf.Length, stored.Size);
        Assert.Equal(Start.AddDays(7), stored.ExpiresAt);
        Assert.DoesNotContain("tenant-secret-name", stored.ObjectKey, StringComparison.OrdinalIgnoreCase);
        Assert.False(Encoding.UTF8.GetString(blobs.StoredValues.Single()).Contains("%PDF", StringComparison.Ordinal));
        Assert.True(store.TryGet("tenant-secret-name", stored.ObjectKey, out byte[] roundtrip));
        Assert.Equal(pdf, roundtrip);
        Assert.False(store.TryGet("other-tenant", stored.ObjectKey, out _));
    }

    [Fact]
    public void DownloadUrlIsTimeBoxedAndExpiredObjectsAreSwept()
    {
        MutableClock clock = new(Start);
        EncryptedDocumentStore store = new(new MemoryBlobStore(), Key, clock);
        DocumentObject stored = store.Put("tenant-a", "signed-bytes"u8.ToArray(), "application/pdf");
        DocumentAccessUrl url = store.CreateDownloadUrl("tenant-a", stored.ObjectKey, TimeSpan.FromMinutes(15));

        Assert.True(store.TryRedeem(url.Url, out byte[] content));
        Assert.Equal("signed-bytes"u8.ToArray(), content);

        clock.UtcNow = Start.AddMinutes(15);
        Assert.False(store.TryRedeem(url.Url, out _));

        clock.UtcNow = Start.AddDays(7);
        Assert.Equal(1, store.SweepExpired());
        Assert.False(store.TryGet("tenant-a", stored.ObjectKey, out _));
    }

    [Fact]
    public void RetentionPolicyRejectsUnlimitedLifetime()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            StorageRetentionPolicy.Create(TimeSpan.FromHours(24), Timeout.InfiniteTimeSpan));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            StorageRetentionPolicy.Create(TimeSpan.Zero, TimeSpan.FromDays(7)));
        StorageRetentionPolicy shortened = StorageRetentionPolicy.Default.With(
            incompleteOperation: TimeSpan.FromHours(1),
            completedArtifact: TimeSpan.FromDays(1));
        Assert.Equal(TimeSpan.FromHours(1), shortened.IncompleteOperation);
    }

    private sealed class MutableClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
