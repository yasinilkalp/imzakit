using System.Text.Json;
using ImzaKit.Api.Audit;

namespace ImzaKit.Api.Tests.Audit;

public sealed class HashChainAuditLogTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 24, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void AppendOnlyChainBindsPreviousHashAndRejectsSensitiveFields()
    {
        HashChainAuditLog log = new(new MutableClock(Start));

        AuditEvent first = log.Append(AuditEventKinds.OperationCreated, "tenant-1", Guid.NewGuid());
        AuditEvent second = log.Append(AuditEventKinds.Prepared, "tenant-1", first.OperationId, new Dictionary<string, string>
        {
            ["fingerprint"] = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
        });

        Assert.Equal(new string('0', 64), first.PreviousHash);
        Assert.Equal(first.EventHash, second.PreviousHash);
        Assert.True(log.VerifyChain());
        Assert.Throws<ArgumentException>(() => log.Append(
            AuditEventKinds.SignatureCreated, "tenant-1", first.OperationId, new Dictionary<string, string> { ["pin"] = "1234" }));
        Assert.Throws<ArgumentException>(() => log.Append(
            AuditEventKinds.SignatureCreated, "tenant-1", first.OperationId, new Dictionary<string, string>
            {
                ["document"] = Convert.ToBase64String(new byte[64])
            }));

        string dump = JsonSerializer.Serialize(log.Read());
        Assert.DoesNotContain("1234", dump, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", dump, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tenant-1", dump, StringComparison.Ordinal);
    }

    [Fact]
    public void TamperedEventBreaksTheChain()
    {
        HashChainAuditLog log = new(new MutableClock(Start));
        log.Append(AuditEventKinds.OperationCreated, "tenant-a", Guid.NewGuid());
        log.Append(AuditEventKinds.Cancelled, "tenant-a", Guid.NewGuid());
        AuditEvent[] copy = [.. log.Read()];
        copy[1] = copy[1] with { Kind = "forged" };

        Assert.False(HashChainAuditLog.Verify(copy));
        Assert.True(log.VerifyChain());
    }

    [Fact]
    public void RetentionSweepIsAuditedPerTenant()
    {
        MutableClock clock = new(Start);
        HashChainAuditLog log = new(clock);
        RetentionMaintenance maintenance = new(log);
        maintenance.RecordSweep("tenant-a", documentsRemoved: 2, metadataRemoved: 1);

        AuditEvent evt = Assert.Single(log.Read());
        Assert.Equal(AuditEventKinds.RetentionSwept, evt.Kind);
        Assert.Equal("2", evt.Attributes["documentsRemoved"]);
        Assert.DoesNotContain("tenant-a", JsonSerializer.Serialize(evt), StringComparison.Ordinal);
    }

    private sealed class MutableClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
