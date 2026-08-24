using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Operations;
using ImzaKit.Api.Storage;

namespace ImzaKit.Api.Tests.Operations;

public sealed class SignatureOperationRetentionTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 24, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void IncompleteOperationsExpireAfterTwentyFourHours()
    {
        MutableClock clock = new(Start);
        SignatureOperationService service = new(new InMemoryIdempotencyStore(clock), clock);
        SignatureOperation created = service.Create("key-1", "hash-a", tenantId: "tenant-a").Operation!;

        Assert.Equal(Start.AddHours(24), created.ExpiresAt);
        clock.UtcNow = Start.AddHours(24);
        Assert.Null(service.Get(created.Id, "tenant-a"));
        Assert.Equal(OperationMutationStatus.NotFound, service.Transition(
            created.Id, SignatureOperationState.WaitingForClient, 0, "key-2", "hash-b", "tenant-a").Status);
        Assert.Equal(OperationMutationStatus.Succeeded, service.Create("key-1", "hash-a", tenantId: "tenant-a").Status);
    }

    [Fact]
    public void CompletedOutputExtendsRetentionToSevenDaysAndStaysTenantScoped()
    {
        MutableClock clock = new(Start);
        SignatureOperationService service = new(new InMemoryIdempotencyStore(clock), clock);
        SignatureOperation operation = service.Create("c", "h0", tenantId: "tenant-a").Operation!;
        SignatureOperationState[] chain =
        [
            SignatureOperationState.WaitingForClient, SignatureOperationState.ClientConnected,
            SignatureOperationState.CertificateSelected, SignatureOperationState.Prepared,
            SignatureOperationState.Signing, SignatureOperationState.Signed
        ];
        for (int index = 0; index < chain.Length; index++)
        {
            operation = service.Transition(
                operation.Id, chain[index], operation.Version, $"s{index}", $"h{index}", "tenant-a").Operation!;
        }

        Assert.Equal(Start.AddDays(7), operation.ExpiresAt);
        Assert.Null(service.Get(operation.Id, "tenant-b"));
        clock.UtcNow = Start.AddDays(7);
        Assert.Null(service.Get(operation.Id, "tenant-a"));
    }

    private sealed class MutableClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
