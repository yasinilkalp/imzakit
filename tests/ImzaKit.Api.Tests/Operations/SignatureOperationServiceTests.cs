using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Operations;
using ImzaKit.Api.Problems;

namespace ImzaKit.Api.Tests.Operations;

public sealed class SignatureOperationServiceTests
{
    [Fact]
    public void SameIdempotencyKeyAndRequestReplaysCreatedOperation()
    {
        SignatureOperationService service = CreateService();
        SignatureOperationResult first = service.Create("key-1", "hash-a");

        SignatureOperationResult replay = service.Create("key-1", "hash-a");

        Assert.Equal(OperationMutationStatus.Replayed, replay.Status);
        Assert.Equal(first.Operation, replay.Operation);
    }

    [Fact]
    public void SameIdempotencyKeyWithDifferentRequestConflicts()
    {
        SignatureOperationService service = CreateService();
        service.Create("key-1", "hash-a");

        SignatureOperationResult conflict = service.Create("key-1", "hash-b");

        Assert.Equal(OperationMutationStatus.IdempotencyConflict, conflict.Status);
        Assert.Equal("IMZAKIT.CORE.IDEMPOTENCY_CONFLICT", conflict.ProblemCode);
    }

    [Fact]
    public void ApprovedTransitionChainIncrementsVersion()
    {
        SignatureOperationService service = CreateService();
        SignatureOperation operation = service.Create("create", "h0").Operation!;
        SignatureOperationState[] chain =
        [
            SignatureOperationState.WaitingForClient,
            SignatureOperationState.ClientConnected,
            SignatureOperationState.CertificateSelected,
            SignatureOperationState.Prepared,
            SignatureOperationState.Signing,
            SignatureOperationState.Signed,
            SignatureOperationState.Validating,
            SignatureOperationState.Completed
        ];

        for (int index = 0; index < chain.Length; index++)
        {
            SignatureOperationResult result = service.Transition(
                operation.Id, chain[index], operation.Version, $"step-{index}", $"hash-{index}");
            Assert.Equal(OperationMutationStatus.Succeeded, result.Status);
            operation = result.Operation!;
            Assert.Equal(index + 1, operation.Version);
            Assert.Equal(chain[index], operation.State);
        }
    }

    [Fact]
    public void SkippedTransitionIsRejectedWithoutChangingOperation()
    {
        SignatureOperationService service = CreateService();
        SignatureOperation operation = service.Create("create", "h0").Operation!;

        SignatureOperationResult result = service.Transition(
            operation.Id, SignatureOperationState.Prepared, 0, "skip", "h1");

        Assert.Equal(OperationMutationStatus.InvalidTransition, result.Status);
        Assert.Equal("IMZAKIT.CORE.INVALID_STATE_TRANSITION", result.ProblemCode);
        Assert.Equal(SignatureOperationState.Created, service.Get(operation.Id)!.State);
    }

    [Fact]
    public void StaleExpectedVersionIsRejected()
    {
        SignatureOperationService service = CreateService();
        SignatureOperation operation = service.Create("create", "h0").Operation!;
        service.Transition(operation.Id, SignatureOperationState.WaitingForClient, 0, "step", "h1");

        SignatureOperationResult stale = service.Transition(
            operation.Id, SignatureOperationState.ClientConnected, 0, "stale", "h2");

        Assert.Equal(OperationMutationStatus.VersionConflict, stale.Status);
        Assert.Equal("IMZAKIT.CORE.VERSION_CONFLICT", stale.ProblemCode);
    }

    [Theory]
    [InlineData(SignatureOperationState.Completed)]
    [InlineData(SignatureOperationState.Failed)]
    [InlineData(SignatureOperationState.Cancelled)]
    [InlineData(SignatureOperationState.Expired)]
    public void TerminalOperationCannotTransition(SignatureOperationState terminal)
    {
        SignatureOperationService service = CreateService();
        SignatureOperation operation = service.Create("create", "h0").Operation!;
        SignatureOperation current = MoveToTerminal(service, operation, terminal);

        SignatureOperationResult result = service.Transition(
            operation.Id, SignatureOperationState.WaitingForClient, current.Version, "after-terminal", "h1");

        Assert.Equal(OperationMutationStatus.TerminalState, result.Status);
    }

    [Fact]
    public void SignedOperationCanPassThroughTimestampingAndValidation()
    {
        SignatureOperationService service = CreateService();
        SignatureOperation operation = service.Create("create", "h0").Operation!;
        SignatureOperationState[] chain =
        [
            SignatureOperationState.WaitingForClient, SignatureOperationState.ClientConnected,
            SignatureOperationState.CertificateSelected, SignatureOperationState.Prepared,
            SignatureOperationState.Signing, SignatureOperationState.Signed,
            SignatureOperationState.Timestamping, SignatureOperationState.Validating,
            SignatureOperationState.Completed
        ];

        for (int index = 0; index < chain.Length; index++)
            operation = service.Transition(operation.Id, chain[index], operation.Version, $"ts-{index}", $"tsh-{index}").Operation!;

        Assert.Equal(SignatureOperationState.Completed, operation.State);
    }

    [Theory]
    [InlineData(ApiProblemKind.Unauthenticated, 401, "IMZAKIT.CORE.UNAUTHENTICATED")]
    [InlineData(ApiProblemKind.NotFound, 404, "IMZAKIT.CORE.NOT_FOUND")]
    [InlineData(ApiProblemKind.Conflict, 409, "IMZAKIT.CORE.CONFLICT")]
    [InlineData(ApiProblemKind.IdempotencyConflict, 409, "IMZAKIT.CORE.IDEMPOTENCY_CONFLICT")]
    [InlineData(ApiProblemKind.InvalidStateTransition, 409, "IMZAKIT.CORE.INVALID_STATE_TRANSITION")]
    [InlineData(ApiProblemKind.PayloadTooLarge, 413, "IMZAKIT.CORE.PAYLOAD_TOO_LARGE")]
    [InlineData(ApiProblemKind.Unprocessable, 422, "IMZAKIT.CORE.UNPROCESSABLE")]
    [InlineData(ApiProblemKind.RateLimited, 429, "IMZAKIT.CORE.RATE_LIMITED")]
    [InlineData(ApiProblemKind.DependencyUnavailable, 503, "IMZAKIT.CORE.DEPENDENCY_UNAVAILABLE")]
    [InlineData(ApiProblemKind.MtlsRequired, 401, "IMZAKIT.AGENT.MTLS_REQUIRED")]
    [InlineData(ApiProblemKind.DeviceUnknown, 401, "IMZAKIT.AGENT.DEVICE_UNKNOWN")]
    [InlineData(ApiProblemKind.DeviceRevoked, 401, "IMZAKIT.AGENT.DEVICE_REVOKED")]
    [InlineData(ApiProblemKind.DeviceExpired, 401, "IMZAKIT.AGENT.DEVICE_EXPIRED")]
    [InlineData(ApiProblemKind.TicketRejected, 401, "IMZAKIT.AGENT.TICKET_REJECTED")]
    public void ProblemKindsHaveStableHttpAndMachineCodes(ApiProblemKind kind, int status, string code)
    {
        ApiProblemDescriptor descriptor = ApiProblemCatalog.Get(kind);

        Assert.Equal(status, descriptor.HttpStatus);
        Assert.Equal(code, descriptor.Code);
    }

    private static SignatureOperationService CreateService() => new(new InMemoryIdempotencyStore());

    private static SignatureOperation MoveToTerminal(
        SignatureOperationService service, SignatureOperation operation, SignatureOperationState terminal)
    {
        if (terminal == SignatureOperationState.Completed)
        {
            SignatureOperationState[] chain =
            [
                SignatureOperationState.WaitingForClient, SignatureOperationState.ClientConnected,
                SignatureOperationState.CertificateSelected,
                SignatureOperationState.Prepared, SignatureOperationState.Signing,
                SignatureOperationState.Signed, SignatureOperationState.Validating,
                SignatureOperationState.Completed
            ];
            for (int index = 0; index < chain.Length; index++)
                operation = service.Transition(operation.Id, chain[index], operation.Version, $"terminal-{index}", $"th-{index}").Operation!;
            return operation;
        }

        if (terminal == SignatureOperationState.Failed)
        {
            SignatureOperationState[] prefix =
            [
                SignatureOperationState.WaitingForClient, SignatureOperationState.ClientConnected,
                SignatureOperationState.CertificateSelected, SignatureOperationState.Prepared,
                SignatureOperationState.Signing
            ];
            for (int index = 0; index < prefix.Length; index++)
                operation = service.Transition(operation.Id, prefix[index], operation.Version, $"fail-{index}", $"fh-{index}").Operation!;
        }
        else if (terminal == SignatureOperationState.Expired)
        {
            operation = service.Transition(operation.Id, SignatureOperationState.WaitingForClient, operation.Version, "expire-wait", "eh-0").Operation!;
        }

        return service.Transition(operation.Id, terminal, operation.Version, "terminal", "terminal-hash").Operation!;
    }
}
