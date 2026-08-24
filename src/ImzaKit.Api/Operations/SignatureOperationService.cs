using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Storage;

namespace ImzaKit.Api.Operations;

public sealed class SignatureOperationService(
    IIdempotencyStore idempotencyStore,
    TimeProvider? timeProvider = null,
    StorageRetentionPolicy? retention = null)
{
    private readonly Dictionary<Guid, SignatureOperation> _operations = [];
    private readonly Dictionary<Guid, string> _tenants = [];
    private readonly Lock _gate = new();
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly StorageRetentionPolicy _retention = retention ?? StorageRetentionPolicy.Default;

    public SignatureOperationResult Create(
        string idempotencyKey,
        string requestHash,
        string documentDigest = "",
        string? tenantId = null)
    {
        lock (_gate)
        {
            PurgeExpired();
            SignatureOperationResult? replay = Replay(idempotencyKey, requestHash);
            if (replay is not null)
            {
                return replay;
            }

            DateTimeOffset now = _timeProvider.GetUtcNow();
            SignatureOperation operation = new(
                Guid.NewGuid(),
                SignatureOperationState.Created,
                0,
                now,
                documentDigest,
                now.Add(_retention.IncompleteOperation));
            _operations.Add(operation.Id, operation);
            _tenants[operation.Id] = tenantId ?? "";
            SignatureOperationResult result = new(OperationMutationStatus.Succeeded, operation);
            idempotencyStore.Store(idempotencyKey, requestHash, result);
            return result;
        }
    }

    public SignatureOperationResult Transition(
        Guid operationId,
        SignatureOperationState target,
        int expectedVersion,
        string idempotencyKey,
        string requestHash,
        string? tenantId = null)
    {
        lock (_gate)
        {
            PurgeExpired();
            SignatureOperationResult? replay = Replay(idempotencyKey, requestHash);
            if (replay is not null)
            {
                return replay;
            }

            if (!TryOwned(operationId, tenantId, out SignatureOperation? current))
            {
                return Store(idempotencyKey, requestHash, new(OperationMutationStatus.NotFound, ProblemCode: "IMZAKIT.CORE.NOT_FOUND"));
            }

            if (IsTerminal(current.State))
            {
                return Store(idempotencyKey, requestHash, new(OperationMutationStatus.TerminalState, current, "IMZAKIT.CORE.TERMINAL_STATE"));
            }

            if (current.Version != expectedVersion)
            {
                return Store(idempotencyKey, requestHash, new(OperationMutationStatus.VersionConflict, current, "IMZAKIT.CORE.VERSION_CONFLICT"));
            }

            if (!CanTransition(current.State, target))
            {
                return Store(idempotencyKey, requestHash, new(OperationMutationStatus.InvalidTransition, current, "IMZAKIT.CORE.INVALID_STATE_TRANSITION"));
            }

            DateTimeOffset expiresAt = HasCompletedOutput(target)
                ? _timeProvider.GetUtcNow().Add(_retention.CompletedArtifact)
                : current.ExpiresAt ?? _timeProvider.GetUtcNow().Add(_retention.IncompleteOperation);
            SignatureOperation updated = current with { State = target, Version = current.Version + 1, ExpiresAt = expiresAt };
            _operations[operationId] = updated;
            return Store(idempotencyKey, requestHash, new(OperationMutationStatus.Succeeded, updated));
        }
    }

    public SignatureOperation? Get(Guid operationId, string? tenantId = null)
    {
        lock (_gate)
        {
            PurgeExpired();
            return TryOwned(operationId, tenantId, out SignatureOperation? operation) ? operation : null;
        }
    }

    public SignatureOperationResult? TryReplay(string idempotencyKey, string requestHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(idempotencyKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestHash);
        lock (_gate)
        {
            return Replay(idempotencyKey, requestHash);
        }
    }

    private bool TryOwned(Guid operationId, string? tenantId, out SignatureOperation operation)
    {
        if (!_operations.TryGetValue(operationId, out operation!))
        {
            return false;
        }

        if (tenantId is not null && !string.Equals(_tenants.GetValueOrDefault(operationId), tenantId, StringComparison.Ordinal))
        {
            operation = null!;
            return false;
        }

        return true;
    }

    private void PurgeExpired()
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        List<Guid> expired = [.. _operations.Where(pair => pair.Value.ExpiresAt <= now).Select(pair => pair.Key)];
        foreach (Guid id in expired)
        {
            _operations.Remove(id);
            _tenants.Remove(id);
        }
    }

    private SignatureOperationResult? Replay(string key, string requestHash)
    {
        IdempotencyLookup lookup = idempotencyStore.Find(key, requestHash);
        if (lookup.Status == IdempotencyLookupStatus.Conflict)
        {
            return new(OperationMutationStatus.IdempotencyConflict, ProblemCode: "IMZAKIT.CORE.IDEMPOTENCY_CONFLICT");
        }

        if (lookup.Status == IdempotencyLookupStatus.Match && lookup.Response is SignatureOperationResult result)
        {
            return result with { Status = OperationMutationStatus.Replayed };
        }

        return null;
    }

    private SignatureOperationResult Store(string key, string hash, SignatureOperationResult result)
    {
        idempotencyStore.Store(key, hash, result);
        return result;
    }

    private static bool HasCompletedOutput(SignatureOperationState state) => state is
        SignatureOperationState.Signed or SignatureOperationState.Timestamping or
        SignatureOperationState.Validating or SignatureOperationState.Completed;

    private static bool IsTerminal(SignatureOperationState state) => state is
        SignatureOperationState.Completed or SignatureOperationState.Failed or
        SignatureOperationState.Cancelled or SignatureOperationState.Expired;

    private static bool CanTransition(SignatureOperationState source, SignatureOperationState target)
    {
        return (source, target) switch
        {
            (SignatureOperationState.Created, SignatureOperationState.WaitingForClient) => true,
            (SignatureOperationState.WaitingForClient, SignatureOperationState.ClientConnected) => true,
            (SignatureOperationState.ClientConnected, SignatureOperationState.CertificateSelected) => true,
            (SignatureOperationState.CertificateSelected, SignatureOperationState.Prepared) => true,
            (SignatureOperationState.Prepared, SignatureOperationState.Signing) => true,
            (SignatureOperationState.Signing, SignatureOperationState.Signed) => true,
            (SignatureOperationState.Signed, SignatureOperationState.Timestamping) => true,
            (SignatureOperationState.Signed, SignatureOperationState.Validating) => true,
            (SignatureOperationState.Timestamping, SignatureOperationState.Validating) => true,
            (SignatureOperationState.Validating, SignatureOperationState.Completed) => true,
            (SignatureOperationState.Created, SignatureOperationState.Cancelled) => true,
            (SignatureOperationState.WaitingForClient, SignatureOperationState.Cancelled) => true,
            (SignatureOperationState.ClientConnected, SignatureOperationState.Cancelled) => true,
            (SignatureOperationState.CertificateSelected, SignatureOperationState.Cancelled) => true,
            (SignatureOperationState.Prepared, SignatureOperationState.Cancelled) => true,
            (SignatureOperationState.WaitingForClient, SignatureOperationState.Expired) => true,
            (SignatureOperationState.Prepared, SignatureOperationState.Expired) => true,
            (SignatureOperationState.Signing, SignatureOperationState.Failed) => true,
            (SignatureOperationState.Timestamping, SignatureOperationState.Failed) => true,
            (SignatureOperationState.Validating, SignatureOperationState.Failed) => true,
            _ => false
        };
    }
}
