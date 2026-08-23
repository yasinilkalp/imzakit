namespace ImzaKit.Api.Idempotency;

public interface IIdempotencyStore
{
    IdempotencyLookup Find(string key, string requestHash);
    void Store(string key, string requestHash, object response);
}

public enum IdempotencyLookupStatus { Missing, Match, Conflict }

public sealed record IdempotencyLookup(IdempotencyLookupStatus Status, object? Response = null);
