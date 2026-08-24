using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ImzaKit.Api.Storage;

namespace ImzaKit.Api.Audit;

public sealed class HashChainAuditLog(TimeProvider? timeProvider = null)
{
    private static readonly HashSet<string> ForbiddenKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "pin", "password", "privatekey", "private_key", "token", "credential",
        "certificate", "certificateder", "document", "pem", "secret", "authorization"
    };

    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private readonly List<AuditEvent> _events = [];

    public AuditEvent Append(
        string kind,
        string tenantId,
        Guid? operationId,
        IReadOnlyDictionary<string, string>? attributes = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        IReadOnlyDictionary<string, string> safe = Sanitize(attributes);
        lock (_gate)
        {
            DateTimeOffset at = _timeProvider.GetUtcNow();
            string tenantHash = MetadataKey.Hash(tenantId);
            string previous = _events.Count == 0 ? new string('0', 64) : _events[^1].EventHash;
            string hash = ComputeHash(kind, at, tenantHash, operationId, safe, previous);
            AuditEvent evt = new(kind, at, tenantHash, operationId, safe, previous, hash);
            _events.Add(evt);
            return evt;
        }
    }

    public IReadOnlyList<AuditEvent> Read()
    {
        lock (_gate)
        {
            return [.. _events];
        }
    }

    public bool VerifyChain() => Verify(Read());

    public static bool Verify(IReadOnlyList<AuditEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);
        string previous = new('0', 64);
        foreach (AuditEvent evt in events)
        {
            if (!string.Equals(evt.PreviousHash, previous, StringComparison.Ordinal) ||
                !string.Equals(
                    evt.EventHash,
                    ComputeHash(evt.Kind, evt.At, evt.TenantHash, evt.OperationId, evt.Attributes, evt.PreviousHash),
                    StringComparison.Ordinal))
            {
                return false;
            }

            previous = evt.EventHash;
        }

        return true;
    }

    private static Dictionary<string, string> Sanitize(IReadOnlyDictionary<string, string>? attributes)
    {
        if (attributes is null || attributes.Count == 0)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        Dictionary<string, string> copy = new(StringComparer.Ordinal);
        foreach ((string key, string value) in attributes)
        {
            if (ForbiddenKeys.Contains(key) || ContainsSensitive(value))
            {
                throw new ArgumentException("Audit events cannot contain secrets, PIN, credentials, or document bytes.", nameof(attributes));
            }

            copy[key] = value;
        }

        return copy;
    }

    private static bool ContainsSensitive(string value) =>
        value.Contains("BEGIN ", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("PRIVATE", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("PIN", StringComparison.Ordinal) ||
        value.Length > 128;

    private static string ComputeHash(
        string kind,
        DateTimeOffset at,
        string tenantHash,
        Guid? operationId,
        IReadOnlyDictionary<string, string> attributes,
        string previousHash)
    {
        StringBuilder builder = new();
        builder.Append(kind).Append('\n')
            .Append(at.ToUnixTimeMilliseconds()).Append('\n')
            .Append(tenantHash).Append('\n')
            .Append(operationId?.ToString("D") ?? "").Append('\n')
            .Append(previousHash).Append('\n');
        foreach ((string key, string value) in attributes.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            builder.Append(key).Append('=').Append(value).Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }
}

public sealed class RetentionMaintenance(HashChainAuditLog audit)
{
    public void RecordSweep(string tenantId, int documentsRemoved, int metadataRemoved)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        audit.Append(
            AuditEventKinds.RetentionSwept,
            tenantId,
            operationId: null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["documentsRemoved"] = documentsRemoved.ToString(CultureInfo.InvariantCulture),
                ["metadataRemoved"] = metadataRemoved.ToString(CultureInfo.InvariantCulture)
            });
    }
}
