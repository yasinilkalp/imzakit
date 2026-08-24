using System.Security.Cryptography;
using System.Text;

namespace ImzaKit.Api.Storage;

public static class MetadataKey
{
    public static string Operation(string tenantId, Guid operationId)
    {
        ArgumentNullException.ThrowIfNull(tenantId);
        return $"imzakit:op:{Hash(tenantId)}:{operationId:N}";
    }

    public static string Idempotency(string tenantId, string idempotencyKey)
    {
        ArgumentNullException.ThrowIfNull(tenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(idempotencyKey);
        return $"imzakit:idem:{Hash(tenantId)}:{Hash(idempotencyKey)}";
    }

    public static string Hash(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }
}
