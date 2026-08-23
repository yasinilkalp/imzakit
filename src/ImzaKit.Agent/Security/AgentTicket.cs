using System.Buffers;
using System.Text;

namespace ImzaKit.Agent.Security;

public sealed record AgentTicket(
    string Issuer,
    string Audience,
    string Origin,
    Guid OperationId,
    string TenantId,
    string ApplicationId,
    string DocumentSha256,
    string Action,
    string Nonce,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    byte[] Signature)
{
    public byte[] GetCanonicalPayload()
    {
        ArrayBufferWriter<byte> buffer = new();
        Write(buffer, Issuer);
        Write(buffer, Audience);
        Write(buffer, Origin);
        Write(buffer, OperationId.ToString("D"));
        Write(buffer, TenantId);
        Write(buffer, ApplicationId);
        Write(buffer, DocumentSha256);
        Write(buffer, Action);
        Write(buffer, Nonce);
        Write(buffer, IssuedAt.ToUniversalTime().ToString("O"));
        Write(buffer, ExpiresAt.ToUniversalTime().ToString("O"));
        return buffer.WrittenSpan.ToArray();
    }

    private static void Write(ArrayBufferWriter<byte> buffer, string value)
    {
        int byteCount = Encoding.UTF8.GetByteCount(value);
        Span<byte> destination = buffer.GetSpan(4 + byteCount);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(destination, byteCount);
        Encoding.UTF8.GetBytes(value, destination[4..]);
        buffer.Advance(4 + byteCount);
    }
}
