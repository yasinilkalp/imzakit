using System.Text;
using System.Text.Json;
using ImzaKit.Agent.Security;

namespace ImzaKit.Api.Hosting;

public static class AgentTicketCodec
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string Encode(AgentTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        TicketDto dto = new(
            ticket.Issuer,
            ticket.Audience,
            ticket.Origin,
            ticket.OperationId,
            ticket.TenantId,
            ticket.ApplicationId,
            ticket.DocumentSha256,
            ticket.Action,
            ticket.Nonce,
            ticket.IssuedAt,
            ticket.ExpiresAt,
            Convert.ToBase64String(ticket.Signature));
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(dto, Json)));
    }

    public static AgentTicket Decode(string encoded)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encoded);
        TicketDto dto = JsonSerializer.Deserialize<TicketDto>(
            Encoding.UTF8.GetString(Convert.FromBase64String(encoded)), Json)
            ?? throw new FormatException("Agent ticket payload was empty.");
        return new AgentTicket(
            dto.Issuer,
            dto.Audience,
            dto.Origin,
            dto.OperationId,
            dto.TenantId,
            dto.ApplicationId,
            dto.DocumentSha256,
            dto.Action,
            dto.Nonce,
            dto.IssuedAt,
            dto.ExpiresAt,
            Convert.FromBase64String(dto.Signature));
    }

    private sealed record TicketDto(
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
        string Signature);
}
