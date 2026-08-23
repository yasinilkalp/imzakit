using System.Globalization;
using System.Net;
using System.Text.Json;
using ImzaKit.Agent.Native;
using ImzaKit.Agent.Security;

namespace ImzaKit.Agent.Hosting;

public sealed class AgentSignRequestHandler
{
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip
    };

    private readonly AgentTicketValidator _validator;
    private readonly INativeConsentPrompt _consentPrompt;
    private readonly INativePinPrompt _pinPrompt;

    public AgentSignRequestHandler(
        AgentTicketValidator validator,
        INativeConsentPrompt consentPrompt,
        INativePinPrompt pinPrompt)
    {
        ArgumentNullException.ThrowIfNull(validator);
        ArgumentNullException.ThrowIfNull(consentPrompt);
        ArgumentNullException.ThrowIfNull(pinPrompt);
        _validator = validator;
        _consentPrompt = consentPrompt;
        _pinPrompt = pinPrompt;
    }

    public AgentHttpResponse Handle(AgentHttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        string? corsOrigin = IsHttpsOrigin(request.Origin) ? request.Origin : null;

        if (!IPAddress.IsLoopback(request.RemoteAddress))
        {
            return Error(403, "loopback_required", corsOrigin);
        }

        if (string.Equals(request.Method, "OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            return new AgentHttpResponse
            {
                StatusCode = 204,
                Body = "",
                AccessControlAllowOrigin = corsOrigin
            };
        }

        if (!string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(request.Path, "/v1/sign", StringComparison.Ordinal))
        {
            return Error(404, "not_found", corsOrigin);
        }

        if (string.IsNullOrWhiteSpace(request.Origin))
        {
            return Error(400, "origin_required", corsOrigin);
        }

        if (ContainsForbiddenCredential(request.Body))
        {
            return Error(400, "pin_not_allowed", corsOrigin);
        }

        if (!TryReadSignRequest(request.Body, out SignPayload payload, out AgentTicket ticket))
        {
            return Error(400, "invalid_request", corsOrigin);
        }

        AgentTicketValidationResult validation = _validator.ValidateAndConsume(
            ticket,
            request.Origin,
            payload.DocumentSha256,
            "sign");
        if (validation.Status != AgentTicketValidationStatus.Passed)
        {
            return Error(401, "ticket_rejected", corsOrigin);
        }

        NativeConsentDecision decision = _consentPrompt.Prompt(new NativeConsentRequest(
            payload.DocumentName,
            payload.DocumentSha256,
            request.Origin,
            payload.CertificateLabel,
            payload.Algorithm));
        if (decision != NativeConsentDecision.Approved)
        {
            return Error(403, "consent_denied", corsOrigin);
        }

        using NativePinSession? pin = _pinPrompt.Acquire();
        if (pin is null)
        {
            return Error(403, "pin_cancelled", corsOrigin);
        }

        return new AgentHttpResponse
        {
            StatusCode = 200,
            Body = """{"status":"consent_granted"}""",
            AccessControlAllowOrigin = corsOrigin
        };
    }

    private static bool ContainsForbiddenCredential(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(body, JsonOptions);
            return ContainsForbiddenProperty(document.RootElement);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool ContainsForbiddenProperty(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (property.Name.Equals("pin", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Equals("password", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (ContainsForbiddenProperty(property.Value))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryReadSignRequest(string body, out SignPayload payload, out AgentTicket ticket)
    {
        payload = default!;
        ticket = default!;
        try
        {
            using JsonDocument document = JsonDocument.Parse(body, JsonOptions);
            JsonElement root = document.RootElement;
            if (!root.TryGetProperty("ticket", out JsonElement ticketElement) ||
                ticketElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            payload = new SignPayload(
                ReadRequiredString(root, "documentName"),
                ReadRequiredString(root, "documentSha256"),
                ReadRequiredString(root, "certificateLabel"),
                ReadRequiredString(root, "algorithm"));
            ticket = new AgentTicket(
                ReadRequiredString(ticketElement, "issuer"),
                ReadRequiredString(ticketElement, "audience"),
                ReadRequiredString(ticketElement, "origin"),
                Guid.Parse(ReadRequiredString(ticketElement, "operationId"), CultureInfo.InvariantCulture),
                ReadRequiredString(ticketElement, "tenantId"),
                ReadRequiredString(ticketElement, "applicationId"),
                ReadRequiredString(ticketElement, "documentSha256"),
                ReadRequiredString(ticketElement, "action"),
                ReadRequiredString(ticketElement, "nonce"),
                DateTimeOffset.Parse(ReadRequiredString(ticketElement, "issuedAt"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                DateTimeOffset.Parse(ReadRequiredString(ticketElement, "expiresAt"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                Convert.FromBase64String(ReadRequiredString(ticketElement, "signature")));
            return true;
        }
        catch (Exception exception) when (exception is JsonException or FormatException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    private static string ReadRequiredString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(name);
        }

        return value.GetString() ?? throw new InvalidOperationException(name);
    }

    private static bool IsHttpsOrigin(string? origin) =>
        origin is not null &&
        Uri.TryCreate(origin, UriKind.Absolute, out Uri? uri) &&
        uri.Scheme == Uri.UriSchemeHttps;

    private static AgentHttpResponse Error(int statusCode, string code, string? corsOrigin) =>
        new()
        {
            StatusCode = statusCode,
            Body = $$"""{"error":"{{code}}"}""",
            AccessControlAllowOrigin = corsOrigin
        };

    private sealed record SignPayload(
        string DocumentName,
        string DocumentSha256,
        string CertificateLabel,
        string Algorithm);
}
