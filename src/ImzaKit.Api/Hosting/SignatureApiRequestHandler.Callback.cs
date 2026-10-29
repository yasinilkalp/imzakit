using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using ImzaKit.Agent.Security;
using ImzaKit.Api.Mtls;
using ImzaKit.Api.Operations;
using ImzaKit.Api.Problems;

namespace ImzaKit.Api.Hosting;

public sealed partial class SignatureApiRequestHandler
{
    private ApiHttpResponse HandleAgentCallback(ApiHttpRequest request, string correlationId)
    {
        if (!string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return Problem(ApiProblemKind.NotFound, correlationId);
        }

        if (request.ClientCertificateDer is not { Length: > 0 } && !request.HasMutualTlsClientCertificate)
        {
            return Problem(ApiProblemKind.MtlsRequired, correlationId);
        }

        DeviceAuthenticationResult device = _devices.Authenticate(request.ClientCertificateDer);
        ApiHttpResponse? deviceProblem = MapDevice(device.Status, correlationId);
        if (deviceProblem is not null)
        {
            return deviceProblem;
        }

        if (!TryReadIdempotencyKey(request, out string idempotencyKey, out ApiHttpResponse? missingKey))
        {
            return missingKey!;
        }

        DeviceRegistration registration = device.Device!;
        idempotencyKey = ScopeIdempotencyKey(registration.TenantId, idempotencyKey);
        string signedHash = CanonicalRequestHasher.Hash(
            request.Method, request.Path, request.Body + ":" + SignatureOperationState.Signed);
        SignatureOperationResult? replay = _operations.TryReplay(idempotencyKey, signedHash);
        if (replay is not null)
        {
            return replay.Status == OperationMutationStatus.IdempotencyConflict
                ? Problem(ApiProblemKind.IdempotencyConflict, correlationId)
                : JsonResult(200, SerializeOperation(replay.Operation!), correlationId);
        }

        if (!TryReadCallback(request.Body, out CallbackBody body))
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId);
        }

        if (!TryDecodeTicket(body, registration, out AgentTicket? ticket))
        {
            return Problem(ApiProblemKind.TicketRejected, correlationId, body.OperationId);
        }

        SignatureOperation? current = _operations.Get(body.OperationId, registration.TenantId);
        if (current is null)
        {
            return Problem(ApiProblemKind.NotFound, correlationId, body.OperationId);
        }

        if (_callbackTickets.ValidateAndConsume(ticket, ticket.Origin, current.DocumentDigest, "sign").Status
            != AgentTicketValidationStatus.Passed)
        {
            return Problem(ApiProblemKind.TicketRejected, correlationId, body.OperationId);
        }

        OperationSidecar? sidecar = AcceptCompletion(body.OperationId, null, null, body.CertificateFingerprintSha256);
        if (sidecar is null)
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId, body.OperationId);
        }

        if (current.State == SignatureOperationState.Prepared)
        {
            SignatureOperationResult signing = Move(
                current, SignatureOperationState.Signing, idempotencyKey + ":signing", request, registration.TenantId);
            if (!signing.OperationMutationSucceeded() && signing.Status != OperationMutationStatus.Replayed)
            {
                return MapMutation(signing, correlationId, body.OperationId);
            }

            current = signing.Operation ?? current;
        }

        SignatureOperationResult signed = Move(
            current, SignatureOperationState.Signed, idempotencyKey, request, registration.TenantId);
        if (!signed.OperationMutationSucceeded() && signed.Status != OperationMutationStatus.Replayed)
        {
            return MapMutation(signed, correlationId, body.OperationId);
        }

        ConsumeCompletionToken(sidecar);
        return JsonResult(200, SerializeOperation(signed.Operation ?? current), correlationId);
    }

    private static bool TryDecodeTicket(
        CallbackBody body,
        DeviceRegistration device,
        [NotNullWhen(true)] out AgentTicket? ticket)
    {
        try
        {
            ticket = AgentTicketCodec.Decode(body.Ticket);
        }
        catch (Exception exception) when (exception is FormatException or JsonException or ArgumentException)
        {
            ticket = null;
            return false;
        }

        return ticket.OperationId == body.OperationId &&
               string.Equals(ticket.TenantId, device.TenantId, StringComparison.Ordinal) &&
               string.Equals(ticket.ApplicationId, device.ApplicationId, StringComparison.Ordinal);
    }

    private static ApiHttpResponse? MapDevice(DeviceAuthenticationStatus status, string correlationId) => status switch
    {
        DeviceAuthenticationStatus.Passed => null,
        DeviceAuthenticationStatus.MissingCertificate => Problem(ApiProblemKind.MtlsRequired, correlationId),
        DeviceAuthenticationStatus.Unknown => Problem(ApiProblemKind.DeviceUnknown, correlationId),
        DeviceAuthenticationStatus.Revoked => Problem(ApiProblemKind.DeviceRevoked, correlationId),
        DeviceAuthenticationStatus.Expired => Problem(ApiProblemKind.DeviceExpired, correlationId),
        _ => Problem(ApiProblemKind.MtlsRequired, correlationId)
    };

    private static bool TryReadCallback(string body, out CallbackBody parsed)
    {
        parsed = default!;
        try
        {
            CallbackBody? value = JsonSerializer.Deserialize<CallbackBody>(body, Json);
            if (value is null ||
                value.OperationId == Guid.Empty ||
                value.Ticket.Length < 32 ||
                string.IsNullOrWhiteSpace(value.SignatureValueBase64) ||
                !Sha256Pattern.IsMatch(value.CertificateFingerprintSha256))
            {
                return false;
            }

            parsed = value;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private sealed record CallbackBody(
        Guid OperationId,
        string Ticket,
        string SignatureValueBase64,
        string CertificateFingerprintSha256);
}
