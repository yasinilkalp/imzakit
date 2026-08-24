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

        SignatureOperation? current = _operations.Get(body.OperationId);
        if (current is null)
        {
            return Problem(ApiProblemKind.NotFound, correlationId, body.OperationId);
        }

        if (!TryAcceptTicket(body, current, device.Device!, correlationId, out ApiHttpResponse? ticketProblem))
        {
            return ticketProblem!;
        }

        if (!_sidecars.TryGetValue(body.OperationId, out OperationSidecar? sidecar) ||
            sidecar.CompletionToken is null ||
            sidecar.Fingerprint is null ||
            !string.Equals(sidecar.Fingerprint, body.CertificateFingerprintSha256, StringComparison.OrdinalIgnoreCase) ||
            !_workflow.Complete(sidecar.CompletionToken, sidecar.PrepareVersion, body.CertificateFingerprintSha256))
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId, body.OperationId);
        }

        if (current.State == SignatureOperationState.Prepared)
        {
            SignatureOperationResult signing = Move(current, SignatureOperationState.Signing, idempotencyKey + ":signing", request);
            if (!signing.OperationMutationSucceeded() && signing.Status != OperationMutationStatus.Replayed)
            {
                return MapMutation(signing, correlationId, body.OperationId);
            }

            current = signing.Operation ?? current;
        }

        SignatureOperationResult signed = Move(current, SignatureOperationState.Signed, idempotencyKey, request);
        if (!signed.OperationMutationSucceeded() && signed.Status != OperationMutationStatus.Replayed)
        {
            return MapMutation(signed, correlationId, body.OperationId);
        }

        return JsonResult(200, SerializeOperation(signed.Operation ?? current), correlationId);
    }

    private bool TryAcceptTicket(
        CallbackBody body,
        SignatureOperation operation,
        DeviceRegistration device,
        string correlationId,
        out ApiHttpResponse? problem)
    {
        problem = Problem(ApiProblemKind.TicketRejected, correlationId, body.OperationId);
        AgentTicket ticket;
        try
        {
            ticket = AgentTicketCodec.Decode(body.Ticket);
        }
        catch (Exception exception) when (exception is FormatException or JsonException or ArgumentException)
        {
            return false;
        }

        if (ticket.OperationId != body.OperationId ||
            ticket.OperationId != operation.Id ||
            !string.Equals(ticket.TenantId, device.TenantId, StringComparison.Ordinal) ||
            !string.Equals(ticket.ApplicationId, device.ApplicationId, StringComparison.Ordinal) ||
            _callbackTickets.ValidateAndConsume(ticket, ticket.Origin, operation.DocumentDigest, "sign").Status
                != AgentTicketValidationStatus.Passed)
        {
            return false;
        }

        problem = null;
        return true;
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
