using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using ImzaKit.Agent.Security;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Mtls;
using ImzaKit.Api.Operations;
using ImzaKit.Api.Problems;

namespace ImzaKit.Api.Hosting;

public sealed partial class SignatureApiRequestHandler
{
    private const int MaxJsonBytes = 1_048_576;
    private const int MaxDocumentBytes = 104_857_600;
    private static readonly Regex Sha256Pattern = new("^[A-Fa-f0-9]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly SignatureOperationService _operations;
    private readonly IApiCallerResolver _callers;
    private readonly AgentTicketIssuer _tickets;
    private readonly ISignatureWorkflow _workflow;
    private readonly ISignatureExtensionWorkflow _extensions;
    private readonly DeviceEnrollmentAuthority _devices;
    private readonly AgentTicketValidator _callbackTickets;
    private readonly InMemoryIdempotencyStore _extendIdempotency = new();
    private readonly Dictionary<Guid, OperationSidecar> _sidecars = [];
    private readonly Dictionary<Guid, StoredValidationReport> _validations = [];

    public SignatureApiRequestHandler(
        SignatureOperationService operations,
        IApiCallerResolver callers,
        AgentTicketIssuer tickets,
        ISignatureWorkflow? workflow = null,
        DeviceEnrollmentAuthority? devices = null,
        ISignatureExtensionWorkflow? extensions = null)
    {
        ArgumentNullException.ThrowIfNull(operations);
        ArgumentNullException.ThrowIfNull(callers);
        ArgumentNullException.ThrowIfNull(tickets);
        _operations = operations;
        _callers = callers;
        _tickets = tickets;
        _workflow = workflow ?? new InMemorySignatureWorkflow();
        _devices = devices ?? new DeviceEnrollmentAuthority();
        _extensions = extensions ?? new UnavailableSignatureExtensionWorkflow();
        _callbackTickets = new AgentTicketValidator(tickets.PublicKey, new InMemoryNonceStore());
    }

    public ApiHttpResponse Handle(ApiHttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        string correlationId = ResolveCorrelationId(request);
        if (request.Body.Length > MaxJsonBytes)
        {
            return Problem(ApiProblemKind.PayloadTooLarge, correlationId);
        }

        if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(request.Path, "/v1/openapi.yaml", StringComparison.Ordinal))
        {
            return JsonResult(200, OpenApiContract.ReadYaml(), correlationId, "application/yaml");
        }

        if (string.Equals(request.Path, "/v1/agent-callbacks/signature-results", StringComparison.Ordinal))
        {
            return HandleAgentCallback(request, correlationId);
        }

        ApiCallerIdentity caller = _callers.Resolve(request);
        if (!caller.Authenticated)
        {
            return Problem(ApiProblemKind.Unauthenticated, correlationId);
        }

        if (TryMatch(request.Path, "/v1/signature-operations", out _) &&
            string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return CreateOperation(request, caller, correlationId);
        }

        if (TryMatch(request.Path, "/v1/validations", out _) &&
            string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return CreateValidation(request, correlationId);
        }

        if (TryMatch(request.Path, "/v1/signatures/extend", out _) &&
            string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return ExtendSignature(request, caller, correlationId);
        }

        if (TryMatch(request.Path, "/v1/validations/", out string validationTail) &&
            string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
            Guid.TryParse(validationTail, out Guid validationId))
        {
            return _validations.TryGetValue(validationId, out StoredValidationReport? report)
                ? JsonResult(200, JsonSerializer.Serialize(ToValidationJson(report), Json), correlationId)
                : Problem(ApiProblemKind.NotFound, correlationId);
        }

        if (TryMatch(request.Path, "/v1/signature-operations/", out string operationTail))
        {
            return HandleOperationResource(request, caller, correlationId, operationTail);
        }

        return Problem(ApiProblemKind.NotFound, correlationId);
    }

    private ApiHttpResponse HandleOperationResource(
        ApiHttpRequest request,
        ApiCallerIdentity caller,
        string correlationId,
        string tail)
    {
        string[] parts = tail.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || !Guid.TryParse(parts[0], out Guid operationId))
        {
            return Problem(ApiProblemKind.NotFound, correlationId);
        }

        if (parts.Length == 1 && string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase))
        {
            SignatureOperation? operation = _operations.Get(operationId);
            return operation is null
                ? Problem(ApiProblemKind.NotFound, correlationId, operationId)
                : JsonResult(200, SerializeOperation(operation), correlationId);
        }

        if (parts.Length != 2 || !string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return Problem(ApiProblemKind.NotFound, correlationId, operationId);
        }

        if (!TryReadIdempotencyKey(request, out string idempotencyKey, out ApiHttpResponse? missingKey))
        {
            return missingKey!;
        }

        return parts[1] switch
        {
            "agent-ticket" => IssueTicket(request, caller, correlationId, operationId, idempotencyKey),
            "certificate" => BindCertificate(request, correlationId, operationId, idempotencyKey),
            "prepare" => Prepare(request, correlationId, operationId, idempotencyKey),
            "complete" => Complete(request, correlationId, operationId, idempotencyKey),
            "cancel" => Cancel(request, correlationId, operationId, idempotencyKey),
            _ => Problem(ApiProblemKind.NotFound, correlationId, operationId)
        };
    }

    private ApiHttpResponse CreateOperation(ApiHttpRequest request, ApiCallerIdentity caller, string correlationId)
    {
        if (!TryReadIdempotencyKey(request, out string idempotencyKey, out ApiHttpResponse? missingKey))
        {
            return missingKey!;
        }

        if (!TryReadCreateBody(request.Body, out CreateBody body, out ApiProblemKind? problem))
        {
            return Problem(problem!.Value, correlationId);
        }

        _ = caller;
        string hash = CanonicalRequestHasher.Hash(request.Method, request.Path, request.Body);
        SignatureOperationResult result = _operations.Create(idempotencyKey, hash, body.Sha256);
        if (result.Status == OperationMutationStatus.IdempotencyConflict)
        {
            return Problem(ApiProblemKind.IdempotencyConflict, correlationId);
        }

        SignatureOperation operation = result.Operation!;
        _sidecars.TryAdd(operation.Id, new OperationSidecar(body.ObjectKey, body.Sha256, body.Size, body.Profile));
        return JsonResult(201, SerializeOperation(operation), correlationId);
    }

    private ApiHttpResponse IssueTicket(
        ApiHttpRequest request,
        ApiCallerIdentity caller,
        string correlationId,
        Guid operationId,
        string idempotencyKey)
    {
        SignatureOperation? current = _operations.Get(operationId);
        if (current is null)
        {
            return Problem(ApiProblemKind.NotFound, correlationId, operationId);
        }

        if (!TryHeader(request, "Origin", out string? origin) &&
            !TryHeader(request, "X-Calling-Origin", out origin))
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId, operationId);
        }

        if (current.State == SignatureOperationState.Created)
        {
            SignatureOperationResult transition = _operations.Transition(
                operationId,
                SignatureOperationState.WaitingForClient,
                current.Version,
                idempotencyKey,
                CanonicalRequestHasher.Hash(request.Method, request.Path, request.Body));
            if (transition.Status is OperationMutationStatus.InvalidTransition or OperationMutationStatus.TerminalState)
            {
                return Problem(ApiProblemKind.InvalidStateTransition, correlationId, operationId);
            }

            if (transition.Status == OperationMutationStatus.IdempotencyConflict)
            {
                return Problem(ApiProblemKind.IdempotencyConflict, correlationId, operationId);
            }

            current = transition.Operation ?? current;
        }
        else if (current.State != SignatureOperationState.WaitingForClient)
        {
            return Problem(ApiProblemKind.InvalidStateTransition, correlationId, operationId);
        }

        AgentTicket ticket = _tickets.Issue(
            origin!,
            current.Id,
            caller.TenantId,
            caller.ApplicationId,
            current.DocumentDigest);
        string encoded = AgentTicketCodec.Encode(ticket);
        return JsonResult(200, JsonSerializer.Serialize(new { ticket = encoded, expiresAt = ticket.ExpiresAt }, Json), correlationId);
    }

    private ApiHttpResponse BindCertificate(ApiHttpRequest request, string correlationId, Guid operationId, string idempotencyKey)
    {
        SignatureOperation? current = _operations.Get(operationId);
        if (current is null)
        {
            return Problem(ApiProblemKind.NotFound, correlationId, operationId);
        }

        if (!TryReadCertificate(request.Body, out string der, out string fingerprint))
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId, operationId);
        }

        if (current.State == SignatureOperationState.WaitingForClient)
        {
            SignatureOperationResult connected = Move(current, SignatureOperationState.ClientConnected, idempotencyKey + ":connected", request);
            if (!connected.OperationMutationSucceeded() && connected.Status != OperationMutationStatus.Replayed)
            {
                return MapMutation(connected, correlationId, operationId);
            }

            current = connected.Operation ?? current;
        }

        SignatureOperationResult bound = Move(current, SignatureOperationState.CertificateSelected, idempotencyKey, request);
        if (!bound.OperationMutationSucceeded() && bound.Status != OperationMutationStatus.Replayed)
        {
            return MapMutation(bound, correlationId, operationId);
        }

        if (_sidecars.TryGetValue(operationId, out OperationSidecar? sidecar))
        {
            sidecar.CertificateDerBase64 = der;
            sidecar.Fingerprint = fingerprint;
        }

        return JsonResult(200, SerializeOperation(bound.Operation ?? current), correlationId);
    }

    private ApiHttpResponse Prepare(ApiHttpRequest request, string correlationId, Guid operationId, string idempotencyKey)
    {
        SignatureOperation? current = _operations.Get(operationId);
        if (current is null)
        {
            return Problem(ApiProblemKind.NotFound, correlationId, operationId);
        }

        SignatureOperationResult prepared = Move(current, SignatureOperationState.Prepared, idempotencyKey, request);
        if (!prepared.OperationMutationSucceeded() && prepared.Status != OperationMutationStatus.Replayed)
        {
            return MapMutation(prepared, correlationId, operationId);
        }

        if (!_sidecars.TryGetValue(operationId, out OperationSidecar? sidecar) ||
            sidecar.CertificateDerBase64 is null || sidecar.Fingerprint is null)
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId, operationId);
        }

        SignaturePrepareResult prepare = _workflow.Prepare(operationId, sidecar.CertificateDerBase64, sidecar.Fingerprint);
        sidecar.CompletionToken = prepare.CompletionToken;
        sidecar.PrepareVersion = prepare.PrepareVersion;
        return JsonResult(200, JsonSerializer.Serialize(prepare, Json), correlationId);
    }

    private ApiHttpResponse Complete(ApiHttpRequest request, string correlationId, Guid operationId, string idempotencyKey)
    {
        SignatureOperation? current = _operations.Get(operationId);
        if (current is null)
        {
            return Problem(ApiProblemKind.NotFound, correlationId, operationId);
        }

        if (!TryReadComplete(request.Body, out CompleteBody complete))
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId, operationId);
        }

        if (!_workflow.Complete(complete.CompletionToken, complete.PrepareVersion, complete.CertificateFingerprintSha256))
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId, operationId);
        }

        if (current.State == SignatureOperationState.Prepared)
        {
            SignatureOperationResult signing = Move(current, SignatureOperationState.Signing, idempotencyKey + ":signing", request);
            if (!signing.OperationMutationSucceeded() && signing.Status != OperationMutationStatus.Replayed)
            {
                return MapMutation(signing, correlationId, operationId);
            }

            current = signing.Operation ?? current;
        }

        SignatureOperationResult signed = Move(current, SignatureOperationState.Signed, idempotencyKey, request);
        if (!signed.OperationMutationSucceeded() && signed.Status != OperationMutationStatus.Replayed)
        {
            return MapMutation(signed, correlationId, operationId);
        }

        return JsonResult(200, SerializeOperation(signed.Operation ?? current), correlationId);
    }

    private ApiHttpResponse Cancel(ApiHttpRequest request, string correlationId, Guid operationId, string idempotencyKey)
    {
        SignatureOperation? current = _operations.Get(operationId);
        if (current is null)
        {
            return Problem(ApiProblemKind.NotFound, correlationId, operationId);
        }

        SignatureOperationResult cancelled = Move(current, SignatureOperationState.Cancelled, idempotencyKey, request);
        if (!cancelled.OperationMutationSucceeded() && cancelled.Status != OperationMutationStatus.Replayed)
        {
            return MapMutation(cancelled, correlationId, operationId);
        }

        return JsonResult(200, SerializeOperation(cancelled.Operation ?? current), correlationId);
    }

    private ApiHttpResponse CreateValidation(ApiHttpRequest request, string correlationId)
    {
        if (!TryReadIdempotencyKey(request, out _, out ApiHttpResponse? missingKey))
        {
            return missingKey!;
        }

        if (!TryReadCreateBody(request.Body, out CreateBody body, out ApiProblemKind? problem, requireFormat: false))
        {
            return Problem(problem!.Value, correlationId);
        }

        StoredValidationReport report = _workflow.Validate(body.ObjectKey, body.Sha256, body.Profile);
        _validations[report.ValidationId] = report;
        return JsonResult(202, JsonSerializer.Serialize(ToValidationJson(report), Json), correlationId);
    }

    private SignatureOperationResult Move(
        SignatureOperation current,
        SignatureOperationState target,
        string idempotencyKey,
        ApiHttpRequest request) =>
        _operations.Transition(
            current.Id,
            target,
            current.Version,
            idempotencyKey,
            CanonicalRequestHasher.Hash(request.Method, request.Path, request.Body + ":" + target));

    private static ApiHttpResponse MapMutation(SignatureOperationResult result, string correlationId, Guid operationId) =>
        result.Status switch
        {
            OperationMutationStatus.NotFound => Problem(ApiProblemKind.NotFound, correlationId, operationId),
            OperationMutationStatus.IdempotencyConflict => Problem(ApiProblemKind.IdempotencyConflict, correlationId, operationId),
            OperationMutationStatus.InvalidTransition or OperationMutationStatus.TerminalState or OperationMutationStatus.VersionConflict =>
                Problem(ApiProblemKind.InvalidStateTransition, correlationId, operationId),
            _ => Problem(ApiProblemKind.Unprocessable, correlationId, operationId)
        };

    private static bool TryReadCreateBody(
        string body,
        out CreateBody parsed,
        out ApiProblemKind? problem,
        bool requireFormat = true)
    {
        parsed = default!;
        problem = ApiProblemKind.Unprocessable;
        try
        {
            using JsonDocument document = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
            JsonElement root = document.RootElement;
            if (!root.TryGetProperty("document", out JsonElement documentElement) ||
                !TryString(documentElement, "objectKey", out string? objectKey) ||
                !TryString(documentElement, "sha256", out string? sha256) ||
                !documentElement.TryGetProperty("size", out JsonElement sizeElement) ||
                !sizeElement.TryGetInt64(out long size) ||
                !TryString(root, "validationProfile", out string? profile))
            {
                return false;
            }

            if (requireFormat &&
                (!TryString(root, "format", out string? format) ||
                 !string.Equals(format, "PAdES", StringComparison.Ordinal) ||
                 !TryString(root, "targetLevel", out string? level) ||
                 !string.Equals(level, "B-B", StringComparison.Ordinal)))
            {
                return false;
            }

            if (profile is not ("TurkiyeNes" or "GenelX509") || !Sha256Pattern.IsMatch(sha256!))
            {
                return false;
            }

            if (size < 1 || size > MaxDocumentBytes)
            {
                problem = ApiProblemKind.PayloadTooLarge;
                return false;
            }

            parsed = new CreateBody(objectKey!, sha256!, size, profile!);
            problem = null;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryReadCertificate(string body, out string der, out string fingerprint)
    {
        der = "";
        fingerprint = "";
        try
        {
            using JsonDocument document = JsonDocument.Parse(body);
            if (!TryString(document.RootElement, "certificateDerBase64", out string? derValue) ||
                !TryString(document.RootElement, "fingerprintSha256", out string? fingerprintValue) ||
                !Sha256Pattern.IsMatch(fingerprintValue!))
            {
                return false;
            }

            byte[] bytes = Convert.FromBase64String(derValue!);
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), fingerprintValue, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            der = derValue!;
            fingerprint = fingerprintValue!;
            return true;
        }
        catch (Exception exception) when (exception is JsonException or FormatException)
        {
            return false;
        }
    }

    private static bool TryReadComplete(string body, out CompleteBody complete)
    {
        complete = default!;
        try
        {
            CompleteBody? parsed = JsonSerializer.Deserialize<CompleteBody>(body, Json);
            if (parsed is null ||
                parsed.PrepareVersion < 1 ||
                parsed.CompletionToken.Length < 32 ||
                !Sha256Pattern.IsMatch(parsed.CertificateFingerprintSha256))
            {
                return false;
            }

            complete = parsed;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryReadIdempotencyKey(ApiHttpRequest request, out string key, out ApiHttpResponse? problem)
    {
        key = "";
        problem = null;
        if (!TryHeader(request, "Idempotency-Key", out string? value) ||
            value!.Length is < 16 or > 128)
        {
            problem = Problem(ApiProblemKind.Unprocessable, ResolveCorrelationId(request));
            return false;
        }

        key = value;
        return true;
    }

    private static bool TryHeader(ApiHttpRequest request, string name, out string? value) =>
        request.Headers.TryGetValue(name, out value) && !string.IsNullOrWhiteSpace(value);

    private static string ResolveCorrelationId(ApiHttpRequest request)
    {
        if (TryHeader(request, "X-Correlation-Id", out string? value) && value!.Length <= 128)
        {
            return value;
        }

        return Guid.NewGuid().ToString("N");
    }

    private static bool TryMatch(string path, string prefix, out string tail)
    {
        tail = "";
        if (string.Equals(path, prefix, StringComparison.Ordinal))
        {
            return true;
        }

        if (path.StartsWith(prefix, StringComparison.Ordinal) && prefix.EndsWith('/'))
        {
            tail = path[prefix.Length..];
            return true;
        }

        return false;
    }

    private static bool TryString(JsonElement element, string name, out string? value)
    {
        value = null;
        if (!element.TryGetProperty(name, out JsonElement property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString();
        return !string.IsNullOrWhiteSpace(value);
    }

    private static string SerializeOperation(SignatureOperation operation) =>
        JsonSerializer.Serialize(
            new
            {
                operationId = operation.Id,
                status = operation.State.ToString(),
                documentDigest = operation.DocumentDigest,
                expiresAt = operation.ExpiresAt,
                resultObjectKey = operation.ResultObjectKey
            },
            Json);

    private static object ToValidationJson(StoredValidationReport report) => new
    {
        validationId = report.ValidationId,
        outcome = report.Outcome,
        subIndication = (string?)null,
        onlineRevocationChecked = report.OnlineRevocationChecked,
        trustStoreVersion = report.TrustStoreVersion,
        signatures = report.Signatures.Select(item => new
        {
            revision = item.Revision,
            outcome = item.Outcome,
            documentSha256 = item.DocumentSha256
        })
    };

    private static ApiHttpResponse JsonResult(int status, string body, string correlationId, string contentType = "application/json") =>
        new()
        {
            StatusCode = status,
            Body = body,
            ContentType = contentType,
            CorrelationId = correlationId
        };

    private static ApiHttpResponse Problem(ApiProblemKind kind, string correlationId, Guid? operationId = null) =>
        ProblemDetailsFactory.Create(kind, correlationId, operationId);

    private sealed record CreateBody(string ObjectKey, string Sha256, long Size, string Profile);

    private sealed record CompleteBody(
        int PrepareVersion,
        string SignatureValueBase64,
        string CompletionToken,
        string CertificateFingerprintSha256);

    private sealed class OperationSidecar(string objectKey, string sha256, long size, string profile)
    {
        public string ObjectKey { get; } = objectKey;
        public string Sha256 { get; } = sha256;
        public long Size { get; } = size;
        public string Profile { get; } = profile;
        public string? CertificateDerBase64 { get; set; }
        public string? Fingerprint { get; set; }
        public string? CompletionToken { get; set; }
        public int PrepareVersion { get; set; }
    }
}
