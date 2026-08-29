using System.Text.Json;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Problems;
using ImzaKit.Api.Workflow;

namespace ImzaKit.Api.Hosting;

public sealed partial class SignatureApiRequestHandler
{
    private ApiHttpResponse HandleEnvelopeResource(ApiHttpRequest request, string correlationId, string tail)
    {
        string[] parts = tail.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || !Guid.TryParse(parts[0], out Guid envelopeId))
        {
            return Problem(ApiProblemKind.NotFound, correlationId);
        }

        if (parts.Length == 1 && string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase))
        {
            return _envelopes.TryGetValue(envelopeId, out SignatureEnvelope? envelope)
                ? JsonResult(200, SerializeEnvelope(envelope), correlationId)
                : Problem(ApiProblemKind.NotFound, correlationId);
        }

        if (parts.Length == 2
            && string.Equals(parts[1], "report", StringComparison.OrdinalIgnoreCase)
            && string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase))
        {
            if (!_envelopes.TryGetValue(envelopeId, out SignatureEnvelope? envelope))
            {
                return Problem(ApiProblemKind.NotFound, correlationId);
            }

            IReadOnlyList<WorkflowSignatureReport> report = SignatureFlowCoordinator.Report(envelope);
            return JsonResult(
                200,
                JsonSerializer.Serialize(new { signatures = report.Select(ToReportJson) }, Json),
                correlationId);
        }

        if (parts.Length != 4
            || !string.Equals(parts[1], "steps", StringComparison.OrdinalIgnoreCase)
            || !int.TryParse(parts[2], out int stepIndex)
            || !string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return Problem(ApiProblemKind.NotFound, correlationId);
        }

        if (!TryReadIdempotencyKey(request, out string idempotencyKey, out ApiHttpResponse? missingKey))
        {
            return missingKey!;
        }

        return parts[3] switch
        {
            "prepare" => MutateEnvelope(request, correlationId, envelopeId, idempotencyKey, 200,
                envelope => SignatureFlowCoordinator.PrepareStep(envelope, stepIndex, DateTimeOffset.UtcNow)),
            "complete" => CompleteEnvelopeStep(request, correlationId, envelopeId, stepIndex, idempotencyKey),
            "reject" => MutateEnvelope(request, correlationId, envelopeId, idempotencyKey, 200,
                envelope => SignatureFlowCoordinator.RejectStep(envelope, stepIndex, DateTimeOffset.UtcNow)),
            _ => Problem(ApiProblemKind.NotFound, correlationId)
        };
    }

    private ApiHttpResponse CreateEnvelope(ApiHttpRequest request, string correlationId)
    {
        if (!TryReadIdempotencyKey(request, out string idempotencyKey, out ApiHttpResponse? missingKey))
        {
            return missingKey!;
        }

        string hash = CanonicalRequestHasher.Hash(request.Method, request.Path, request.Body);
        if (TryReplay(idempotencyKey, hash, correlationId, out ApiHttpResponse? replayed))
        {
            return replayed!;
        }

        if (!TryReadEnvelopeBody(request.Body, out EnvelopeCreateBody body, out ApiProblemKind? problem))
        {
            return Problem(problem!.Value, correlationId);
        }

        SignatureEnvelope envelope;
        try
        {
            envelope = SignatureFlowCoordinator.Create(
                body.Flow,
                body.MergeStrategy,
                body.Policy,
                body.ApprovedDocumentSha256);
        }
        catch (ArgumentException)
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId);
        }

        return StoreEnvelope(idempotencyKey, hash, envelope, 201, correlationId);
    }

    private ApiHttpResponse CompleteEnvelopeStep(
        ApiHttpRequest request,
        string correlationId,
        Guid envelopeId,
        int stepIndex,
        string idempotencyKey)
    {
        if (!TryReadEnvelopeComplete(request.Body, out EnvelopeCompleteBody complete))
        {
            return Problem(ApiProblemKind.Unprocessable, correlationId);
        }

        return MutateEnvelope(request, correlationId, envelopeId, idempotencyKey, 200,
            envelope => SignatureFlowCoordinator.CompleteStep(
                envelope,
                stepIndex,
                complete.CertificateFingerprintSha256,
                complete.SignedDocumentSha256,
                complete.CoveredRevision,
                DateTimeOffset.UtcNow));
    }

    private ApiHttpResponse MutateEnvelope(
        ApiHttpRequest request,
        string correlationId,
        Guid envelopeId,
        string idempotencyKey,
        int successStatus,
        Func<SignatureEnvelope, WorkflowMutationResult> mutate)
    {
        string hash = CanonicalRequestHasher.Hash(request.Method, request.Path, request.Body);
        if (TryReplay(idempotencyKey, hash, correlationId, out ApiHttpResponse? replayed))
        {
            return replayed!;
        }

        if (!_envelopes.TryGetValue(envelopeId, out SignatureEnvelope? envelope))
        {
            return Problem(ApiProblemKind.NotFound, correlationId);
        }

        WorkflowMutationResult result = mutate(envelope);
        if (!result.Succeeded)
        {
            return Problem(MapWorkflowProblem(result.ProblemCode), correlationId);
        }

        return StoreEnvelope(idempotencyKey, hash, result.Envelope, successStatus, correlationId);
    }

    private bool TryReplay(string idempotencyKey, string hash, string correlationId, out ApiHttpResponse? response)
    {
        response = null;
        IdempotencyLookup replay = _envelopeIdempotency.Find(idempotencyKey, hash);
        if (replay.Status == IdempotencyLookupStatus.Conflict)
        {
            response = Problem(ApiProblemKind.IdempotencyConflict, correlationId);
            return true;
        }

        if (replay.Status == IdempotencyLookupStatus.Match && replay.Response is EnvelopeReplay stored)
        {
            response = JsonResult(stored.StatusCode, stored.Body, correlationId);
            return true;
        }

        return false;
    }

    private ApiHttpResponse StoreEnvelope(
        string idempotencyKey,
        string hash,
        SignatureEnvelope envelope,
        int statusCode,
        string correlationId)
    {
        string body = SerializeEnvelope(envelope);
        _envelopes[envelope.Id] = envelope;
        _envelopeIdempotency.Store(idempotencyKey, hash, new EnvelopeReplay(statusCode, body));
        return JsonResult(statusCode, body, correlationId);
    }

    private static ApiProblemKind MapWorkflowProblem(string? code) => code switch
    {
        WorkflowProblemCodes.StepNotReady => ApiProblemKind.WorkflowStepNotReady,
        WorkflowProblemCodes.DuplicateSigner => ApiProblemKind.WorkflowDuplicateSigner,
        WorkflowProblemCodes.DeadlineExpired => ApiProblemKind.WorkflowDeadlineExpired,
        WorkflowProblemCodes.EnvelopeClosed => ApiProblemKind.WorkflowEnvelopeClosed,
        _ => ApiProblemKind.Unprocessable
    };

    private static string SerializeEnvelope(SignatureEnvelope envelope) =>
        JsonSerializer.Serialize(
            new
            {
                envelopeId = envelope.Id,
                flow = envelope.Flow.ToString(),
                mergeStrategy = envelope.MergeStrategy.ToString(),
                status = envelope.Status.ToString(),
                approvedDocumentSha256 = envelope.ApprovedDocumentSha256,
                currentDocumentSha256 = envelope.CurrentDocumentSha256,
                steps = envelope.Steps.Select(step => new
                {
                    index = step.Index,
                    role = step.Role,
                    status = step.Status.ToString(),
                    approvedDigestSha256 = step.ApprovedDigestSha256,
                    certificateFingerprintSha256 = step.CertificateFingerprintSha256,
                    coveredRevision = step.CoveredRevision,
                    completionOrder = step.CompletionOrder
                })
            },
            Json);

    private static object ToReportJson(WorkflowSignatureReport report) => new
    {
        order = report.Order,
        role = report.Role,
        certificateFingerprintSha256 = report.CertificateFingerprintSha256,
        approvedDigestSha256 = report.ApprovedDigestSha256,
        coveredRevision = report.CoveredRevision,
        subsequentChangeSemantics = report.SubsequentChangeSemantics
    };

    private static bool TryReadEnvelopeBody(string body, out EnvelopeCreateBody parsed, out ApiProblemKind? problem)
    {
        parsed = default!;
        problem = ApiProblemKind.Unprocessable;
        try
        {
            using JsonDocument document = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
            JsonElement root = document.RootElement;
            if (!root.TryGetProperty("document", out JsonElement documentElement)
                || !TryString(documentElement, "sha256", out string? sha256)
                || !Sha256Pattern.IsMatch(sha256!)
                || !TryString(root, "flow", out string? flowText)
                || !Enum.TryParse(flowText, ignoreCase: true, out SignatureFlowKind flow)
                || !TryString(root, "mergeStrategy", out string? mergeText)
                || !Enum.TryParse(mergeText, ignoreCase: true, out ParallelMergeStrategy merge)
                || !root.TryGetProperty("policy", out JsonElement policyElement)
                || !TryReadPolicy(policyElement, flow, out SignaturePolicy policy))
            {
                return false;
            }

            parsed = new EnvelopeCreateBody(sha256!, flow, merge, policy);
            problem = null;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryReadPolicy(JsonElement policy, SignatureFlowKind flow, out SignaturePolicy parsed)
    {
        parsed = null!;
        if (!policy.TryGetProperty("requiredRoles", out JsonElement rolesElement)
            || rolesElement.ValueKind != JsonValueKind.Array
            || !TryString(policy, "rejection", out string? rejectionText)
            || !Enum.TryParse(rejectionText, ignoreCase: true, out SignatureRejectionBehavior rejection)
            || !TryString(policy, "duplicateSigner", out string? duplicateText)
            || !Enum.TryParse(duplicateText, ignoreCase: true, out DuplicateSignerPolicy duplicate))
        {
            return false;
        }

        List<string> roles = [];
        foreach (JsonElement role in rolesElement.EnumerateArray())
        {
            if (role.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(role.GetString()))
            {
                return false;
            }

            roles.Add(role.GetString()!);
        }

        if (roles.Count == 0)
        {
            return false;
        }

        DateTimeOffset? deadline = null;
        if (policy.TryGetProperty("deadlineUtc", out JsonElement deadlineElement)
            && deadlineElement.ValueKind != JsonValueKind.Null)
        {
            if (deadlineElement.ValueKind != JsonValueKind.String
                || !DateTimeOffset.TryParse(deadlineElement.GetString(), out DateTimeOffset parsedDeadline))
            {
                return false;
            }

            deadline = parsedDeadline;
        }

        parsed = new SignaturePolicy(
            roles.Count,
            roles,
            enforceOrder: flow == SignatureFlowKind.Serial,
            deadline,
            rejection,
            duplicate);
        return true;
    }

    private static bool TryReadEnvelopeComplete(string body, out EnvelopeCompleteBody complete)
    {
        complete = default!;
        try
        {
            using JsonDocument document = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
            JsonElement root = document.RootElement;
            if (!TryString(root, "certificateFingerprintSha256", out string? fingerprint)
                || !Sha256Pattern.IsMatch(fingerprint!)
                || !TryString(root, "signedDocumentSha256", out string? signed)
                || !Sha256Pattern.IsMatch(signed!)
                || !root.TryGetProperty("coveredRevision", out JsonElement revisionElement)
                || !revisionElement.TryGetInt32(out int revision)
                || revision < 1)
            {
                return false;
            }

            complete = new EnvelopeCompleteBody(fingerprint!, signed!, revision);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private sealed record EnvelopeCreateBody(
        string ApprovedDocumentSha256,
        SignatureFlowKind Flow,
        ParallelMergeStrategy MergeStrategy,
        SignaturePolicy Policy);

    private sealed record EnvelopeCompleteBody(
        string CertificateFingerprintSha256,
        string SignedDocumentSha256,
        int CoveredRevision);

    private sealed record EnvelopeReplay(int StatusCode, string Body);
}
