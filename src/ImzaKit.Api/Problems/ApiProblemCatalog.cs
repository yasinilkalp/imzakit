using ImzaKit.Api.Workflow;

namespace ImzaKit.Api.Problems;

public static class ApiProblemCatalog
{
    public static ApiProblemDescriptor Get(ApiProblemKind kind) => kind switch
    {
        ApiProblemKind.Unauthenticated => new(401, "IMZAKIT.CORE.UNAUTHENTICATED"),
        ApiProblemKind.NotFound => new(404, "IMZAKIT.CORE.NOT_FOUND"),
        ApiProblemKind.Conflict => new(409, "IMZAKIT.CORE.CONFLICT"),
        ApiProblemKind.IdempotencyConflict => new(409, "IMZAKIT.CORE.IDEMPOTENCY_CONFLICT"),
        ApiProblemKind.InvalidStateTransition => new(409, "IMZAKIT.CORE.INVALID_STATE_TRANSITION"),
        ApiProblemKind.PayloadTooLarge => new(413, "IMZAKIT.CORE.PAYLOAD_TOO_LARGE"),
        ApiProblemKind.Unprocessable => new(422, "IMZAKIT.CORE.UNPROCESSABLE"),
        ApiProblemKind.RateLimited => new(429, "IMZAKIT.CORE.RATE_LIMITED"),
        ApiProblemKind.DependencyUnavailable => new(503, "IMZAKIT.CORE.DEPENDENCY_UNAVAILABLE"),
        ApiProblemKind.MtlsRequired => new(401, "IMZAKIT.AGENT.MTLS_REQUIRED"),
        ApiProblemKind.DeviceUnknown => new(401, "IMZAKIT.AGENT.DEVICE_UNKNOWN"),
        ApiProblemKind.DeviceRevoked => new(401, "IMZAKIT.AGENT.DEVICE_REVOKED"),
        ApiProblemKind.DeviceExpired => new(401, "IMZAKIT.AGENT.DEVICE_EXPIRED"),
        ApiProblemKind.TicketRejected => new(401, "IMZAKIT.AGENT.TICKET_REJECTED"),
        ApiProblemKind.WorkflowStepNotReady => new(409, WorkflowProblemCodes.StepNotReady),
        ApiProblemKind.WorkflowDuplicateSigner => new(422, WorkflowProblemCodes.DuplicateSigner),
        ApiProblemKind.WorkflowDeadlineExpired => new(422, WorkflowProblemCodes.DeadlineExpired),
        ApiProblemKind.WorkflowEnvelopeClosed => new(409, WorkflowProblemCodes.EnvelopeClosed),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
}
