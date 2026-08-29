namespace ImzaKit.Api.Problems;

public enum ApiProblemKind
{
    Unauthenticated,
    NotFound,
    Conflict,
    IdempotencyConflict,
    InvalidStateTransition,
    PayloadTooLarge,
    Unprocessable,
    RateLimited,
    DependencyUnavailable,
    MtlsRequired,
    DeviceUnknown,
    DeviceRevoked,
    DeviceExpired,
    TicketRejected,
    WorkflowStepNotReady,
    WorkflowDuplicateSigner,
    WorkflowDeadlineExpired,
    WorkflowEnvelopeClosed
}
