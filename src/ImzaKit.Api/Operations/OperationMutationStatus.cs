namespace ImzaKit.Api.Operations;

public enum OperationMutationStatus
{
    Succeeded,
    Replayed,
    IdempotencyConflict,
    NotFound,
    VersionConflict,
    InvalidTransition,
    TerminalState
}
