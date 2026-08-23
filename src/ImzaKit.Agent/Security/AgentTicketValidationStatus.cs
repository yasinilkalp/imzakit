namespace ImzaKit.Agent.Security;

public enum AgentTicketValidationStatus
{
    Passed,
    InvalidSignature,
    IssuerMismatch,
    AudienceMismatch,
    Expired,
    NotYetValid,
    LifetimeTooLong,
    OriginMismatch,
    DigestMismatch,
    ActionMismatch,
    Replayed
}
