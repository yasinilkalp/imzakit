using System.Diagnostics.CodeAnalysis;

namespace ImzaKit.Api.Operations;

public enum SignatureOperationState
{
    Created,
    WaitingForClient,
    ClientConnected,
    CertificateSelected,
    Prepared,
    Signing,
    [SuppressMessage("Naming", "CA1720:Identifier contains type name", Justification = "Signed is part of the published OpenAPI state contract.")]
    Signed,
    Timestamping,
    Validating,
    Completed,
    Failed,
    Cancelled,
    Expired
}
