using ImzaKit.Api.Operations;
using ImzaKit.Verify.Validation;

namespace ImzaKit.DependencyInjection;

public sealed record InProcessSigningResult(
    SignatureOperation Operation,
    byte[] SignedPdf,
    PadesValidationReport Validation);
