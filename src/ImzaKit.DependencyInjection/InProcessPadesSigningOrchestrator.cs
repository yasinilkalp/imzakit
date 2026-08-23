using System.Security.Cryptography;
using ImzaKit.Api.Operations;
using ImzaKit.Core.Signing;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Pkcs11.Signing;
using ImzaKit.Pkcs11.Models;
using ImzaKit.Verify.Validation;

namespace ImzaKit.DependencyInjection;

public sealed class InProcessPadesSigningOrchestrator(
    SignatureOperationService operationService,
    PadesSignaturePreparer padesPreparer,
    Pkcs11SigningService signingService)
{
    public InProcessSigningResult Execute(
        byte[] originalPdf,
        ulong slotId,
        Pkcs11Certificate certificate,
        ReadOnlySpan<char> pin)
    {
        ArgumentNullException.ThrowIfNull(originalPdf);
        string documentSha256 = Convert.ToHexString(SHA256.HashData(originalPdf));
        SignatureOperation operation = Required(operationService.Create("create-" + documentSha256, documentSha256));
        operation = Move(operation, SignatureOperationState.WaitingForClient, "waiting");
        operation = Move(operation, SignatureOperationState.ClientConnected, "connected");
        operation = Move(operation, SignatureOperationState.CertificateSelected, "certificate");

        operation = Move(operation, SignatureOperationState.Prepared, "prepared");
        byte[] certificateDer = certificate.DerEncoded;
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        PadesSignaturePreparation preparation = padesPreparer.Prepare(
            operation.Id, documentSha256, originalPdf, 4096, certificateDer, fingerprint, operation.Version);
        operation = Move(operation, SignatureOperationState.Signing, "signing");
        Pkcs11SigningResult signature = signingService.Sign(
            slotId, certificate.CkaId, pin, preparation.SignaturePreparation.DataToBeSigned.Span);
        if (signature.Status != Pkcs11SigningStatus.Succeeded || signature.Signature is null)
            throw new InvalidOperationException($"PKCS#11 signing failed: {signature.Status}.");

        SignatureCompletion completion = SignatureCompletion.Create(
            preparation.SignaturePreparation.OperationId,
            preparation.SignaturePreparation.PrepareVersion,
            fingerprint,
            signature.Signature);
        byte[] signedPdf = PadesSignatureCompleter.Complete(preparation, completion, certificateDer);
        operation = Move(operation, SignatureOperationState.Signed, "signed");
        operation = Move(operation, SignatureOperationState.Validating, "validating");
        PadesValidationReport validation = PadesValidator.Validate(signedPdf);
        operation = Move(operation, SignatureOperationState.Completed, "completed");
        return new(operation, signedPdf, validation);
    }

    private SignatureOperation Move(SignatureOperation operation, SignatureOperationState target, string step) =>
        Required(operationService.Transition(
            operation.Id, target, operation.Version,
            $"{operation.Id:D}-{step}", $"{operation.Version}:{target}"));

    private static SignatureOperation Required(SignatureOperationResult result) =>
        result.OperationMutationSucceeded()
            ? result.Operation!
            : throw new InvalidOperationException($"Operation mutation failed: {result.Status}.");
}
