using ImzaKit.Agent.Native;
using ImzaKit.Agent.Security;
using ImzaKit.Api.Audit;
using ImzaKit.Api.Hosting;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Mtls;
using ImzaKit.Api.Operations;
using ImzaKit.Api.Storage;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Timestamp.Rfc3161;
using ImzaKit.Certificate.Building;
using ImzaKit.Certificate.Validation;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Pkcs11.Signing;
using ImzaKit.Revocation.Evaluation;
using ImzaKit.Revocation.Online;
using ImzaKit.Revocation.Parsing;
using ImzaKit.Trust.Evaluation;
using ImzaKit.Verify.Validation;
using Microsoft.Extensions.DependencyInjection;

namespace ImzaKit.DependencyInjection;

public static class ImzaKitServiceCollectionExtensions
{
    public static IServiceCollection AddImzaKitCore(
        this IServiceCollection services,
        ReadOnlySpan<byte> agentTicketPublicKey = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        byte[] publicKey = agentTicketPublicKey.IsEmpty ? new byte[32] : agentTicketPublicKey.ToArray();
        services.AddSingleton<IExternalResourceFetcher, SsrfExternalResourceFetcher>();
        services.AddSingleton<Rfc3161TimeStampClient>();
        services.AddSingleton<IDigestCalculator, DefaultDigestCalculator>();
        services.AddSingleton<ICertificateChainBuilder, CertificateChainBuilder>();
        services.AddSingleton<ICertificateChainValidator, CertificateChainValidator>();
        services.AddSingleton<ITrustPolicyEvaluator, TrustPolicyEvaluator>();
        services.AddSingleton<IRevocationEvidenceParser, BouncyCastleRevocationEvidenceParser>();
        services.AddSingleton<IRevocationEvidenceCache, MemoryRevocationEvidenceCache>();
        services.AddSingleton<OnlineRevocationClient>();
        services.AddSingleton<IOfflineRevocationEvaluator, OfflineRevocationEvaluator>();
        services.AddSingleton<IRevocationEvaluator, RevocationEvaluator>();
        services.AddSingleton<ValidationDecisionEngine>();
        services.AddSingleton<CmsSignaturePreparer>();
        services.AddSingleton<PadesSignaturePreparer>();
        services.AddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();
        services.AddSingleton<IMetadataStore, InMemoryMetadataStore>();
        services.AddSingleton<IBlobStore, MemoryBlobStore>();
        services.AddSingleton<IDocumentStore>(static services =>
            new EncryptedDocumentStore(
                services.GetRequiredService<IBlobStore>(),
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
        services.AddSingleton<HashChainAuditLog>();
        services.AddSingleton<RetentionMaintenance>();
        services.AddSingleton<SignatureOperationService>();
        services.AddSingleton<INonceStore, InMemoryNonceStore>();
        services.AddSingleton(serviceProvider => new AgentTicketValidator(
            publicKey, serviceProvider.GetRequiredService<INonceStore>()));
        services.AddTransient<InProcessPadesSigningOrchestrator>();
        services.AddTransient<IPadesValidationService, PadesValidationService>();
        services.AddSingleton<ISignatureExtensionWorkflow, PadesDocumentExtensionWorkflow>();
        return services;
    }

    public static IServiceCollection AddImzaKitApiHost(
        this IServiceCollection services,
        ReadOnlySpan<byte> agentTicketPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(services);
        byte[] key = agentTicketPrivateKey.ToArray();
        services.AddSingleton(new AgentTicketIssuer(key));
        services.AddSingleton<DeviceEnrollmentAuthority>();
        services.AddSingleton<ISignatureWorkflow, InMemorySignatureWorkflow>();
        services.AddSingleton<SignatureApiRequestHandler>();
        return services;
    }

    public static IServiceCollection AddImzaKitWindowsAgent(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<ISecurePinDialog, CredUiSecurePinDialog>();
        services.AddSingleton<IConsentDialog, MessageBoxConsentDialog>();
        services.AddSingleton<INativePinPrompt, WindowsNativePinPrompt>();
        services.AddSingleton<INativeConsentPrompt, WindowsNativeConsentPrompt>();
        return services;
    }

    public static IServiceCollection AddImzaKitPkcs11(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddTransient<Pkcs11SigningService>();
        return services;
    }
}
