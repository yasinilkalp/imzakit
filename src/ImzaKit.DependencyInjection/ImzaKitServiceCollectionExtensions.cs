using ImzaKit.Agent.Security;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Operations;
using ImzaKit.Cms.Preparation;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Pkcs11.Signing;
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
        services.AddSingleton<IDigestCalculator, DefaultDigestCalculator>();
        services.AddSingleton<CmsSignaturePreparer>();
        services.AddSingleton<PadesSignaturePreparer>();
        services.AddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();
        services.AddSingleton<SignatureOperationService>();
        services.AddSingleton<INonceStore, InMemoryNonceStore>();
        services.AddSingleton(serviceProvider => new AgentTicketValidator(
            publicKey, serviceProvider.GetRequiredService<INonceStore>()));
        services.AddTransient<InProcessPadesSigningOrchestrator>();
        return services;
    }

    public static IServiceCollection AddImzaKitPkcs11(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddTransient<Pkcs11SigningService>();
        return services;
    }
}
