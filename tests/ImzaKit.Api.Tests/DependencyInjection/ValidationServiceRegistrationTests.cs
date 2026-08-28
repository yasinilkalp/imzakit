using ImzaKit.Api.Hosting;
using ImzaKit.Certificate.Building;
using ImzaKit.Certificate.Validation;
using ImzaKit.DependencyInjection;
using ImzaKit.Revocation.Evaluation;
using ImzaKit.Trust.Evaluation;
using ImzaKit.Verify.Validation;
using Microsoft.Extensions.DependencyInjection;

namespace ImzaKit.Api.Tests.DependencyInjection;

public sealed class ValidationServiceRegistrationTests
{
    [Fact]
    public void AddImzaKitCoreResolvesCompleteOfflineValidationGraph()
    {
        using ServiceProvider provider = new ServiceCollection()
            .AddImzaKitCore()
            .BuildServiceProvider();

        Assert.IsType<CertificateChainBuilder>(provider.GetRequiredService<ICertificateChainBuilder>());
        Assert.IsType<CertificateChainValidator>(provider.GetRequiredService<ICertificateChainValidator>());
        Assert.IsType<TrustPolicyEvaluator>(provider.GetRequiredService<ITrustPolicyEvaluator>());
        Assert.IsType<OfflineRevocationEvaluator>(provider.GetRequiredService<IOfflineRevocationEvaluator>());
        Assert.IsType<PadesValidationService>(provider.GetRequiredService<IPadesValidationService>());
        Assert.IsType<PadesDocumentExtensionWorkflow>(provider.GetRequiredService<ISignatureExtensionWorkflow>());
    }
}
