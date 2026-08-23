using ImzaKit.Agent.Configuration;
using ImzaKit.Api.Problems;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Cryptography;
using ImzaKit.Cryptography.Digests;
using ImzaKit.DependencyInjection;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Pkcs11.Akis;
using ImzaKit.Verify.Validation;

var names = new[]
{
    typeof(AgentLoopbackOptions).Assembly.GetName().Name,
    typeof(ApiProblemCatalog).Assembly.GetName().Name,
    typeof(CmsSignaturePreparer).Assembly.GetName().Name,
    typeof(HashAlgorithmId).Assembly.GetName().Name,
    typeof(DefaultDigestCalculator).Assembly.GetName().Name,
    typeof(ImzaKitServiceCollectionExtensions).Assembly.GetName().Name,
    typeof(PadesSignaturePreparer).Assembly.GetName().Name,
    typeof(AkisProviderProfile).Assembly.GetName().Name,
    typeof(PadesValidator).Assembly.GetName().Name
};

Console.WriteLine(string.Join('|', names));
