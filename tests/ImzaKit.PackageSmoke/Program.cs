using ImzaKit.Agent.Configuration;
using ImzaKit.Api.Problems;
using ImzaKit.ASiC;
using ImzaKit.CAdES;
using ImzaKit.XAdES;
using ImzaKit.Certificate.Models;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Cryptography;
using ImzaKit.Cryptography.Digests;
using ImzaKit.DependencyInjection;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Pkcs11.Akis;
using ImzaKit.Revocation.Models;
using ImzaKit.Trust.Models;
using ImzaKit.Verify.Validation;

ValidationContext context = new(
    ValidationProfile.GeneralX509,
    DateTimeOffset.UtcNow,
    ValidationTimeSource.CurrentSystemTime,
    new TrustStoreSnapshot("smoke-trust-v1", []),
    new CertificatePolicyCatalog("smoke-policy-v1", []));
PadesValidationReport validation = PadesValidator.Validate("not a pdf"u8, context);

var names = new[]
{
    typeof(AgentLoopbackOptions).Assembly.GetName().Name,
    typeof(ApiProblemCatalog).Assembly.GetName().Name,
    typeof(CertificateDescriptor).Assembly.GetName().Name,
    typeof(CmsSignaturePreparer).Assembly.GetName().Name,
    typeof(AsicPacker).Assembly.GetName().Name,
    typeof(CadesValidator).Assembly.GetName().Name,
    typeof(XadesSigner).Assembly.GetName().Name,
    typeof(HashAlgorithmId).Assembly.GetName().Name,
    typeof(DefaultDigestCalculator).Assembly.GetName().Name,
    typeof(ImzaKitServiceCollectionExtensions).Assembly.GetName().Name,
    typeof(PadesSignaturePreparer).Assembly.GetName().Name,
    typeof(AkisProviderProfile).Assembly.GetName().Name,
    typeof(RevocationEvidenceSet).Assembly.GetName().Name,
    typeof(TrustStoreSnapshot).Assembly.GetName().Name,
    typeof(PadesValidator).Assembly.GetName().Name
};

Console.WriteLine(string.Join('|', names));
Console.WriteLine(validation.Status);
