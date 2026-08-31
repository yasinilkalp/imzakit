using ImzaKit.Agent.Native;
using ImzaKit.DependencyInjection;
using ImzaKit.Hosts.Desktop.Pkcs11;
using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Signing;
using ImzaKit.Verify.Validation;
using Microsoft.Extensions.DependencyInjection;

namespace ImzaKit.Hosts.Desktop.Signing;

public sealed class DesktopPadesSigner(INativePinPrompt pinPrompt)
{
    public DesktopSignOutcome Sign(
        byte[] originalPdf,
        DesktopCertificateItem certificate,
        IPkcs11Provider provider)
    {
        ArgumentNullException.ThrowIfNull(originalPdf);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(pinPrompt);

        using NativePinSession? pin = pinPrompt.Acquire();
        if (pin is null)
        {
            return DesktopSignOutcome.Cancelled();
        }

        DesktopSignOutcome? outcome = null;
        pin.Use(span =>
        {
            try
            {
                using ServiceProvider services = Build(provider);
                InProcessPadesSigningOrchestrator orchestrator =
                    services.GetRequiredService<InProcessPadesSigningOrchestrator>();
                InProcessSigningResult result = orchestrator.Execute(
                    originalPdf,
                    certificate.SlotId,
                    certificate.Certificate,
                    span);
                if (result.Validation.CryptographicStatus == ValidationStatus.Failed)
                {
                    outcome = DesktopSignOutcome.Failed(
                        "CRYPTOGRAPHIC_FAILED",
                        "Kriptografik imza doğrulanamadı.");
                    return;
                }

                outcome = DesktopSignOutcome.Succeeded(result.SignedPdf, result.Validation);
            }
            catch (InvalidOperationException exception)
            {
                outcome = MapFailure(exception.Message);
            }
        });

        return outcome ?? DesktopSignOutcome.Failed("SIGNING_FAILED", "İmza üretilemedi.");
    }

    private static ServiceProvider Build(IPkcs11Provider provider)
    {
        ServiceCollection services = new();
        services.AddImzaKitCore();
        services.AddSingleton(provider);
        services.AddImzaKitPkcs11();
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
    }

    private static DesktopSignOutcome MapFailure(string message)
    {
        foreach (Pkcs11SigningStatus status in Enum.GetValues<Pkcs11SigningStatus>())
        {
            if (status is Pkcs11SigningStatus.Succeeded)
            {
                continue;
            }

            if (message.Contains(status.ToString(), StringComparison.Ordinal))
            {
                return DesktopSignOutcome.Failed(status.ToString(), UserMessage(status));
            }
        }

        return DesktopSignOutcome.Failed("SIGNING_FAILED", "İmza üretilemedi.");
    }

    private static string UserMessage(Pkcs11SigningStatus status) => status switch
    {
        Pkcs11SigningStatus.PinIncorrect => "PIN hatalı.",
        Pkcs11SigningStatus.PinLocked => "PIN kilitli. Kartı veren kuruma başvurun.",
        Pkcs11SigningStatus.TokenRemoved => "Kart imza sırasında çıkarıldı.",
        Pkcs11SigningStatus.TokenNotFound => "Kart bulunamadı. Sürücüyü ve takılı kartı kontrol edin.",
        Pkcs11SigningStatus.MechanismUnsupported => "Kart bu imza mekanizmasını desteklemiyor.",
        Pkcs11SigningStatus.DriverError => "PKCS#11 sürücü hatası.",
        Pkcs11SigningStatus.CertificateNotFound => "Seçilen sertifika kartta bulunamadı.",
        Pkcs11SigningStatus.PrivateKeyNotFound => "Sertifikaya ait özel anahtar bulunamadı.",
        _ => "İmza üretilemedi."
    };
}
