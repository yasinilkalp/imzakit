using ImzaKit.Agent.Native;
using ImzaKit.Hosts.Desktop.Pkcs11;
using ImzaKit.Hosts.Desktop.Signing;
using ImzaKit.Verify.Validation;

namespace ImzaKit.Desktop.Tests.Signing;

public sealed class DesktopPadesSignerTests
{
    [Fact]
    public void CancelledWhenPinPromptReturnsNull()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        DesktopPadesSigner signer = new(new FixedPinPrompt(null));
        DesktopCertificateItem certificate = Item(provider);

        DesktopSignOutcome outcome = signer.Sign(InMemoryRsaPkcs11Provider.CreateOnePagePdf(), certificate, provider);

        Assert.Equal(DesktopSignStatus.Cancelled, outcome.Status);
        Assert.Equal("CANCELLED", outcome.Code);
        Assert.Null(outcome.SignedPdf);
    }

    [Fact]
    public void MapsIncorrectPin()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        DesktopPadesSigner signer = new(new FixedPinPrompt(new NativePinSession("0000")));
        DesktopCertificateItem certificate = Item(provider);

        DesktopSignOutcome outcome = signer.Sign(InMemoryRsaPkcs11Provider.CreateOnePagePdf(), certificate, provider);

        Assert.Equal(DesktopSignStatus.Failed, outcome.Status);
        Assert.Equal("PinIncorrect", outcome.Code);
        Assert.Null(outcome.SignedPdf);
    }

    [Fact]
    public void ProducesPadesWithPassedCryptographicStatus()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        DesktopPadesSigner signer = new(new FixedPinPrompt(new NativePinSession("1234")));
        byte[] original = InMemoryRsaPkcs11Provider.CreateOnePagePdf();

        DesktopSignOutcome outcome = signer.Sign(original, Item(provider), provider);

        Assert.Equal(DesktopSignStatus.Succeeded, outcome.Status);
        Assert.NotNull(outcome.SignedPdf);
        Assert.True(outcome.SignedPdf.AsSpan(0, original.Length).SequenceEqual(original));
        Assert.Equal(ValidationStatus.Passed, outcome.Validation!.CryptographicStatus);
        Assert.Equal(ValidationStatus.Passed, outcome.Validation.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Indeterminate, outcome.Validation.TrustStatus);
    }

    private static DesktopCertificateItem Item(InMemoryRsaPkcs11Provider provider) =>
        new("test", provider.Token.SlotId, provider.Certificate, "CN=ImzaKit Desktop Test");

    private sealed class FixedPinPrompt(NativePinSession? session) : INativePinPrompt
    {
        public NativePinSession? Acquire() => session;
    }
}
