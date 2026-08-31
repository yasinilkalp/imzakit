using ImzaKit.Agent.Native;
using ImzaKit.Hosts.Desktop.Pkcs11;
using ImzaKit.Hosts.Desktop.Session;
using ImzaKit.Hosts.Desktop.Signing;
using ImzaKit.Pkcs11.Abstractions;

namespace ImzaKit.Desktop.Tests.Session;

public sealed class SignSessionViewModelTests
{
    [Fact]
    public void RejectsNonPdfWithoutStartingSign()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        SignSessionViewModel viewModel = CreateViewModel(provider, "1234");

        viewModel.SelectPdf(Path.Combine(Path.GetTempPath(), "not-a-pdf.txt"));

        Assert.Equal(SignSessionState.Error, viewModel.State);
        Assert.Equal("NOT_PDF", viewModel.ErrorCode);
        Assert.False(viewModel.CanSign);
        Assert.Null(viewModel.FilePath);
    }

    [Fact]
    public void EmptyCatalogSetsTokenNotFound()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        SignSessionViewModel viewModel = new([], CreateSigner(provider, "1234"));

        viewModel.RefreshCertificates();

        Assert.Equal("TOKEN_NOT_FOUND", viewModel.ErrorCode);
        Assert.Empty(viewModel.Certificates);
    }

    [Fact]
    public void SignsPdfAndWritesImzaliOutput()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        SignSessionViewModel viewModel = CreateViewModel(provider, "1234");
        string original = WritePdf();

        viewModel.SelectPdf(original);
        viewModel.RefreshCertificates();
        viewModel.SelectedCertificate = viewModel.Certificates[0];
        viewModel.Sign();

        Assert.Equal(SignSessionState.Ready, viewModel.State);
        Assert.Equal(Path.Combine(Path.GetDirectoryName(original)!, Path.GetFileNameWithoutExtension(original) + "-imzali.pdf"), viewModel.OutputPath);
        Assert.True(File.Exists(viewModel.OutputPath));
        Assert.Equal(SignSessionViewModel.TrustStoreWarning, viewModel.TrustWarning);
        Assert.Null(viewModel.ErrorCode);
    }

    [Fact]
    public void CancelledPinKeepsFileAndCertificate()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        SignSessionViewModel viewModel = CreateViewModel(provider, pin: null);
        string original = WritePdf();
        viewModel.SelectPdf(original);
        viewModel.RefreshCertificates();
        viewModel.SelectedCertificate = viewModel.Certificates[0];

        viewModel.Sign();

        Assert.Equal(SignSessionState.CertificateSelected, viewModel.State);
        Assert.Equal("CANCELLED", viewModel.ErrorCode);
        Assert.Equal(original, viewModel.FilePath);
        Assert.NotNull(viewModel.SelectedCertificate);
        Assert.Null(viewModel.OutputPath);
    }

    [Fact]
    public void IncorrectPinDoesNotWriteOutput()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        SignSessionViewModel viewModel = CreateViewModel(provider, "0000");
        string original = WritePdf();
        viewModel.SelectPdf(original);
        viewModel.RefreshCertificates();
        viewModel.SelectedCertificate = viewModel.Certificates[0];

        viewModel.Sign();

        Assert.Equal(SignSessionState.Error, viewModel.State);
        Assert.Equal("PinIncorrect", viewModel.ErrorCode);
        Assert.Null(viewModel.OutputPath);
        Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(original)!, Path.GetFileNameWithoutExtension(original) + "-imzali.pdf")));
    }

    [Fact]
    public void SignIsNoOpWithoutCertificate()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        SignSessionViewModel viewModel = CreateViewModel(provider, "1234");
        viewModel.SelectPdf(WritePdf());

        viewModel.Sign();

        Assert.Equal(SignSessionState.FileSelected, viewModel.State);
        Assert.Null(viewModel.OutputPath);
    }

    [Fact]
    public void SaveSignedPdfWritesCallerPathWhenInitialWriteFails()
    {
        using InMemoryRsaPkcs11Provider provider = new();
        DesktopPadesSigner signer = CreateSigner(provider, "1234");
        SignSessionViewModel viewModel = new(
            [new NamedPkcs11Provider("test", provider)],
            signer);
        string original = WritePdf();
        viewModel.SelectPdf(original);
        viewModel.RefreshCertificates();
        viewModel.SelectedCertificate = viewModel.Certificates[0];
        File.SetAttributes(Path.GetDirectoryName(original)!, FileAttributes.ReadOnly);
        try
        {
            viewModel.Sign();
        }
        finally
        {
            File.SetAttributes(Path.GetDirectoryName(original)!, FileAttributes.Directory);
        }

        if (viewModel.State is SignSessionState.Ready)
        {
            return;
        }

        Assert.Equal("OUTPUT_UNWRITABLE", viewModel.ErrorCode);
        Assert.NotNull(viewModel.SignedPdf);
        string fallback = Path.Combine(Path.GetTempPath(), "imzakit-fallback-" + Guid.NewGuid().ToString("N") + ".pdf");
        viewModel.SaveSignedPdf(fallback);
        Assert.True(File.Exists(fallback));
        Assert.Equal(fallback, viewModel.OutputPath);
        Assert.Equal(SignSessionState.Ready, viewModel.State);
    }

    private static SignSessionViewModel CreateViewModel(InMemoryRsaPkcs11Provider provider, string? pin)
    {
        return new SignSessionViewModel(
            [new NamedPkcs11Provider("test", provider)],
            CreateSigner(provider, pin));
    }

    private static DesktopPadesSigner CreateSigner(IPkcs11Provider provider, string? pin)
    {
        _ = provider;
        NativePinSession? session = pin is null ? null : new NativePinSession(pin);
        return new DesktopPadesSigner(new FixedPinPrompt(session));
    }

    private static string WritePdf()
    {
        string directory = Path.Combine(Path.GetTempPath(), "imzakit-vm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "belge.pdf");
        File.WriteAllBytes(path, InMemoryRsaPkcs11Provider.CreateOnePagePdf());
        return path;
    }

    private sealed class FixedPinPrompt(NativePinSession? session) : INativePinPrompt
    {
        public NativePinSession? Acquire() => session;
    }
}
