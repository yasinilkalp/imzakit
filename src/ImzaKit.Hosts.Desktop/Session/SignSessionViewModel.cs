using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using ImzaKit.Hosts.Desktop.Pkcs11;
using ImzaKit.Hosts.Desktop.Signing;
using ImzaKit.PAdES.Preflight;
using ImzaKit.Verify.Validation;

namespace ImzaKit.Hosts.Desktop.Session;

public enum SignSessionState
{
    Empty,
    FileSelected,
    CertificateSelected,
    Signing,
    Ready,
    Error
}

public sealed class SignSessionViewModel : INotifyPropertyChanged
{
    public const string TrustStoreWarning =
        "İmza belgede; kurumsal güven deposu bu uygulamada yok.";

    private readonly IReadOnlyList<NamedPkcs11Provider> _providers;
    private readonly DesktopPadesSigner _signer;
    private SignSessionState _state = SignSessionState.Empty;
    private string? _filePath;
    private string? _documentSha256;
    private DesktopCertificateItem? _selectedCertificate;
    private string? _errorCode;
    private string? _errorMessage;
    private string? _outputPath;
    private string? _trustWarning;
    private byte[]? _signedPdf;

    public SignSessionViewModel(
        IReadOnlyList<NamedPkcs11Provider> providers,
        DesktopPadesSigner signer)
    {
        _providers = providers ?? throw new ArgumentNullException(nameof(providers));
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public SignSessionState State
    {
        get => _state;
        private set => SetField(ref _state, value);
    }

    public string? FilePath
    {
        get => _filePath;
        private set => SetField(ref _filePath, value);
    }

    public string? DocumentSha256
    {
        get => _documentSha256;
        private set => SetField(ref _documentSha256, value);
    }

    public ObservableCollection<DesktopCertificateItem> Certificates { get; } = [];

    public DesktopCertificateItem? SelectedCertificate
    {
        get => _selectedCertificate;
        set
        {
            if (SetField(ref _selectedCertificate, value) && value is not null && FilePath is not null)
            {
                ClearError();
                State = SignSessionState.CertificateSelected;
            }

            OnPropertyChanged(nameof(CanSign));
        }
    }

    public string? ErrorCode
    {
        get => _errorCode;
        private set => SetField(ref _errorCode, value);
    }

    public string? ErrorMessage
    {
        get => _errorMessage;
        private set => SetField(ref _errorMessage, value);
    }

    public string? OutputPath
    {
        get => _outputPath;
        private set => SetField(ref _outputPath, value);
    }

    public string? TrustWarning
    {
        get => _trustWarning;
        private set => SetField(ref _trustWarning, value);
    }

    public byte[]? SignedPdf => _signedPdf;

    public bool CanSign =>
        State is not SignSessionState.Signing
        && FilePath is not null
        && SelectedCertificate is not null;

    public void SelectPdf(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (State is SignSessionState.Signing)
        {
            return;
        }

        if (!string.Equals(Path.GetExtension(path), ".pdf", StringComparison.OrdinalIgnoreCase))
        {
            SetFileError("NOT_PDF", "Yalnız PDF dosyaları imzalanabilir.");
            return;
        }

        byte[] pdf;
        try
        {
            pdf = File.ReadAllBytes(path);
        }
        catch (IOException)
        {
            SetFileError("PDF_UNREADABLE", "PDF okunamadı.");
            return;
        }

        try
        {
            PdfSigningPreflight.Validate(pdf, PdfPreflightLimits.Default);
        }
        catch (PdfPreflightException exception)
        {
            SetFileError(exception.Code.ToString(), exception.Message);
            return;
        }

        FilePath = path;
        DocumentSha256 = Convert.ToHexString(SHA256.HashData(pdf));
        OutputPath = null;
        TrustWarning = null;
        _signedPdf = null;
        ClearError();
        State = SelectedCertificate is null ? SignSessionState.FileSelected : SignSessionState.CertificateSelected;
        OnPropertyChanged(nameof(CanSign));
        OnPropertyChanged(nameof(SignedPdf));
    }

    public void RefreshCertificates()
    {
        if (State is SignSessionState.Signing)
        {
            return;
        }

        Certificates.Clear();
        IReadOnlyList<DesktopCertificateItem> listed = TokenCertificateCatalog.List(_providers);
        foreach (DesktopCertificateItem item in listed)
        {
            Certificates.Add(item);
        }

        if (Certificates.Count == 0)
        {
            SelectedCertificate = null;
            ErrorCode = "TOKEN_NOT_FOUND";
            ErrorMessage = "Kart sürücüsünü ve takılı kartı kontrol edin.";
            OnPropertyChanged(nameof(CanSign));
            return;
        }

        if (SelectedCertificate is not null
            && Certificates.All(item => !SameCertificate(item, SelectedCertificate)))
        {
            SelectedCertificate = null;
        }

        if (ErrorCode is "TOKEN_NOT_FOUND")
        {
            ClearError();
        }

        OnPropertyChanged(nameof(CanSign));
    }

    public void Sign()
    {
        if (!CanSign || FilePath is null || SelectedCertificate is null)
        {
            return;
        }

        State = SignSessionState.Signing;
        OnPropertyChanged(nameof(CanSign));
        OutputPath = null;
        TrustWarning = null;
        _signedPdf = null;
        OnPropertyChanged(nameof(SignedPdf));

        byte[] pdf = File.ReadAllBytes(FilePath);
        NamedPkcs11Provider? named = _providers.FirstOrDefault(provider =>
            string.Equals(provider.Name, SelectedCertificate.ProviderName, StringComparison.Ordinal));
        if (named is null)
        {
            ErrorCode = "PROVIDER_NOT_FOUND";
            ErrorMessage = "Kart sürücüsünü ve takılı kartı kontrol edin.";
            State = SignSessionState.Error;
            OnPropertyChanged(nameof(CanSign));
            return;
        }

        DesktopSignOutcome outcome = _signer.Sign(pdf, SelectedCertificate, named.Provider);
        switch (outcome.Status)
        {
            case DesktopSignStatus.Cancelled:
                ErrorCode = outcome.Code;
                ErrorMessage = outcome.Message;
                State = SignSessionState.CertificateSelected;
                OnPropertyChanged(nameof(CanSign));
                return;
            case DesktopSignStatus.Failed:
                ErrorCode = outcome.Code;
                ErrorMessage = outcome.Message;
                State = SignSessionState.Error;
                OnPropertyChanged(nameof(CanSign));
                return;
        }

        if (outcome.SignedPdf is null)
        {
            ErrorCode = "SIGNING_FAILED";
            ErrorMessage = "İmza üretilemedi.";
            State = SignSessionState.Error;
            OnPropertyChanged(nameof(CanSign));
            return;
        }

        _signedPdf = outcome.SignedPdf;
        OnPropertyChanged(nameof(SignedPdf));
        try
        {
            OutputPath = SignedPdfOutput.Write(FilePath, outcome.SignedPdf);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            ErrorCode = "OUTPUT_UNWRITABLE";
            ErrorMessage = "İmzalı PDF yazılamadı. Farklı konum seçin.";
            State = SignSessionState.Error;
            OnPropertyChanged(nameof(CanSign));
            return;
        }

        ClearError();
        TrustWarning = outcome.Validation?.TrustStatus is ValidationStatus.Indeterminate
            ? TrustStoreWarning
            : null;
        State = SignSessionState.Ready;
        OnPropertyChanged(nameof(CanSign));
    }

    public void SaveSignedPdf(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (_signedPdf is null)
        {
            throw new InvalidOperationException("Signed PDF is not available.");
        }

        File.WriteAllBytes(path, _signedPdf);
        OutputPath = path;
        ClearError();
        State = SignSessionState.Ready;
        OnPropertyChanged(nameof(CanSign));
    }

    private void SetFileError(string code, string message)
    {
        FilePath = null;
        DocumentSha256 = null;
        OutputPath = null;
        TrustWarning = null;
        _signedPdf = null;
        ErrorCode = code;
        ErrorMessage = message;
        State = SignSessionState.Error;
        OnPropertyChanged(nameof(CanSign));
        OnPropertyChanged(nameof(SignedPdf));
    }

    private void ClearError()
    {
        ErrorCode = null;
        ErrorMessage = null;
    }

    private static bool SameCertificate(DesktopCertificateItem left, DesktopCertificateItem right) =>
        left.SlotId == right.SlotId
        && left.ProviderName == right.ProviderName
        && left.Certificate.CkaId.AsSpan().SequenceEqual(right.Certificate.CkaId);

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
