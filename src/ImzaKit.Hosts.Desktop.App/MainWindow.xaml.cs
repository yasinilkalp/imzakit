using System.Diagnostics;
using ImzaKit.Hosts.Desktop.Pkcs11;
using ImzaKit.Hosts.Desktop.Session;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace ImzaKit.Hosts.Desktop.App;

public sealed partial class MainWindow : Window
{
    private readonly SignSessionViewModel _session;

    public MainWindow(SignSessionViewModel session)
    {
        _session = session;
        InitializeComponent();
        DownloadLink.Visibility = Visibility.Collapsed;
        ShowFolderButton.Visibility = Visibility.Collapsed;
        _session.RefreshCertificates();
        Bind();
    }

    private async void PickPdfButton_Click(object sender, RoutedEventArgs e)
    {
        FileOpenPicker picker = new()
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary
        };
        picker.FileTypeFilter.Add(".pdf");
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
        Windows.Storage.StorageFile? file = await picker.PickSingleFileAsync();
        if (file is null)
        {
            return;
        }

        _session.SelectPdf(file.Path);
        Bind();
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        _session.RefreshCertificates();
        Bind();
    }

    private void CertificateList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _session.SelectedCertificate = CertificateList.SelectedItem as DesktopCertificateItem;
        Bind();
    }

    private void SignButton_Click(object sender, RoutedEventArgs e)
    {
        SignButton.IsEnabled = false;
        try
        {
            _session.Sign();
        }
        finally
        {
            Bind();
        }
    }

    private void DownloadLink_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_session.OutputPath) && _session.SignedPdf is not null)
        {
            SaveFallback();
            return;
        }

        if (!string.IsNullOrWhiteSpace(_session.OutputPath))
        {
            Process.Start(new ProcessStartInfo(_session.OutputPath) { UseShellExecute = true });
        }
    }

    private async void SaveFallback()
    {
        FileSavePicker picker = new();
        picker.FileTypeChoices.Add("PDF", [".pdf"]);
        picker.SuggestedFileName = "imzali";
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
        Windows.Storage.StorageFile? file = await picker.PickSaveFileAsync();
        if (file is null)
        {
            return;
        }

        _session.SaveSignedPdf(file.Path);
        Bind();
    }

    private void ShowFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_session.OutputPath))
        {
            return;
        }

        Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + _session.OutputPath + "\"")
        {
            UseShellExecute = true
        });
    }

    private void Bind()
    {
        FilePathText.Text = _session.FilePath ?? "PDF seçilmedi.";
        HashText.Text = _session.DocumentSha256 is null ? string.Empty : "SHA-256: " + _session.DocumentSha256;
        CertificateList.ItemsSource = _session.Certificates;
        if (_session.SelectedCertificate is not null)
        {
            CertificateList.SelectedItem = _session.SelectedCertificate;
        }

        ErrorText.Text = _session.ErrorMessage ?? string.Empty;
        TrustText.Text = _session.TrustWarning ?? string.Empty;
        SignButton.IsEnabled = _session.CanSign;
        bool hasOutput = !string.IsNullOrWhiteSpace(_session.OutputPath) || _session.SignedPdf is not null;
        DownloadLink.Visibility = hasOutput ? Visibility.Visible : Visibility.Collapsed;
        ShowFolderButton.Visibility = string.IsNullOrWhiteSpace(_session.OutputPath)
            ? Visibility.Collapsed
            : Visibility.Visible;
        if (!string.IsNullOrWhiteSpace(_session.OutputPath))
        {
            DownloadLink.Content = "İmzalı PDF’i indir";
        }
        else if (_session.SignedPdf is not null)
        {
            DownloadLink.Content = "İmzalı PDF’i kaydet";
        }
    }
}
