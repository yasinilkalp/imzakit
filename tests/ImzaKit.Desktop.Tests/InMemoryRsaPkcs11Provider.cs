using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Desktop.Tests;

internal sealed class InMemoryRsaPkcs11Provider : IPkcs11Provider, IDisposable
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly X509Certificate2 _certificate;
    public Pkcs11Token Token { get; } = new(1, "Test Token", "ImzaKit", "InMemory", "****0001");
    public Pkcs11Certificate Certificate { get; }
    public string RequiredPin { get; init; } = "1234";

    public InMemoryRsaPkcs11Provider()
    {
        CertificateRequest request = new("CN=ImzaKit Desktop Test", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        Certificate = new([1, 2, 3], "Test NES", _certificate.Export(X509ContentType.Cert));
    }

    public void Initialize() { }
    public IReadOnlyList<Pkcs11Token> DiscoverTokens() => [Token];
    public ulong OpenSession(ulong slotId) => 1;
    public void Login(ulong session, ReadOnlySpan<char> pin)
    {
        if (!pin.SequenceEqual(RequiredPin))
        {
            throw new Pkcs11ProviderException(Pkcs11ErrorCode.PinIncorrect);
        }
    }
    public IReadOnlyList<Pkcs11Certificate> FindCertificates(ulong session) => [Certificate];
    public ulong? FindPrivateKey(ulong session, ReadOnlySpan<byte> ckaId) =>
        ckaId.SequenceEqual(Certificate.CkaId) ? 1UL : null;
    public byte[] SignRsaPkcs1Sha256(ulong session, ulong keyHandle, ReadOnlySpan<byte> data) =>
        _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    public void Logout(ulong session) { }
    public void CloseSession(ulong session) { }
    public void FinalizeProvider() { }
    public void Dispose()
    {
        _certificate.Dispose();
        _rsa.Dispose();
    }

    public static byte[] CreateOnePagePdf()
    {
        StringBuilder builder = new("%PDF-1.4\n");
        int catalogOffset = builder.Length;
        builder.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        int pagesOffset = builder.Length;
        builder.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        int pageOffset = builder.Length;
        builder.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        int xrefOffset = builder.Length;
        builder.Append("xref\n0 4\n0000000000 65535 f \n")
            .Append(catalogOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pagesOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pageOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n")
            .Append(xrefOffset.ToString(CultureInfo.InvariantCulture)).Append("\n%%EOF\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }
}
