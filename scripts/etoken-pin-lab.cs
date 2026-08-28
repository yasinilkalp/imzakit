#:project ../src/ImzaKit.Pkcs11/ImzaKit.Pkcs11.csproj
#:project ../src/ImzaKit.Agent/ImzaKit.Agent.csproj
#:project ../src/ImzaKit.PAdES/ImzaKit.PAdES.csproj
#:project ../src/ImzaKit.Verify/ImzaKit.Verify.csproj
#:project ../src/ImzaKit.Cms/ImzaKit.Cms.csproj
#:project ../src/ImzaKit.Cryptography/ImzaKit.Cryptography.csproj

using System.Security.Cryptography;
using System.Text;
using ImzaKit.Agent.Native;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Pkcs11.Etoken;
using ImzaKit.Pkcs11.Models;
using ImzaKit.Pkcs11.Native;
using ImzaKit.Verify.Validation;

if (args.Contains("--compile-check", StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine("ETOKEN_PIN_LAB_COMPILE_OK");
    return 0;
}

if (!OperatingSystem.IsWindows())
{
    Console.WriteLine("ETOKEN_PIN_LAB_FAILED: Windows is required for CredUI.");
    return 1;
}

string? modulePath = Environment.GetEnvironmentVariable("IMZAKIT_ETOKEN_MODULE");
if (string.IsNullOrWhiteSpace(modulePath) || !File.Exists(modulePath))
{
    Console.WriteLine("ETOKEN_PIN_LAB_FAILED: set IMZAKIT_ETOKEN_MODULE to eTPKCS11.dll.");
    return 2;
}

string fullPath = Path.GetFullPath(modulePath);
string allowlistRoot = Path.GetDirectoryName(fullPath)
    ?? throw new InvalidOperationException("PKCS#11 module path has no directory.");

Console.WriteLine("A Windows PIN dialog will open. Enter the eToken PIN. PIN is not written to the console, argv, or git.");
if (!TryReadPinSta(
        "ImzaKit eToken PIN",
        "Kullanici adi: imza (gercek bir hesap degil).\r\nSifre: eToken PIN.\r\nPIN tarayiciya veya API'ye gitmez.",
        out char[] pinChars))
{
    Console.WriteLine("ETOKEN_PIN_LAB_CANCELLED: PIN dialog was cancelled.");
    return 3;
}

using NativePinSession pin = new(pinChars);
Array.Clear(pinChars);

IPkcs11NativeApi native = Pkcs11NativeLibraryLoader.Load(
    fullPath,
    [allowlistRoot],
    EtokenProviderProfile.SupportedLibraryFileNames);
using NativePkcs11Provider provider = new(native, NativePkcs11ProviderOptions.ForEtoken());
provider.Initialize();
IReadOnlyList<Pkcs11Token> tokens = provider.DiscoverTokens();
if (tokens.Count == 0)
{
    Console.WriteLine("ETOKEN_PIN_LAB_FAILED: no readable token.");
    return 1;
}

Pkcs11Token token = tokens[0];
Console.WriteLine($"TokenLabel={token.Label}");
Console.WriteLine($"TokenModel={token.Model}");
Console.WriteLine($"MaskedSerial={token.MaskedSerialNumber}");

ulong session = provider.OpenSession(token.SlotId);
bool loggedIn = false;
try
{
    try
    {
        pin.Use(value => provider.Login(session, value));
        loggedIn = true;
    }
    catch (Pkcs11ProviderException exception) when (exception.Code == Pkcs11ErrorCode.PinIncorrect)
    {
        Console.WriteLine("CKA_ID_MATCH=fail PinIncorrect on login.");
        Console.WriteLine("NEGATIVE_PIN=PinIncorrect");
        return 1;
    }

    IReadOnlyList<Pkcs11Certificate> certificates = provider.FindCertificates(session);
    if (certificates.Count == 0)
    {
        Console.WriteLine("ETOKEN_PIN_LAB_FAILED: no signable X.509 certificate after login.");
        return 1;
    }

    Pkcs11Certificate certificate = certificates[0];
    ulong? keyHandle = provider.FindPrivateKey(session, certificate.CkaId);
    Console.WriteLine($"CertificateLabel={certificate.Label}");
    Console.WriteLine($"CkaIdBytes={certificate.CkaId.Length}");
    Console.WriteLine($"CertificateDerBytes={certificate.DerEncoded.Length}");
    Console.WriteLine(keyHandle is null ? "CKA_ID_MATCH=fail" : "CKA_ID_MATCH=ok");
    if (keyHandle is null)
    {
        return 1;
    }

    byte[] originalPdf = CreateMinimalPdf();
    string documentSha256 = Convert.ToHexString(SHA256.HashData(originalPdf));
    string fingerprint = Convert.ToHexString(SHA256.HashData(certificate.DerEncoded));
    PadesSignaturePreparation preparation = new PadesSignaturePreparer(new CmsSignaturePreparer(new DefaultDigestCalculator()))
        .Prepare(Guid.NewGuid(), documentSha256, originalPdf, 32768, certificate.DerEncoded, fingerprint, 1);

    byte[] signature = provider.SignRsaPkcs1Sha256(
        session,
        keyHandle.Value,
        preparation.SignaturePreparation.DataToBeSigned.Span);
    SignatureCompletion completion = SignatureCompletion.Create(
        preparation.SignaturePreparation.OperationId,
        preparation.SignaturePreparation.PrepareVersion,
        fingerprint,
        signature);
    byte[] signedPdf = PadesSignatureCompleter.Complete(preparation, completion, certificate.DerEncoded);
    PadesValidationReport report = PadesValidator.Validate(signedPdf);
    string pdfHash = Convert.ToHexString(SHA256.HashData(signedPdf));

    Console.WriteLine("SIGN=ok CKM_SHA256_RSA_PKCS");
    Console.WriteLine($"PadesStatus={report.Status}");
    Console.WriteLine($"PadesCrypto={report.CryptographicStatus}");
    Console.WriteLine($"PadesTrust={report.TrustStatus}");
    Console.WriteLine($"SignedPdfSha256={pdfHash}");
    Console.WriteLine("Signed PDF was not written to the repository.");
}
finally
{
    if (loggedIn)
    {
        try { provider.Logout(session); } catch (Pkcs11ProviderException) { }
    }

    try { provider.CloseSession(session); } catch (Pkcs11ProviderException) { }
}

Console.WriteLine("Optional negative test: a second dialog asks for an INCORRECT PIN. Cancel to skip.");
if (TryReadPinSta(
        "ImzaKit eToken wrong PIN",
        "Kullanici adi: imza.\r\nSifre: BILEREK YANLIS PIN. Iptal = bu testi atla.",
        out char[] wrongPinChars))
{
    ulong negativeSession = provider.OpenSession(token.SlotId);
    try
    {
        provider.Login(negativeSession, wrongPinChars);
        Console.WriteLine("NEGATIVE_PIN=unexpected-success");
    }
    catch (Pkcs11ProviderException exception) when (exception.Code == Pkcs11ErrorCode.PinIncorrect)
    {
        Console.WriteLine("NEGATIVE_PIN=PinIncorrect");
    }
    catch (Pkcs11ProviderException exception)
    {
        Console.WriteLine($"NEGATIVE_PIN={exception.Code}");
    }
    finally
    {
        Array.Clear(wrongPinChars);
        try { provider.CloseSession(negativeSession); } catch (Pkcs11ProviderException) { }
    }
}
else
{
    Console.WriteLine("NEGATIVE_PIN=skipped");
}

return 0;

static bool TryReadPinSta(string caption, string message, out char[] pin)
{
    char[] captured = [];
    bool ok = false;
    Thread thread = new(() =>
    {
        ok = new CredUiSecurePinDialog().TryReadPin(new PinDialogRequest(caption, message), out captured);
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
    pin = captured;
    return ok;
}

static byte[] CreateMinimalPdf() => Encoding.ASCII.GetBytes(
    "%PDF-1.4\n" +
    "1 0 obj\n<< /Type /Catalog >>\nendobj\n" +
    "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n" +
    "trailer\n<< /Size 2 /Root 1 0 R >>\n" +
    "startxref\n45\n%%EOF\n");
