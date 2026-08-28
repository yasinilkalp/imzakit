using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Verify.Validation;

namespace ImzaKit.Verify.Tests.Validation;

public sealed class PadesValidatorTests
{
    [Fact]
    public void ValidSignaturePassesIntegrityAndCryptoButTrustIsIndeterminate()
    {
        byte[] pdf = CreateSignedPdf();

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(ValidationStatus.Indeterminate, report.TrustStatus);
        Assert.Matches("^[0-9A-F]{64}$", report.SignerCertificateSha256!);
        Assert.Contains(report.Findings, finding => finding.Code == "TrustNotEvaluated");
        Assert.Equal(PadesBaselineLevel.BB, report.SignatureLevel);
    }

    [Fact]
    public void ChangedSignedByteFailsCryptographicValidation()
    {
        byte[] pdf = CreateSignedPdf();
        pdf[10] ^= 1;

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Failed, report.CryptographicStatus);
        Assert.Contains(report.Findings, finding => finding.Code == "CmsSignatureInvalid");
    }

    [Fact]
    public void MalformedByteRangeFailsWithoutThrowing()
    {
        byte[] pdf = CreateSignedPdf();
        int marker = Encoding.ASCII.GetString(pdf).LastIndexOf("/ByteRange [", StringComparison.Ordinal);
        pdf[marker + "/ByteRange [".Length] = (byte)'9';

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(ValidationStatus.Failed, report.ByteRangeStatus);
        Assert.Contains(report.Findings, finding => finding.Code == "InvalidByteRange");
    }

    [Fact]
    public void UnsignedPdfIsIndeterminate()
    {
        PadesValidationReport report = PadesValidator.Validate(CreateOnePagePdf());

        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Contains(report.Findings, finding => finding.Code == "SignatureNotFound");
    }

    [Fact]
    public void MissingCmsFailsWithDedicatedFinding()
    {
        byte[] pdf = CreateSignedPdf();
        int contents = Encoding.ASCII.GetString(pdf).LastIndexOf("/Contents <", StringComparison.Ordinal);
        pdf[contents + "/Contents <".Length] = (byte)'0';
        pdf[contents + "/Contents <".Length + 1] = (byte)'0';

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Contains(report.Findings, finding => finding.Code == "InvalidCms");
    }

    [Fact]
    public void UnsupportedInputFailsWithoutSearchingForSignatureMarkers()
    {
        PadesValidationReport report = PadesValidator.Validate("not a pdf"u8);

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Contains(report.Findings, finding => finding.Code == "UnsupportedPdf");
    }

    private static byte[] CreateSignedPdf()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new("CN=ImzaKit Verify Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId, "VERIFY-TEST", CreateOnePagePdf(), 4096, certificateDer, fingerprint, 1);
        byte[] signature = rsa.SignData(preparation.SignaturePreparation.DataToBeSigned.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return PadesSignatureCompleter.Complete(
            preparation, SignatureCompletion.Create(operationId, 1, fingerprint, signature), certificateDer);
    }

    private static byte[] CreateOnePagePdf()
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
