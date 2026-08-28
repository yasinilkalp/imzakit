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

public sealed class PadesRevisionReportTests
{
    [Fact]
    public void SingleSignatureReportsCoveredRevisionWithoutSubsequentBytes()
    {
        byte[] pdf = Sign(CreateOnePagePdf());

        PadesValidationReport report = PadesValidator.Validate(pdf);

        PadesSignatureRevisionReport signature = Assert.Single(report.Signatures);
        Assert.Equal(1, signature.Index);
        Assert.Equal("Signature1", signature.FieldName);
        Assert.Equal(2, signature.CoveredRevision);
        Assert.Equal(pdf.Length, signature.CoveredLength);
        Assert.Equal(0, signature.SubsequentByteCount);
        Assert.Equal(ValidationStatus.Passed, signature.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, signature.CryptographicStatus);
        Assert.Equal(ValidationStatus.Passed, signature.ModificationPolicyStatus);
    }

    [Fact]
    public void EachSignatureReportsOwnRevisionAndSubsequentChanges()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify Revision");
        byte[] first = Sign(CreateOnePagePdf(), rsa, certificate);
        byte[] pdf = Sign(first, rsa, certificate);

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(2, report.Signatures.Count);
        PadesSignatureRevisionReport earlier = report.Signatures[0];
        PadesSignatureRevisionReport later = report.Signatures[1];
        Assert.Equal("Signature1", earlier.FieldName);
        Assert.Equal("Signature2", later.FieldName);
        Assert.Equal(1, earlier.Index);
        Assert.Equal(2, later.Index);
        Assert.True(earlier.CoveredLength < later.CoveredLength);
        Assert.True(earlier.CoveredRevision < later.CoveredRevision);
        Assert.True(earlier.SubsequentByteCount > 0);
        Assert.Equal(0, later.SubsequentByteCount);
        Assert.Equal(ValidationStatus.Passed, earlier.CryptographicStatus);
        Assert.Equal(ValidationStatus.Passed, later.CryptographicStatus);
        Assert.Equal(pdf.Length, later.CoveredLength);
        Assert.Equal(pdf.Length - earlier.CoveredLength, earlier.SubsequentByteCount);
    }

    [Fact]
    public void LaterRevisionTamperFailsOnlyTheSignatureThatCoveredIt()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify Tail Tamper");
        byte[] first = Sign(CreateOnePagePdf(), rsa, certificate);
        byte[] pdf = Sign(first, rsa, certificate);
        pdf[first.Length + 8] ^= 1;

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Passed, report.Signatures[0].CryptographicStatus);
        Assert.Equal(ValidationStatus.Failed, report.Signatures[1].CryptographicStatus);
        Assert.True(report.Signatures[0].SubsequentByteCount > 0);
        Assert.Equal(ValidationStatus.Failed, report.CryptographicStatus);
        Assert.Equal(ValidationStatus.Failed, report.Status);
    }

    private static byte[] Sign(byte[] pdf)
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify Single");
        return Sign(pdf, rsa, certificate);
    }

    private static byte[] Sign(byte[] pdf, RSA rsa, X509Certificate2 certificate)
    {
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId, "VERIFY-REVISION", pdf, 4096, certificateDer, fingerprint, 1);
        byte[] signature = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return PadesSignatureCompleter.Complete(
            preparation, SignatureCompletion.Create(operationId, 1, fingerprint, signature), certificateDer);
    }

    private static X509Certificate2 CreateCertificate(RSA rsa, string subject)
    {
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
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
