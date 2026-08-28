using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;
using ImzaKit.Verify.Validation;

namespace ImzaKit.Verify.Tests.Validation;

public sealed class PadesModificationPolicyTests
{
    [Fact]
    public void DocMdpNoChangesWithExtraPageFailsValidation()
    {
        byte[] signed = Sign(CreateOnePagePdf());
        byte[] pdf = Append(
            signed,
            "% /TransformMethod /DocMDP /TransformParams << /P 1 >>\n" +
            "9 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n");

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(ValidationStatus.Failed, report.ModificationPolicyStatus);
        Assert.Contains(report.Findings, finding => finding.Code == "DocMdpViolation");
    }

    [Fact]
    public async Task DocMdpNoChangesAllowsBaselineLtDssTail()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify DocMDP DSS");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        byte[] signed = await SignBaselineT(
            rsa,
            certificateDer,
            tsa,
            CreateOnePagePdf());
        byte[] pdf = Append(
            PadesSignatureCompleter.EmbedBaselineLt(
                signed,
                new PadesValidationMaterial([certificateDer, tsa.CertificateDer])),
            "% /TransformMethod /DocMDP /TransformParams << /P 1 >>\n");

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(ValidationStatus.Passed, report.ModificationPolicyStatus);
        Assert.DoesNotContain(report.Findings, finding => finding.Code == "DocMdpViolation");
        Assert.Equal(PadesBaselineLevel.BLT, report.SignatureLevel);
    }

    [Fact]
    public void FieldMdpIncludeReportsLockedFieldChange()
    {
        byte[] signed = Sign(CreateOnePagePdf(
            "/TransformMethod /FieldMDP /TransformParams << /Action /Include /Fields [(Amount)] >>"));
        byte[] pdf = Append(signed, "9 0 obj\n<< /FT /Tx /T (Amount) /V (100) >>\nendobj\n");

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(ValidationStatus.Failed, report.ModificationPolicyStatus);
        Assert.Contains(report.Findings, finding => finding.Code == "FieldMdpViolation");
    }

    [Fact]
    public void IncrementalUpdateWithoutPolicyDoesNotReportModificationViolation()
    {
        byte[] pdf = Append(Sign(CreateOnePagePdf()), "9 0 obj\n<< /Type /Page >>\nendobj\n");

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Equal(ValidationStatus.Passed, report.ModificationPolicyStatus);
        Assert.DoesNotContain(report.Findings, finding => finding.Code is "DocMdpViolation" or "FieldMdpViolation");
    }

    private static byte[] Sign(byte[] originalPdf)
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify MDP");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "VERIFY-MDP",
                originalPdf,
                cmsCapacity: 4096,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signature = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return PadesSignatureCompleter.Complete(
            preparation,
            SignatureCompletion.Create(operationId, 1, fingerprint, signature),
            certificateDer);
    }

    private static async Task<byte[]> SignBaselineT(
        RSA rsa,
        byte[] certificateDer,
        TestTsaResponder tsa,
        byte[] originalPdf)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "VERIFY-MDP-T",
                originalPdf,
                cmsCapacity: 8192,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signature = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));
        return await PadesSignatureCompleter.CompleteBaselineT(
            preparation,
            SignatureCompletion.Create(operationId, 1, fingerprint, signature),
            certificateDer,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);
    }

    private static byte[] CreateOnePagePdf(string? policy = null)
    {
        StringBuilder builder = new("%PDF-1.4\n");
        if (!string.IsNullOrEmpty(policy))
        {
            builder.Append('%').Append(' ').Append(policy).Append('\n');
        }

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

    private static byte[] Append(byte[] pdf, string tail)
    {
        byte[] extra = Encoding.ASCII.GetBytes(tail);
        byte[] combined = new byte[pdf.Length + extra.Length];
        pdf.CopyTo(combined, 0);
        extra.CopyTo(combined, pdf.Length);
        return combined;
    }

    private static X509Certificate2 CreateCertificate(RSA rsa, string subject)
    {
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private sealed class ScriptedFetcher(Func<Uri, byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ExternalResourceFetchResult(
                respond(request.Uri, request.Body),
                "application/timestamp-reply"));
    }
}
