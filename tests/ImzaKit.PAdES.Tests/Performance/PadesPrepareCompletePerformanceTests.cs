using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Preparation;

namespace ImzaKit.PAdES.Tests.Performance;

public sealed class PadesPrepareCompletePerformanceTests
{
    private const int TargetPdfBytes = 10 * 1024 * 1024;
    private const int WarmupIterations = 2;
    private const int MeasuredIterations = 20;
    private const double SlaMilliseconds = 2000;

    [Fact]
    public void TenMegabytePrepareAndCompleteP95IsUnderTwoSeconds()
    {
        byte[] pdf = CreateTypicalTenMegabytePdf();
        Assert.True(pdf.Length >= TargetPdfBytes, $"Typical PDF must be at least 10 MB, was {pdf.Length}.");

        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa);
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        string documentSha256 = Convert.ToHexString(SHA256.HashData(pdf));
        PadesSignaturePreparer preparer = new(new CmsSignaturePreparer(new DefaultDigestCalculator()));

        for (int warmup = 0; warmup < WarmupIterations; warmup++)
        {
            SignOnce(preparer, rsa, pdf, certificateDer, fingerprint, documentSha256);
        }

        double[] samples = new double[MeasuredIterations];
        byte[] lastSigned = [];
        for (int index = 0; index < MeasuredIterations; index++)
        {
            long start = Stopwatch.GetTimestamp();
            lastSigned = SignOnce(preparer, rsa, pdf, certificateDer, fingerprint, documentSha256);
            samples[index] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        }

        Array.Sort(samples);
        double p95 = Percentile(samples, 0.95);

        Assert.True(
            lastSigned.Length > pdf.Length,
            "Complete must append an incremental signature revision.");
        Assert.True(
            p95 < SlaMilliseconds,
            string.Create(
                CultureInfo.InvariantCulture,
                $"NFR-001 p95 was {p95:F1} ms for a {pdf.Length} byte PDF; SLA is {SlaMilliseconds} ms."));
    }

    private static byte[] SignOnce(
        PadesSignaturePreparer preparer,
        RSA rsa,
        byte[] pdf,
        byte[] certificateDer,
        string fingerprint,
        string documentSha256)
    {
        PadesSignaturePreparation preparation = preparer.Prepare(
            Guid.NewGuid(),
            documentSha256,
            pdf,
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
            SignatureCompletion.Create(
                preparation.SignaturePreparation.OperationId,
                preparation.SignaturePreparation.PrepareVersion,
                fingerprint,
                signature),
            certificateDer);
    }

    private static byte[] CreateTypicalTenMegabytePdf()
    {
        using MemoryStream stream = new(TargetPdfBytes + 2048);
        stream.Write("%PDF-1.4\n%"u8);
        byte[] payload = new byte[TargetPdfBytes];
        payload.AsSpan().Fill((byte)'x');
        stream.Write(payload);
        stream.Write("\n"u8);
        int catalog = (int)stream.Position;
        stream.Write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"u8);
        int pages = (int)stream.Position;
        stream.Write("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"u8);
        int page = (int)stream.Position;
        stream.Write("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"u8);
        int xref = (int)stream.Position;
        stream.Write("xref\n0 4\n0000000000 65535 f \n"u8);
        stream.Write(Encoding.ASCII.GetBytes(catalog.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n"));
        stream.Write(Encoding.ASCII.GetBytes(pages.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n"));
        stream.Write(Encoding.ASCII.GetBytes(page.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n"));
        stream.Write("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n"u8);
        stream.Write(Encoding.ASCII.GetBytes(xref.ToString(CultureInfo.InvariantCulture)));
        stream.Write("\n%%EOF\n"u8);
        return stream.ToArray();
    }

    private static X509Certificate2 CreateCertificate(RSA rsa)
    {
        CertificateRequest request = new("CN=ImzaKit NFR-001", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static double Percentile(double[] sortedAscending, double percentile)
    {
        double position = percentile * (sortedAscending.Length - 1);
        int lower = (int)Math.Floor(position);
        int upper = (int)Math.Ceiling(position);
        if (lower == upper)
        {
            return sortedAscending[lower];
        }

        return sortedAscending[lower]
            + ((sortedAscending[upper] - sortedAscending[lower]) * (position - lower));
    }
}
