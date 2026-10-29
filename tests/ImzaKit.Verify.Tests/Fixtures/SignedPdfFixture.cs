using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Certificate.Models;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Revocation.Models;
using ImzaKit.Testing.Certificates;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;
using ImzaKit.Trust.Models;
using ImzaKit.Verify.Validation;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ImzaKit.Verify.Tests.Fixtures;

internal sealed class SignedPdfFixture : IDisposable
{
    private SignedPdfFixture(TestCertificateAuthority pki, byte[] pdf)
    {
        Pki = pki;
        Pdf = pdf;
    }

    internal TestCertificateAuthority Pki { get; }

    internal byte[] Pdf { get; }

    internal static SignedPdfFixture Create(bool nonRepudiationOnlySigner = false)
    {
        TestCertificateAuthority pki = nonRepudiationOnlySigner
            ? TestCertificateAuthority.Create(leafHasDigitalSignature: false, leafHasNonRepudiation: true)
            : TestCertificateAuthority.Create();
        return new(pki, Sign(CreateOnePagePdf(), pki.Leaf));
    }

    internal static byte[] Sign(byte[] pdf, X509Certificate2 signer)
    {
        (PadesSignaturePreparation preparation, SignatureCompletion completion, byte[] certificateDer) =
            Prepare(pdf, signer, cmsCapacity: 4096);
        return PadesSignatureCompleter.Complete(preparation, completion, certificateDer);
    }

    // Signs with the fixture's leaf and adds a signature time-stamp from the given TSA (PAdES B-T).
    internal Task<byte[]> SignBaselineTAsync(TestTsaResponder tsa)
    {
        (PadesSignaturePreparation preparation, SignatureCompletion completion, byte[] certificateDer) =
            Prepare(CreateOnePagePdf(), Pki.Leaf, cmsCapacity: 8192);
        return PadesSignatureCompleter.CompleteBaselineT(
            preparation,
            completion,
            certificateDer,
            new Rfc3161TimeStampClient(new TsaFetcher(tsa)),
            [new TimeStampAuthority("signature", new Uri("https://tsa.example/rfc3161"))]);
    }

    // Adds a DSS and a document time-stamp from the given TSA (PAdES B-LTA).
    internal Task<byte[]> ArchiveAsync(byte[] signedPdf, TestTsaResponder tsa) =>
        PadesSignatureCompleter.CompleteBaselineLta(
            PadesSignatureCompleter.EmbedBaselineLt(
                signedPdf,
                new PadesValidationMaterial([Pki.Leaf.Export(X509ContentType.Cert), Pki.Intermediate.Export(X509ContentType.Cert)])),
            new Rfc3161TimeStampClient(new TsaFetcher(tsa)),
            [new TimeStampAuthority("archive", new Uri("https://tsa.example/rfc3161"))]);

    private static (PadesSignaturePreparation, SignatureCompletion, byte[]) Prepare(
        byte[] pdf,
        X509Certificate2 signer,
        int cmsCapacity)
    {
        byte[] certificateDer = signer.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new ImzaKit.Cryptography.Digests.DefaultDigestCalculator())).Prepare(
                operationId,
                "OFFLINE-TRUST-TEST",
                pdf,
                cmsCapacity,
                certificateDer,
                fingerprint,
                1);
        using RSA signerKey = signer.GetRSAPrivateKey()!;
        byte[] signature = signerKey.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return (preparation, SignatureCompletion.Create(operationId, 1, fingerprint, signature), certificateDer);
    }

    internal X509Certificate2 CreateUntrustedSigner()
    {
        RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=Ahmet Yilmaz", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        return request.CreateSelfSigned(Pki.ReferenceTimeUtc.AddDays(-1), Pki.ReferenceTimeUtc.AddDays(30));
    }

    internal static byte[] CreateUnsignedPdf() => CreateOnePagePdf();

    internal ValidationContext CreateContext(bool includeGoodCrl, bool includeIntermediate = true)
    {
        CertificateDescriptor root = Describe(Pki.Root, CertificateSource.Local);
        RevocationEvidenceSet evidence = includeGoodCrl
            ? new([
                new(RevocationEvidenceType.Crl, RevocationEvidenceSource.Local,
                    CreateGoodCrl(Pki.Intermediate)),
                new(RevocationEvidenceType.Crl, RevocationEvidenceSource.Local,
                    CreateGoodCrl(Pki.Root))])
            : RevocationEvidenceSet.Empty;
        return new(
            ValidationProfile.GeneralX509,
            Pki.ReferenceTimeUtc,
            ValidationTimeSource.CurrentSystemTime,
            new TrustStoreSnapshot("trust-test-v1", [new(root, [ValidationProfile.GeneralX509])]),
            new CertificatePolicyCatalog("policy-test-v1", []),
            embeddedIntermediates: includeIntermediate
                ? [Describe(Pki.Intermediate, CertificateSource.Embedded)]
                : [],
            revocationEvidence: evidence);
    }

    public void Dispose() => Pki.Dispose();

    private byte[] CreateGoodCrl(X509Certificate2 issuerCertificate)
    {
        Org.BouncyCastle.X509.X509Certificate issuer = DotNetUtilities.FromX509Certificate(issuerCertificate);
        using RSA issuerKey = issuerCertificate.GetRSAPrivateKey()!;
        X509V2CrlGenerator generator = new();
        generator.SetIssuerDN(issuer.SubjectDN);
        generator.SetThisUpdate(Pki.ReferenceTimeUtc.AddHours(-2).UtcDateTime);
        generator.SetNextUpdate(Pki.ReferenceTimeUtc.AddHours(10).UtcDateTime);
        return generator.Generate(new Asn1SignatureFactory(
            "SHA256WITHRSA",
            DotNetUtilities.GetRsaKeyPair(issuerKey).Private)).GetEncoded();
    }

    private sealed class TsaFetcher(TestTsaResponder tsa) : IExternalResourceFetcher
    {
        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ExternalResourceFetchResult(tsa.Grant(request.Body), "application/timestamp-reply"));
    }

    private static CertificateDescriptor Describe(X509Certificate2 certificate, CertificateSource source) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), source);

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
