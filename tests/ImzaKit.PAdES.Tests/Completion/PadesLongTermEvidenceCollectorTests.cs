using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Revocation.Online;
using ImzaKit.Revocation.Parsing;
using ImzaKit.Testing.Certificates;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace ImzaKit.PAdES.Tests.Completion;

public sealed class PadesLongTermEvidenceCollectorTests
{
    [Fact]
    public async Task CollectFetchesOcspForSignerWhenIssuerIsSupplied()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            ocspUri: "https://ocsp.example/status");
        using TestTsaResponder tsa = new();
        byte[] signedPdf = SignBaselineT(pki, tsa);
        ScriptedFetcher fetcher = new((uri, body) =>
        {
            Assert.Equal("https://ocsp.example/status", uri.ToString());
            return GrantOcsp(pki, body);
        });
        OnlineRevocationClient client = new(
            fetcher,
            new MemoryRevocationEvidenceCache(),
            new BouncyCastleRevocationEvidenceParser());

        PadesValidationMaterial material = await PadesLongTermEvidenceCollector.CollectAsync(
            signedPdf,
            client,
            pki.ReferenceTimeUtc,
            [
                pki.Leaf.Export(X509ContentType.Cert),
                pki.Intermediate.Export(X509ContentType.Cert)
            ]);

        Assert.True(material.OcspResponses.Count >= 1);
        Assert.Contains(
            material.Certificates,
            certificate => certificate.AsSpan().SequenceEqual(pki.Leaf.RawData));
        Assert.Equal(1, fetcher.Calls);
        byte[] longTerm = PadesSignatureCompleter.EmbedBaselineLt(signedPdf, material);
        Assert.Contains("/OCSPs [", Encoding.ASCII.GetString(longTerm), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExtendToLtCollectsEvidenceWithoutCallerOcsp()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            ocspUri: "https://ocsp.example/status");
        using TestTsaResponder tsa = new();
        byte[] signedPdf = SignBaselineT(pki, tsa);
        ScriptedFetcher fetcher = new((_, body) => GrantOcsp(pki, body));
        OnlineRevocationClient client = new(
            fetcher,
            new MemoryRevocationEvidenceCache(),
            new BouncyCastleRevocationEvidenceParser());

        byte[] extended = await PadesSignatureExtender.ExtendAsync(
            signedPdf,
            "B-LT",
            revocationClient: client,
            validationTimeUtc: pki.ReferenceTimeUtc,
            material: new PadesValidationMaterial(
                [pki.Leaf.Export(X509ContentType.Cert), pki.Intermediate.Export(X509ContentType.Cert)]));

        Assert.Equal("B-LT", PadesSignatureExtender.DetectLevel(extended));
        Assert.Contains("/OCSPs [", Encoding.ASCII.GetString(extended), StringComparison.Ordinal);
        Assert.True(fetcher.Calls >= 1);
    }

    private static byte[] SignBaselineT(TestCertificateAuthority pki, TestTsaResponder tsa)
    {
        using RSA rsa = pki.Leaf.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Test leaf has no RSA key.");
        byte[] certificateDer = pki.Leaf.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new ImzaKit.Cryptography.Digests.DefaultDigestCalculator())).Prepare(
                operationId,
                "COLLECT-PDF",
                CreateOnePagePdf(),
                cmsCapacity: 8192,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signature = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        ScriptedFetcher tsaFetcher = new((_, body) => tsa.Grant(body));
        return PadesSignatureCompleter.CompleteBaselineT(
            preparation,
            SignatureCompletion.Create(operationId, 1, fingerprint, signature),
            certificateDer,
            new Rfc3161TimeStampClient(tsaFetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None).GetAwaiter().GetResult();
    }

    private static byte[] GrantOcsp(TestCertificateAuthority pki, byte[] requestDer)
    {
        OcspReq request = new(requestDer);
        Req item = request.GetRequestList()[0];
        BcX509Certificate issuer = DotNetUtilities.FromX509Certificate(pki.Intermediate);
        using RSA issuerKey = pki.Intermediate.GetRSAPrivateKey()!;
        BasicOcspRespGenerator generator = new(issuer.GetPublicKey());
        generator.AddResponse(
            item.GetCertID(),
            CertificateStatus.Good,
            pki.ReferenceTimeUtc.AddHours(-2).UtcDateTime,
            pki.ReferenceTimeUtc.AddHours(10).UtcDateTime,
            null);
        Asn1OctetString? nonce = request.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
        if (nonce is not null)
        {
            X509ExtensionsGenerator extensions = new();
            extensions.AddExtension(OcspObjectIdentifiers.PkixOcspNonce, false, nonce.GetOctets());
            generator.SetResponseExtensions(extensions.Generate());
        }

        BasicOcspResp basic = generator.Generate(
            new Asn1SignatureFactory("SHA256WITHRSA", DotNetUtilities.GetRsaKeyPair(issuerKey).Private),
            [issuer],
            pki.ReferenceTimeUtc.UtcDateTime);
        return new OCSPRespGenerator().Generate(OCSPRespGenerator.Successful, basic).GetEncoded();
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

    private sealed class ScriptedFetcher(Func<Uri, byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public int Calls { get; private set; }

        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            string contentType = request.Method == "POST"
                ? "application/ocsp-response"
                : "application/pkix-crl";
            return Task.FromResult(new ExternalResourceFetchResult(
                respond(request.Uri, request.Body),
                contentType));
        }
    }
}
