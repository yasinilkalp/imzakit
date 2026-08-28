using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;

namespace ImzaKit.PAdES.Tests.Completion;

public sealed class PadesBaselineTTests
{
    private const string SignatureTimeStampTokenOid = "1.2.840.113549.1.9.16.2.14";

    [Fact]
    public async Task CompleteBaselineTEmbedsRfc3161TokenOverSignatureValueHash()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new("CN=ImzaKit PAdES B-T", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.Parse("a7c3d1e0-4b92-4c18-9f6a-21d8e0b4c901");
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "ORIGINAL-PDF-SHA256",
                CreateOnePagePdf(),
                cmsCapacity: 8192,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signatureValue = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        SignatureCompletion completion = SignatureCompletion.Create(operationId, 1, fingerprint, signatureValue);
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));

        byte[] signedPdf = await PadesSignatureCompleter.CompleteBaselineT(
            preparation,
            completion,
            certificateDer,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);

        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(
            signedPdf,
            preparation.Placeholder.ContentsOffset + 1,
            preparation.Placeholder.ContentsLength - 2));
        int cmsLength = ReadDerValueLength(paddedCms);
        SignedCms signedCms = new(
            new ContentInfo(preparation.Placeholder.GetSignableBytes()),
            detached: true);
        signedCms.Decode(paddedCms[..cmsLength]);
        signedCms.CheckSignature(verifySignatureOnly: true);
        List<CryptographicAttributeObject> unsignedAttributes = [];
        foreach (CryptographicAttributeObject attribute in signedCms.SignerInfos[0].UnsignedAttributes)
        {
            unsignedAttributes.Add(attribute);
        }

        CryptographicAttributeObject timestamp = Assert.Single(unsignedAttributes);
        Assert.Equal(SignatureTimeStampTokenOid, timestamp.Oid?.Value);
        byte[] tokenDer = timestamp.Values[0].RawData;
        TimeStampToken token = new(new CmsSignedData(tokenDer));
        Assert.Equal(SHA256.HashData(signatureValue), token.TimeStampInfo.GetMessageImprintDigest());
        Assert.Equal(1, fetcher.Calls);
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
        builder.Append("xref\n0 4\n")
            .Append("0000000000 65535 f \n")
            .Append(catalogOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pagesOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pageOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n")
            .Append(xrefOffset.ToString(CultureInfo.InvariantCulture))
            .Append("\n%%EOF\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static int ReadDerValueLength(ReadOnlySpan<byte> encoded)
    {
        int lengthByte = encoded[1];
        if ((lengthByte & 0x80) == 0)
        {
            return 2 + lengthByte;
        }

        int lengthByteCount = lengthByte & 0x7F;
        int contentLength = 0;
        for (int index = 0; index < lengthByteCount; index++)
        {
            contentLength = (contentLength << 8) | encoded[2 + index];
        }

        return 2 + lengthByteCount + contentLength;
    }

    private sealed class ScriptedFetcher(Func<Uri, byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public int Calls { get; private set; }

        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            byte[] body = respond(request.Uri, request.Body);
            return Task.FromResult(new ExternalResourceFetchResult(body, "application/timestamp-reply"));
        }
    }
}
