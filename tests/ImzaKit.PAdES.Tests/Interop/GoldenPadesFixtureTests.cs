using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Preparation;
using Org.BouncyCastle.Cms;
using PdfSharp.Pdf.IO;

namespace ImzaKit.PAdES.Tests.Interop;

public sealed class GoldenPadesFixtureTests
{
    [Fact]
    public void GoldenPadesHasStableSha256()
    {
        GoldenPadesFixture fixture = GoldenPadesFixture.Create();

        string sha256 = Convert.ToHexString(SHA256.HashData(fixture.SignedPdf));

        Assert.Equal("8206460B35BBFF225605A2679BE003A917567D960FF2EEE0192B50CDAC3EBC83", sha256);
    }

    [Fact]
    public void GoldenPadesPassesPdfSharpAndBouncyCastleValidation()
    {
        GoldenPadesFixture fixture = GoldenPadesFixture.Create();

        using MemoryStream stream = new(fixture.SignedPdf, writable: false);
        using PdfSharp.Pdf.PdfDocument document = PdfReader.Open(stream, PdfDocumentOpenMode.Import);
        Assert.Single(document.Pages);

        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(
            fixture.SignedPdf,
            fixture.Preparation.Placeholder.ContentsOffset + 1,
            fixture.Preparation.Placeholder.ContentsLength - 2));
        byte[] cmsBytes = paddedCms[..ReadDerValueLength(paddedCms)];
        CmsSignedData signedData = new(
            new CmsProcessableByteArray(fixture.Preparation.Placeholder.GetSignableBytes()),
            cmsBytes);
        SignerInformation signer = Assert.Single(signedData.GetSignerInfos().GetSigners());
        Org.BouncyCastle.X509.X509Certificate signerCertificate = Assert.Single(
            signedData.GetCertificates().EnumerateMatches(signer.SignerID));

        Assert.True(signer.Verify(signerCertificate.GetPublicKey()));
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
}

internal sealed record GoldenPadesFixture(
    byte[] SignedPdf,
    PadesSignaturePreparation Preparation)
{
    private const string PrivateKeyBase64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+3I36CiMiw1ltm4FhVtAEhC/TWFSnaXtNg4AgEl/ebU3jmhD7lLlP9D8wonl3cxPqotFU0sYjK6jamLGv5uMItDNeRT7CEuaFYwk7X63kOFML9RNZfzSTqkEPo9/3mU+/2bU2gMuqAxC9NtoZfmgyePLlnOYimlihm4sTrrFtbL5ivdZyVn8QTihNxpLpGqg3Onq1cDk8+Z5PXlZNbc2odkeLIF7JQkgS83i+CYyS6/wDgXoCojTFgw5WgAf0vHIh0kXK1LC3x8CK5hxxmCn1d/xEffBcUM6zAaMUPq6IqOpclKtHESlkkJi2tMSzDSvQljRARqOGt7Q/vtH1bNktAgMBAAECggEBAJzOMSrzNyixXACMGQCyxRZgz7YQRQSBydbGKfavgeoI3UwX4MoAxzrkDSJU6fx0JDHKcLcCr9xnW0O03Y8J3w7gla9mrofd5VxDIGuSURhGGhyhzbLiqnyDDQ7fcPtIDtgs8g+EQ087U35Q2WDGlK6a5dw1SnG1Ywnq85lJFeYyW4lxBZkpAn2Vjil37RLGhn98IccRzP2gdY+5v6UvUUsaJ64kQEBzOVZUZlxzsvcnS3Rt4b6T9IwNdiK9pcbiKfSRY0xhh6Z86XXw8nowD0VIlnwIn1lyHjtltVh6DpaX1kSzqAcutKVTOKxGhhSYMCQQSd1PnUIt+9+/rXgWNVUCgYEA8fs5EDkE3Cn6JyjOoSjOGWKBcwguLxYYCRlaD/y2YyiN3HFb0jAOaekDSSi2YXCg2w1zpwGxf/U3PnxvQ0UJlUPFQQ/ZJo09mzbf+6NzYwWYmIHGgkEktO36z07yt1Xr+xoUm8qocnkiA4/38jR+wn8sm/dy6biHr9VrOO/CzV8CgYEAyesvI8E8Fx4SCAYuq+rkcPGW6PTjMgCqpwj0ysN1Yxl7oVWlpvWMWe1gNuHb2wBQ7SqOmwQ46wQBubQ/rKPU4edb0QaOpBor97fn5/kqR9wxs6mxV6oN4J9Afx6axHf6CnoiPW4alC7DEQUFpDZ+rgef1dRXu8s2/e+mw3edGPMCgYA7U+DVvWUXpaMTXsnqcVq2lpQuY98O5FfYQ0L1kHwXK6Y8Wf6tNeMSzHJlyXmNwlNt4Yptc9jVCoYU5+VPlOmYkxkVrpELBq4IFBguVhDAQmr7WTYWUWpygbZwhWa01HgbBHXxDGroRhK01ONxmrVJcmy5gJ3H99osniK/vuj/+QKBgAuJzfLMGwPzKvKcb9RRIua1V3tOayEzWo0a/OoNS0rzbNYmT8X/qBqHbwUT2P1lwjobQXToQ9xiKTsUasMRxZt3Hg8Owd3sxPBt6OmfmmPq2Eg8/S5WQF7Cmuvoss1hUb+BhS1felNXbLwvPkhI+Oo281JDxROtJCJUrIHk9uwzAoGAC0ffa0Q9FQalMArNHEBEEcy5kjhgtTsa+xFfFnUSmC2Di7qcoP+y41rNbYgZzkS33yzZzKBTpVh7N8KR+auUx8USZCAUCuY51qZjyXAZIVfw8A5EnF4Ce4ljP8GRRQrPSxuNCqg4CpeaLZAfJBn9bKXo0vrUEe8LgWFQrB/NkmU=";
    private const string CertificateBase64 = "MIICvTCCAaWgAwIBAgIJANbDTwMu9AFdMA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMTE0ltemFLaXQgR29sZGVuIFRlc3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAeMRwwGgYDVQQDExNJbXphS2l0IEdvbGRlbiBUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtyN+gojIsNZbZuBYVbQBIQv01hUp2l7TYOAIBJf3m1N45oQ+5S5T/Q/MKJ5d3MT6qLRVNLGIyuo2pixr+bjCLQzXkU+whLmhWMJO1+t5DhTC/UTWX80k6pBD6Pf95lPv9m1NoDLqgMQvTbaGX5oMnjy5ZzmIppYoZuLE66xbWy+Yr3WclZ/EE4oTcaS6RqoNzp6tXA5PPmeT15WTW3NqHZHiyBeyUJIEvN4vgmMkuv8A4F6AqI0xYMOVoAH9LxyIdJFytSwt8fAiuYccZgp9Xf8RH3wXFDOswGjFD6uiKjqXJSrRxEpZJCYtrTEsw0r0JY0QEajhre0P77R9WzZLQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBr/5WItUDOoRPKZjyeQW/rlDDPqRlb4mYrgMBpMRZ2NXrzuPB73lzD7DBAEt3jEHEFOhCCAId8cwalF9LxyuM7i2STcAnAUMdnXuGvrWlou8/7nSCxlKBpzfmLvY2iC4P0s0+dGONvu+3mB4uPgHEohLAHV5S1SDVlQNpIfrVuJyGFAeSHx9sMo/p/slwvg2uhPVvfV7CCwUKWWcQO/fDZZumWdYOu8cK8YVJe2fDnTSpOd+CAOjh2Q2grTAgg7NwZkRXhmDme2gIhZbVy08xl/Zk8QLE2/PpjNupLSZH9SDFkn5IxkRda2xt4mfJLDk/sXsqonA478PaAj2uEuc9F";

    public static GoldenPadesFixture Create()
    {
        byte[] certificateDer = Convert.FromBase64String(CertificateBase64);
        using RSA rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(PrivateKeyBase64), out _);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.Parse("8696b5a7-3d68-4d97-a765-8c6e68f8dc62");
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "GOLDEN-ORIGINAL-PDF-SHA256",
                CreateOnePagePdf(),
                cmsCapacity: 4096,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signatureValue = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        SignatureCompletion completion = SignatureCompletion.Create(operationId, 1, fingerprint, signatureValue);
        byte[] signedPdf = PadesSignatureCompleter.Complete(preparation, completion, certificateDer);
        return new GoldenPadesFixture(signedPdf, preparation);
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
