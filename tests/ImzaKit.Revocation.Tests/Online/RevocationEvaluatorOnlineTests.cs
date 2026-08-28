using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;
using ImzaKit.Core.Net;
using ImzaKit.Revocation.Evaluation;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Online;
using ImzaKit.Revocation.Parsing;
using ImzaKit.Revocation.Tests.Fixtures;
using ImzaKit.Testing.Certificates;
using Org.BouncyCastle.Asn1.X509;

namespace ImzaKit.Revocation.Tests.Online;

public sealed class RevocationEvaluatorOnlineTests
{
    [Fact]
    public async Task OnlineOcspIsUsedBeforeEmbeddedCrl()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            ocspUri: "https://ocsp.example/status");
        ScriptedFetcher fetcher = new((_, body) => RevocationEvidenceFixture.CreateOcspResponse(pki, body));
        RevocationEvaluator evaluator = CreateEvaluator(fetcher);

        OfflineRevocationResult result = await evaluator.EvaluateAsync(
            Request(
                pki,
                [new RevocationEvidence(
                    RevocationEvidenceType.Crl,
                    RevocationEvidenceSource.Embedded,
                    RevocationEvidenceFixture.CreateCrl(pki, CrlReason.KeyCompromise))],
                allowOnline: true),
            CancellationToken.None);

        Assert.Equal(RevocationStatus.Good, result.Status);
        Assert.Equal(RevocationEvidenceSource.Online, result.Certificates[0].EvidenceSource);
        Assert.Equal(RevocationEvidenceType.Ocsp, result.Certificates[0].EvidenceType);
        Assert.Equal(1, fetcher.Calls);
    }

    [Fact]
    public async Task OnlineCrlIsUsedWhenCertificateHasNoOcspUri()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            crlDistributionUri: "https://crl.example/ca.crl");
        ScriptedFetcher fetcher = new((_, _) => RevocationEvidenceFixture.CreateCrl(pki));
        RevocationEvaluator evaluator = CreateEvaluator(fetcher);

        OfflineRevocationResult result = await evaluator.EvaluateAsync(
            Request(pki, [], allowOnline: true),
            CancellationToken.None);

        Assert.Equal(RevocationStatus.Good, result.Status);
        Assert.Equal(RevocationEvidenceSource.Online, result.Certificates[0].EvidenceSource);
        Assert.Equal(RevocationEvidenceType.Crl, result.Certificates[0].EvidenceType);
        Assert.Equal(1, fetcher.Calls);
    }

    [Fact]
    public async Task CachedOcspAvoidsSecondNetworkFetch()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            ocspUri: "https://ocsp.example/status");
        ScriptedFetcher fetcher = new((_, body) => RevocationEvidenceFixture.CreateOcspResponse(pki, body));
        MemoryRevocationEvidenceCache cache = new();
        RevocationEvaluator evaluator = CreateEvaluator(fetcher, cache);
        RevocationEvaluationRequest request = Request(pki, [], allowOnline: true);

        OfflineRevocationResult first = await evaluator.EvaluateAsync(request, CancellationToken.None);
        OfflineRevocationResult second = await evaluator.EvaluateAsync(request, CancellationToken.None);

        Assert.Equal(RevocationStatus.Good, first.Status);
        Assert.Equal(RevocationStatus.Good, second.Status);
        Assert.Equal(RevocationEvidenceSource.Online, first.Certificates[0].EvidenceSource);
        Assert.Equal(RevocationEvidenceSource.Local, second.Certificates[0].EvidenceSource);
        Assert.Equal(1, fetcher.Calls);
    }

    [Fact]
    public void CacheExpiresAtNextUpdate()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        MemoryRevocationEvidenceCache cache = new();
        byte[] ocsp = RevocationEvidenceFixture.CreateOcsp(pki);
        cache.Store(
            OnlineRevocationClient.OcspKey(Describe(pki.Leaf), Describe(pki.Intermediate)),
            RevocationEvidenceType.Ocsp,
            ocsp,
            pki.ReferenceTimeUtc.AddHours(10),
            pki.ReferenceTimeUtc);

        Assert.True(cache.TryGet(
            OnlineRevocationClient.OcspKey(Describe(pki.Leaf), Describe(pki.Intermediate)),
            pki.ReferenceTimeUtc.AddHours(9),
            out RevocationEvidence cached));
        Assert.Equal(RevocationEvidenceSource.Local, cached.Source);
        Assert.False(cache.TryGet(
            OnlineRevocationClient.OcspKey(Describe(pki.Leaf), Describe(pki.Intermediate)),
            pki.ReferenceTimeUtc.AddHours(11),
            out _));
    }

    [Fact]
    public async Task AllowOnlineFalseDoesNotFetch()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            ocspUri: "https://ocsp.example/status");
        ScriptedFetcher fetcher = new((_, body) => RevocationEvidenceFixture.CreateOcspResponse(pki, body));
        RevocationEvaluator evaluator = CreateEvaluator(fetcher);

        OfflineRevocationResult result = await evaluator.EvaluateAsync(
            Request(pki, [], allowOnline: false),
            CancellationToken.None);

        Assert.Equal(RevocationStatus.Unavailable, result.Status);
        Assert.Equal(0, fetcher.Calls);
    }

    [Fact]
    public async Task OcspNonceMismatchIsInvalid()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            ocspUri: "https://ocsp.example/status");
        ScriptedFetcher fetcher = new((_, body) =>
            RevocationEvidenceFixture.CreateOcspResponse(pki, body, echoNonce: false));
        RevocationEvaluator evaluator = CreateEvaluator(fetcher);

        OfflineRevocationResult result = await evaluator.EvaluateAsync(
            Request(pki, [], allowOnline: true),
            CancellationToken.None);

        Assert.Equal(RevocationStatus.Invalid, result.Status);
        Assert.Contains("OcspNonceMismatch", result.Certificates[0].Findings);
        Assert.Equal(1, fetcher.Calls);
    }

    private static RevocationEvaluator CreateEvaluator(
        ScriptedFetcher fetcher,
        IRevocationEvidenceCache? cache = null) =>
        new(
            new BouncyCastleRevocationEvidenceParser(),
            new OnlineRevocationClient(
                fetcher,
                cache ?? new MemoryRevocationEvidenceCache(),
                new BouncyCastleRevocationEvidenceParser()));

    private static RevocationEvaluationRequest Request(
        TestCertificateAuthority pki,
        IEnumerable<RevocationEvidence> evidence,
        bool allowOnline) =>
        new(
            new CertificateChainCandidate([Describe(pki.Leaf), Describe(pki.Intermediate)]),
            new RevocationEvidenceSet(evidence),
            pki.ReferenceTimeUtc,
            TimeSpan.FromMinutes(5),
            allowOnline);

    private static CertificateDescriptor Describe(X509Certificate2 certificate) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), CertificateSource.Local);

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
            return Task.FromResult(new ExternalResourceFetchResult(respond(request.Uri, request.Body), contentType));
        }
    }
}
