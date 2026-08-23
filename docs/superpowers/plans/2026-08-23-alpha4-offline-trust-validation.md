# ImzaKit Alpha.4 Offline Trust Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend PAdES verification with deterministic offline X.509 chain, trust-policy, and OCSP/CRL evaluation while preserving the existing validation API.

**Architecture:** Three focused libraries (`ImzaKit.Certificate`, `ImzaKit.Trust`, and `ImzaKit.Revocation`) expose immutable models and stateless services. `ImzaKit.Verify` extracts the CMS signer and orchestrates those services through `PadesValidationService`; the static `PadesValidator` remains a compatibility facade.

**Tech Stack:** .NET 10, C# latest, `System.Security.Cryptography.X509Certificates`, `System.Security.Cryptography.Pkcs`, BouncyCastle.Cryptography 2.7.0, xUnit 2.9.3, Microsoft.Extensions.DependencyInjection 10.0.11, PowerShell verification scripts.

**Spec:** `docs/superpowers/specs/2026-08-23-alpha4-offline-trust-validation-design.md`

## Global Constraints

- Target framework remains exactly `net10.0`; nullable reference types and warnings-as-errors remain enabled.
- Package version becomes `1.0.0-alpha.4`, but publishing is not part of this plan.
- System trust stores, AIA, OCSP URLs, and CRL URLs must never be consulted automatically.
- Expected validation failures return structured results; only invalid programming/configuration input throws argument exceptions.
- Certificate and evidence byte arrays must be defensively copied; public collections must be immutable to callers.
- Existing `PadesValidator.Validate(ReadOnlySpan<byte>)` behavior and the six positional `PadesValidationReport` constructor parameters remain source-compatible.
- `GeneralX509` and `TurkiyeNes` are the only public profiles; do not add an `Eidas` placeholder.
- Evidence precedence is embedded OCSP, local OCSP, embedded CRL, local CRL.
- All new production assemblies are included in the single `ImzaKit` package; the package must contain 12 ImzaKit DLLs and zero `ImzaKit.*` package dependencies.
- Each implementation task follows red-green-refactor: add a focused failing test, observe the expected failure, add the minimum implementation, and run the focused suite before committing.

## File and Contract Map

- `src/ImzaKit.Certificate/Models/*`: immutable certificate identity, source, candidate-chain, and chain-validation result contracts.
- `src/ImzaKit.Certificate/Building/*`: embedded-first chain discovery with loop and depth controls.
- `src/ImzaKit.Certificate/Validation/*`: time, signature, Basic Constraints, Key Usage, and algorithm validation.
- `src/ImzaKit.Trust/Models/*`: profiles, versioned anchors, trust snapshots, policy entries, and catalogs.
- `src/ImzaKit.Trust/Evaluation/*`: anchor/profile/policy matching with no platform trust lookup.
- `src/ImzaKit.Revocation/Models/*`: copied raw evidence, evidence source/type, and per-certificate results.
- `src/ImzaKit.Revocation/Evaluation/*`: BouncyCastle-backed OCSP/CRL parsing, signature authorization, freshness, and precedence.
- `src/ImzaKit.Verify/Validation/*`: context, typed reasons, decision engine, orchestration service, compatibility facade, and expanded report.
- `tests/ImzaKit.Testing/Certificates/*`: shared runtime certificate/evidence factory used only by test projects.
- `scripts/verify-nuget-package.ps1`: verifies the expanded module set and dependency contract.
- `README.md`, `docs/imzakit-teknik-kullanim-rehberi.html`, `site/index.html`, and `reports/imzakit-gelistirme-durum.html`: Alpha.4 usage and status material.

---

### Task 1: Certificate module contracts and runtime test PKI

**Files:**
- Create: `src/ImzaKit.Certificate/ImzaKit.Certificate.csproj`
- Create: `src/ImzaKit.Certificate/Models/CertificateSource.cs`
- Create: `src/ImzaKit.Certificate/Models/CertificateDescriptor.cs`
- Create: `src/ImzaKit.Certificate/Models/CertificateChainCandidate.cs`
- Create: `src/ImzaKit.Certificate/Models/CertificateChainBuildResult.cs`
- Create: `src/ImzaKit.Certificate/Models/CertificateChainStatus.cs`
- Create: `tests/ImzaKit.Testing/ImzaKit.Testing.csproj`
- Create: `tests/ImzaKit.Testing/Certificates/TestCertificateAuthority.cs`
- Create: `tests/ImzaKit.Certificate.Tests/ImzaKit.Certificate.Tests.csproj`
- Create: `tests/ImzaKit.Certificate.Tests/Models/CertificateModelTests.cs`
- Modify: `ImzaKit.slnx`

**Interfaces:**
- Produces: `CertificateDescriptor.FromDer(ReadOnlySpan<byte>, CertificateSource)`, with copied DER and normalized uppercase SHA-256 thumbprint.
- Produces: `CertificateChainCandidate(IReadOnlyList<CertificateDescriptor> certificates)` ordered leaf-to-root.
- Produces: `CertificateChainBuildResult(CertificateChainStatus status, CertificateChainCandidate? candidate, IReadOnlyList<string> findings)`.

- [ ] **Step 1: Add the projects and failing immutability/model tests**

```csharp
[Fact]
public void CertificateDescriptorCopiesDerAndNormalizesIdentity()
{
    using TestCertificateAuthority pki = TestCertificateAuthority.Create();
    byte[] der = pki.Leaf.Export(X509ContentType.Cert);
    CertificateDescriptor descriptor = CertificateDescriptor.FromDer(der, CertificateSource.Embedded);
    string expected = Convert.ToHexString(SHA256.HashData(der));
    der[0] ^= 0xff;

    Assert.Equal(expected, descriptor.Sha256Thumbprint);
    Assert.NotEqual(der, descriptor.ExportDer());
    Assert.Equal(CertificateSource.Embedded, descriptor.Source);
}
```

- [ ] **Step 2: Run the focused tests and observe the missing-type failure**

Run: `dotnet test tests/ImzaKit.Certificate.Tests/ImzaKit.Certificate.Tests.csproj --filter FullyQualifiedName~CertificateModelTests`

Expected: FAIL because `CertificateDescriptor`, `CertificateSource`, and `TestCertificateAuthority` do not exist.

- [ ] **Step 3: Implement the immutable model set and runtime PKI helper**

`TestCertificateAuthority.Create()` must generate root CA → intermediate CA → RSA leaf certificates with SKI/AKI, CA Basic Constraints, issuer `keyCertSign | cRLSign`, leaf `digitalSignature`, and a configurable leaf policy OID. It must retain private keys only in the disposable test helper. `CertificateDescriptor` stores a private `byte[]`, returns a clone from `ExportDer()`, and exposes parsed subject, issuer, serial number, SKI, AKI, validity, and source values.

- [ ] **Step 4: Run model tests and the solution build**

Run: `dotnet test tests/ImzaKit.Certificate.Tests/ImzaKit.Certificate.Tests.csproj --filter FullyQualifiedName~CertificateModelTests`

Expected: PASS.

Run: `dotnet build ImzaKit.slnx -c Release`

Expected: PASS with 0 warnings and 0 errors.

- [ ] **Step 5: Commit the module contracts**

```powershell
git add ImzaKit.slnx src/ImzaKit.Certificate tests/ImzaKit.Testing tests/ImzaKit.Certificate.Tests
git commit -m "feat: add certificate validation contracts"
```

### Task 2: Embedded-first certificate chain builder

**Files:**
- Create: `src/ImzaKit.Certificate/Building/ICertificateChainBuilder.cs`
- Create: `src/ImzaKit.Certificate/Building/CertificateChainBuilder.cs`
- Create: `src/ImzaKit.Certificate/Building/CertificateChainBuildRequest.cs`
- Create: `tests/ImzaKit.Certificate.Tests/Building/CertificateChainBuilderTests.cs`

**Interfaces:**
- Consumes: `CertificateDescriptor` and `CertificateChainBuildResult` from Task 1.
- Produces: `ICertificateChainBuilder.Build(CertificateChainBuildRequest request)`.
- Produces: `CertificateChainBuildRequest(CertificateDescriptor leaf, IEnumerable<CertificateDescriptor> embedded, IEnumerable<CertificateDescriptor> local, int maximumDepth = 10)`; constructor copies collections and rejects depth outside `2..32`.

- [ ] **Step 1: Write failing chain-order, source-precedence, incomplete, loop, and depth tests**

```csharp
[Fact]
public void BuildPrefersEmbeddedIntermediateOverMatchingLocalCertificate()
{
    using TestCertificateAuthority pki = TestCertificateAuthority.Create();
    CertificateDescriptor leaf = Describe(pki.Leaf, CertificateSource.Embedded);
    CertificateDescriptor embedded = Describe(pki.Intermediate, CertificateSource.Embedded);
    CertificateDescriptor local = Describe(pki.Intermediate, CertificateSource.Local);

    CertificateChainBuildResult result = new CertificateChainBuilder().Build(
        new(leaf, [embedded], [local, Describe(pki.Root, CertificateSource.Local)]));

    Assert.Equal(CertificateChainStatus.Complete, result.Status);
    Assert.Equal(CertificateSource.Embedded, result.Candidate!.Certificates[1].Source);
}
```

Also assert missing intermediate returns `Incomplete` without throwing, a repeated thumbprint returns `Invalid` with `CertificateChainLoop`, and a chain beyond `maximumDepth` returns `Invalid` with `CertificateChainDepthExceeded`.

- [ ] **Step 2: Run builder tests and observe failure**

Run: `dotnet test tests/ImzaKit.Certificate.Tests/ImzaKit.Certificate.Tests.csproj --filter FullyQualifiedName~CertificateChainBuilderTests`

Expected: FAIL because `ICertificateChainBuilder` and `CertificateChainBuilder` do not exist.

- [ ] **Step 3: Implement deterministic chain discovery**

Match issuer candidates by issuer/subject plus AKI/SKI when present, de-duplicate by SHA-256 thumbprint, order candidate pools embedded before local, stop only at a self-issued certificate, and never invoke `X509Chain.Build`. Return findings through the result model for incomplete, ambiguous, looped, or over-depth chains.

- [ ] **Step 4: Run all certificate tests**

Run: `dotnet test tests/ImzaKit.Certificate.Tests/ImzaKit.Certificate.Tests.csproj`

Expected: PASS.

- [ ] **Step 5: Commit the chain builder**

```powershell
git add src/ImzaKit.Certificate/Building tests/ImzaKit.Certificate.Tests/Building
git commit -m "feat: build certificate chains offline"
```

### Task 3: Certificate chain cryptographic validator

**Files:**
- Create: `src/ImzaKit.Certificate/Validation/ICertificateChainValidator.cs`
- Create: `src/ImzaKit.Certificate/Validation/CertificateChainValidator.cs`
- Create: `src/ImzaKit.Certificate/Validation/CertificateChainValidationRequest.cs`
- Create: `src/ImzaKit.Certificate/Validation/CertificateChainValidationResult.cs`
- Create: `src/ImzaKit.Certificate/Validation/CertificateValidationFailure.cs`
- Create: `tests/ImzaKit.Certificate.Tests/Validation/CertificateChainValidatorTests.cs`
- Modify: `tests/ImzaKit.Testing/Certificates/TestCertificateAuthority.cs`

**Interfaces:**
- Consumes: complete `CertificateChainCandidate` from Task 2.
- Produces: `ICertificateChainValidator.Validate(CertificateChainValidationRequest request)`.
- Produces: `CertificateChainValidationRequest(CertificateChainCandidate chain, DateTimeOffset validationTimeUtc)`; rejects non-zero offsets.
- Produces: `CertificateChainValidationResult(CertificateChainStatus status, IReadOnlyList<CertificateValidationFailure> failures)`.
- Produces failures: `Expired`, `NotYetValid`, `InvalidSignature`, `IssuerIsNotCa`, `IssuerKeyCertSignMissing`, `LeafDigitalSignatureMissing`, and `AlgorithmDisallowed`.

- [ ] **Step 1: Write failing validation tests for every certificate rule**

```csharp
[Fact]
public void ValidateAcceptsACompleteValidChainAtUtcTime()
{
    using TestCertificateAuthority pki = TestCertificateAuthority.Create();
    CertificateChainCandidate chain = Candidate(pki.Leaf, pki.Intermediate, pki.Root);

    CertificateChainValidationResult result = new CertificateChainValidator().Validate(
        new(chain, pki.ReferenceTimeUtc));

    Assert.Equal(CertificateChainStatus.Valid, result.Status);
    Assert.Empty(result.Failures);
}
```

Generate variants for expired/not-yet-valid leaf, tampered or wrong-issuer leaf, non-CA issuer, missing issuer `keyCertSign`, missing leaf `digitalSignature`, SHA-1 signatures, and a non-UTC time constructor call.

- [ ] **Step 2: Run validator tests and observe failure**

Run: `dotnet test tests/ImzaKit.Certificate.Tests/ImzaKit.Certificate.Tests.csproj --filter FullyQualifiedName~CertificateChainValidatorTests`

Expected: FAIL because validator contracts are missing.

- [ ] **Step 3: Implement explicit offline validation**

Use `System.Formats.Asn1` to isolate each certificate's DER `tbsCertificate`, signature algorithm, and signature value, then verify it with the issuer certificate's RSA/ECDSA public key. Inspect Basic Constraints and Key Usage extensions explicitly, validate every chain member at `ValidationTimeUtc`, and reject SHA-1/MD5 signature OIDs. Do not set `X509ChainPolicy.TrustMode` or read machine/user certificate stores.

- [ ] **Step 4: Run certificate suite and full regression suite**

Run: `dotnet test tests/ImzaKit.Certificate.Tests/ImzaKit.Certificate.Tests.csproj`

Expected: PASS.

Run: `dotnet test ImzaKit.slnx -c Release --no-restore`

Expected: all existing and new tests PASS.

- [ ] **Step 5: Commit chain validation**

```powershell
git add src/ImzaKit.Certificate/Validation tests/ImzaKit.Certificate.Tests/Validation tests/ImzaKit.Testing/Certificates/TestCertificateAuthority.cs
git commit -m "feat: validate certificate chains offline"
```

### Task 4: Immutable trust store and policy catalog

**Files:**
- Create: `src/ImzaKit.Trust/ImzaKit.Trust.csproj`
- Create: `src/ImzaKit.Trust/Models/ValidationProfile.cs`
- Create: `src/ImzaKit.Trust/Models/TrustAnchor.cs`
- Create: `src/ImzaKit.Trust/Models/TrustStoreSnapshot.cs`
- Create: `src/ImzaKit.Trust/Models/CertificatePolicyEntry.cs`
- Create: `src/ImzaKit.Trust/Models/CertificatePolicyCatalog.cs`
- Create: `tests/ImzaKit.Trust.Tests/ImzaKit.Trust.Tests.csproj`
- Create: `tests/ImzaKit.Trust.Tests/Models/TrustModelTests.cs`
- Modify: `ImzaKit.slnx`

**Interfaces:**
- Consumes: `CertificateDescriptor` from Task 1.
- Produces: `ValidationProfile.GeneralX509` and `ValidationProfile.TurkiyeNes`.
- Produces: `TrustAnchor(CertificateDescriptor certificate, IEnumerable<ValidationProfile> profiles, string? provenance = null)`.
- Produces: `TrustStoreSnapshot(string version, IEnumerable<TrustAnchor> anchors)`.
- Produces: `CertificatePolicyEntry(ValidationProfile profile, string policyOid, DateTimeOffset effectiveFromUtc, DateTimeOffset? effectiveUntilUtc, TimeSpan revocationFreshnessTolerance)`.
- Produces: `CertificatePolicyCatalog(string version, IEnumerable<CertificatePolicyEntry> entries)`.

- [ ] **Step 1: Write failing constructor-validation and defensive-copy tests**

```csharp
[Theory]
[InlineData("")]
[InlineData("   ")]
public void TrustStoreRejectsBlankVersion(string version)
{
    Assert.Throws<ArgumentException>(() => new TrustStoreSnapshot(version, []));
}

[Fact]
public void PolicyCatalogRejectsMalformedOid()
{
    Assert.Throws<ArgumentException>(() => new CertificatePolicyCatalog(
        "2026.08", [new(ValidationProfile.TurkiyeNes, "not-an-oid", From, Until, TimeSpan.FromHours(12))]));
}
```

Also cover duplicate anchor thumbprints, duplicate profile/OID/time entries, non-UTC bounds, reversed time windows, negative freshness tolerance, and mutation of source arrays/lists after construction.

- [ ] **Step 2: Run trust model tests and observe failure**

Run: `dotnet test tests/ImzaKit.Trust.Tests/ImzaKit.Trust.Tests.csproj --filter FullyQualifiedName~TrustModelTests`

Expected: FAIL because the trust project and types do not exist.

- [ ] **Step 3: Implement immutable validated models**

Normalize versions with `Trim()`, policy OIDs with `Oid.Value`, anchor identity by certificate SHA-256, and expose `IReadOnlyList<T>` backed by private arrays. An empty anchor or policy list is allowed so callers can represent a known-empty versioned snapshot.

- [ ] **Step 4: Run trust model tests and build the solution**

Run: `dotnet test tests/ImzaKit.Trust.Tests/ImzaKit.Trust.Tests.csproj`

Expected: PASS.

Run: `dotnet build ImzaKit.slnx -c Release`

Expected: PASS with 0 warnings and 0 errors.

- [ ] **Step 5: Commit trust contracts**

```powershell
git add ImzaKit.slnx src/ImzaKit.Trust tests/ImzaKit.Trust.Tests
git commit -m "feat: add versioned trust policy models"
```

### Task 5: Trust and certificate-policy evaluator

**Files:**
- Create: `src/ImzaKit.Trust/Evaluation/ITrustPolicyEvaluator.cs`
- Create: `src/ImzaKit.Trust/Evaluation/TrustPolicyEvaluator.cs`
- Create: `src/ImzaKit.Trust/Evaluation/TrustPolicyEvaluationRequest.cs`
- Create: `src/ImzaKit.Trust/Evaluation/TrustPolicyEvaluationResult.cs`
- Create: `src/ImzaKit.Trust/Evaluation/TrustPolicyStatus.cs`
- Create: `src/ImzaKit.Trust/Evaluation/TrustPolicyFailure.cs`
- Create: `tests/ImzaKit.Trust.Tests/Evaluation/TrustPolicyEvaluatorTests.cs`

**Interfaces:**
- Consumes: validated leaf-to-root chain, `ValidationProfile`, `TrustStoreSnapshot`, `CertificatePolicyCatalog`, and UTC validation time.
- Produces: `ITrustPolicyEvaluator.Evaluate(TrustPolicyEvaluationRequest request)`.
- Produces: separate `AnchorStatus` and `PolicyStatus`, matched anchor thumbprint, matched policy OID, trust-store version, policy-catalog version, and failures `TrustAnchorNotFound`, `AnchorProfileNotAllowed`, `CertificatePolicyNotAllowed`, `PolicyNotEffective`.

- [ ] **Step 1: Write failing profile and policy evaluation tests**

```csharp
[Fact]
public void TurkiyeNesAcceptsProfileAnchorAndEffectiveLeafPolicy()
{
    TrustPolicyEvaluationResult result = CreateEvaluator().Evaluate(
        Request(profile: ValidationProfile.TurkiyeNes, anchorProfiles: [ValidationProfile.TurkiyeNes],
            leafPolicyOid: "2.16.792.1.2.1.1.7.1"));

    Assert.Equal(TrustPolicyStatus.Passed, result.AnchorStatus);
    Assert.Equal(TrustPolicyStatus.Passed, result.PolicyStatus);
    Assert.Equal("trust-2026.08", result.TrustStoreVersion);
    Assert.Equal("policy-2026.08", result.PolicyCatalogVersion);
}
```

Cover GeneralX509 without a NES OID, missing anchor, wrong anchor profile, disallowed leaf policy, and validation times before/after catalog effectiveness.

- [ ] **Step 2: Run evaluator tests and observe failure**

Run: `dotnet test tests/ImzaKit.Trust.Tests/ImzaKit.Trust.Tests.csproj --filter FullyQualifiedName~TrustPolicyEvaluatorTests`

Expected: FAIL because evaluator contracts are missing.

- [ ] **Step 3: Implement anchor and certificatePolicies matching**

Match only the final chain certificate against configured anchors by DER SHA-256. For `GeneralX509`, pass policy when the anchor is profile-enabled; for `TurkiyeNes`, additionally parse the leaf `2.5.29.32` Certificate Policies extension and require an effective catalog entry. Return structured failures and never call platform chain APIs.

- [ ] **Step 4: Run trust and certificate suites**

Run: `dotnet test tests/ImzaKit.Trust.Tests/ImzaKit.Trust.Tests.csproj`

Expected: PASS.

Run: `dotnet test tests/ImzaKit.Certificate.Tests/ImzaKit.Certificate.Tests.csproj`

Expected: PASS.

- [ ] **Step 5: Commit policy evaluation**

```powershell
git add src/ImzaKit.Trust/Evaluation tests/ImzaKit.Trust.Tests/Evaluation
git commit -m "feat: evaluate trust anchors and certificate policies"
```

### Task 6: Offline revocation evidence models and parser boundary

**Files:**
- Create: `src/ImzaKit.Revocation/ImzaKit.Revocation.csproj`
- Create: `src/ImzaKit.Revocation/Models/RevocationEvidenceSource.cs`
- Create: `src/ImzaKit.Revocation/Models/RevocationEvidenceType.cs`
- Create: `src/ImzaKit.Revocation/Models/RevocationEvidence.cs`
- Create: `src/ImzaKit.Revocation/Models/RevocationEvidenceSet.cs`
- Create: `src/ImzaKit.Revocation/Models/RevocationStatus.cs`
- Create: `src/ImzaKit.Revocation/Models/CertificateRevocationResult.cs`
- Create: `src/ImzaKit.Revocation/Parsing/IRevocationEvidenceParser.cs`
- Create: `src/ImzaKit.Revocation/Parsing/BouncyCastleRevocationEvidenceParser.cs`
- Create: `src/ImzaKit.Revocation/Parsing/ParsedRevocationEvidence.cs`
- Create: `tests/ImzaKit.Revocation.Tests/ImzaKit.Revocation.Tests.csproj`
- Create: `tests/ImzaKit.Revocation.Tests/Models/RevocationEvidenceModelTests.cs`
- Create: `tests/ImzaKit.Revocation.Tests/Parsing/BouncyCastleRevocationEvidenceParserTests.cs`
- Modify: `ImzaKit.slnx`

**Interfaces:**
- Produces: `RevocationEvidence(RevocationEvidenceType type, RevocationEvidenceSource source, ReadOnlySpan<byte> encoded)` with copied bytes.
- Produces: `RevocationEvidenceSet(IEnumerable<RevocationEvidence> evidence)` preserving insertion order.
- Produces: `IRevocationEvidenceParser.Parse(RevocationEvidence evidence, CertificateDescriptor certificate, CertificateDescriptor issuer)` returning status, serial/issuer match, signature authorization, `ThisUpdateUtc`, optional `NextUpdateUtc`, and revocation reason.

- [ ] **Step 1: Write failing copy, OCSP, and CRL parsing tests**

```csharp
[Fact]
public void RevocationEvidenceCopiesEncodedBytes()
{
    byte[] encoded = [0x30, 0x00];
    RevocationEvidence evidence = new(RevocationEvidenceType.Crl, RevocationEvidenceSource.Local, encoded);
    encoded[0] = 0xff;

    Assert.Equal(0x30, evidence.ExportEncoded()[0]);
}
```

Extend `TestCertificateAuthority` with BouncyCastle-generated signed OCSP basic responses and CRLs. Assert parsing of good/revoked OCSP, revoked/suspended CRL reason codes, wrong serial/issuer, invalid signature, and unauthorized responder.

- [ ] **Step 2: Run revocation tests and observe failure**

Run: `dotnet test tests/ImzaKit.Revocation.Tests/ImzaKit.Revocation.Tests.csproj`

Expected: FAIL because revocation contracts and parser are missing.

- [ ] **Step 3: Implement models and isolated BouncyCastle parsing**

Keep every BouncyCastle type internal to `ImzaKit.Revocation`; public contracts use ImzaKit models and BCL time/value types only. Verify OCSP responder authorization against issuer/delegated responder EKU, CRL signature against issuer, and distinguish malformed encoding from cryptographically invalid evidence.

- [ ] **Step 4: Run revocation tests and dependency check**

Run: `dotnet test tests/ImzaKit.Revocation.Tests/ImzaKit.Revocation.Tests.csproj`

Expected: PASS.

Run: `dotnet list src/ImzaKit.Revocation/ImzaKit.Revocation.csproj package`

Expected: direct production dependency includes only `BouncyCastle.Cryptography`; project reference is limited to `ImzaKit.Certificate`.

- [ ] **Step 5: Commit evidence parsing**

```powershell
git add ImzaKit.slnx src/ImzaKit.Revocation tests/ImzaKit.Revocation.Tests tests/ImzaKit.Testing/Certificates/TestCertificateAuthority.cs
git commit -m "feat: parse offline revocation evidence"
```

### Task 7: Offline revocation evaluator and precedence

**Files:**
- Create: `src/ImzaKit.Revocation/Evaluation/IOfflineRevocationEvaluator.cs`
- Create: `src/ImzaKit.Revocation/Evaluation/OfflineRevocationEvaluator.cs`
- Create: `src/ImzaKit.Revocation/Evaluation/OfflineRevocationRequest.cs`
- Create: `src/ImzaKit.Revocation/Evaluation/OfflineRevocationResult.cs`
- Create: `tests/ImzaKit.Revocation.Tests/Evaluation/OfflineRevocationEvaluatorTests.cs`

**Interfaces:**
- Consumes: non-root chain certificates, `RevocationEvidenceSet`, UTC validation time, freshness tolerance, and `IRevocationEvidenceParser`.
- Produces: `IOfflineRevocationEvaluator.Evaluate(OfflineRevocationRequest request)` returning one `CertificateRevocationResult` per evaluated certificate and aggregate `RevocationStatus`.
- Aggregate precedence: any `Revoked`/`Suspended` → that failure; else any `Invalid` → `Invalid`; else any `Unavailable` → `Unavailable`; else any `Stale` → `Stale`; otherwise `Good`.

- [ ] **Step 1: Write failing status, freshness, mismatch, and source-precedence tests**

```csharp
[Fact]
public void EmbeddedOcspWinsOverLocalOcspAndCrl()
{
    OfflineRevocationResult result = Evaluate([
        Evidence(Ocsp, Local, Good),
        Evidence(Crl, Embedded, Revoked),
        Evidence(Ocsp, Embedded, Good)]);

    Assert.Equal(RevocationStatus.Good, result.Status);
    Assert.Equal(RevocationEvidenceSource.Embedded, result.Certificates[0].EvidenceSource);
    Assert.Equal(RevocationEvidenceType.Ocsp, result.Certificates[0].EvidenceType);
}
```

Cover empty evidence → `Unavailable`, nextUpdate before validation time → `Stale`, thisUpdate after validation time+tolerance → `Invalid`, target mismatch ignored with a finding, invalid signature → `Invalid`, revoked → `Revoked`, and certificateHold → `Suspended`.

- [ ] **Step 2: Run evaluator tests and observe failure**

Run: `dotnet test tests/ImzaKit.Revocation.Tests/ImzaKit.Revocation.Tests.csproj --filter FullyQualifiedName~OfflineRevocationEvaluatorTests`

Expected: FAIL because evaluator contracts are missing.

- [ ] **Step 3: Implement deterministic offline evaluation**

Sort usable matching evidence by the fixed source/type rank without changing caller collections. Evaluate leaf and intermediates but not the configured root anchor. Return evidence source/type metadata, never follow distribution URLs, and do not accept evidence whose authorization or signature cannot be established.

- [ ] **Step 4: Run all revocation tests**

Run: `dotnet test tests/ImzaKit.Revocation.Tests/ImzaKit.Revocation.Tests.csproj`

Expected: PASS.

- [ ] **Step 5: Commit revocation evaluation**

```powershell
git add src/ImzaKit.Revocation/Evaluation tests/ImzaKit.Revocation.Tests/Evaluation
git commit -m "feat: evaluate revocation evidence offline"
```

### Task 8: Validation context, typed findings, expanded report, and decision engine

**Files:**
- Create: `src/ImzaKit.Verify/Validation/ValidationTimeSource.cs`
- Create: `src/ImzaKit.Verify/Validation/ValidationReasonCode.cs`
- Create: `src/ImzaKit.Verify/Validation/ValidationContext.cs`
- Create: `src/ImzaKit.Verify/Validation/ValidationDecisionInput.cs`
- Create: `src/ImzaKit.Verify/Validation/ValidationDecisionEngine.cs`
- Create: `tests/ImzaKit.Verify.Tests/Validation/ValidationContextTests.cs`
- Create: `tests/ImzaKit.Verify.Tests/Validation/ValidationDecisionEngineTests.cs`
- Modify: `src/ImzaKit.Verify/Validation/ValidationFinding.cs`
- Modify: `src/ImzaKit.Verify/Validation/PadesValidationReport.cs`
- Modify: `src/ImzaKit.Verify/ImzaKit.Verify.csproj`

**Interfaces:**
- Consumes: Certificate, Trust, and Revocation models from Tasks 1–7.
- Produces: `ValidationContext(ValidationProfile profile, DateTimeOffset validationTimeUtc, ValidationTimeSource validationTimeSource, TrustStoreSnapshot trustStore, CertificatePolicyCatalog policyCatalog, IEnumerable<CertificateDescriptor>? embeddedIntermediates = null, IEnumerable<CertificateDescriptor>? localIntermediates = null, RevocationEvidenceSet? revocationEvidence = null)`.
- Produces: `ValidationFinding(string code, string message)` unchanged plus init-only `ValidationReasonCode? ReasonCode`.
- Produces: existing six-argument `PadesValidationReport` constructor unchanged plus init-only `ChainStatus`, `PolicyStatus`, `RevocationStatus`, `ValidationTime`, `ValidationTimeSource`, `ValidationProfile`, `TrustStoreVersion`, `PolicyCatalogVersion`, and `EvidenceSources`.
- Produces: `ValidationDecisionEngine.Decide(ValidationDecisionInput input)`.

- [ ] **Step 1: Write failing compatibility, defensive-copy, UTC, and decision-table tests**

```csharp
[Fact]
public void ExistingReportConstructorRemainsAvailable()
{
    PadesValidationReport report = new(
        ValidationStatus.Indeterminate, ValidationStatus.Passed, ValidationStatus.Passed,
        ValidationStatus.Indeterminate, "AA", []);

    Assert.Equal(ValidationStatus.Indeterminate, report.Status);
    Assert.Null(report.ValidationProfile);
}

[Theory]
[InlineData(ValidationStatus.Failed, ValidationStatus.Indeterminate, ValidationStatus.Failed)]
[InlineData(ValidationStatus.Passed, ValidationStatus.Indeterminate, ValidationStatus.Indeterminate)]
[InlineData(ValidationStatus.Passed, ValidationStatus.Passed, ValidationStatus.Passed)]
public void DecisionPriorityIsDeterministic(
    ValidationStatus chain, ValidationStatus revocation, ValidationStatus expected)
{
    Assert.Equal(expected, new ValidationDecisionEngine().Decide(Input(chain, revocation)));
}
```

Assert every reason enum member from the spec exists, non-UTC context time throws, context lists are copied, and definitive failure wins over simultaneous indeterminate evidence.

- [ ] **Step 2: Run focused Verify tests and observe failure**

Run: `dotnet test tests/ImzaKit.Verify.Tests/ImzaKit.Verify.Tests.csproj --filter "FullyQualifiedName~ValidationContextTests|FullyQualifiedName~ValidationDecisionEngineTests"`

Expected: FAIL because the context and decision contracts do not exist.

- [ ] **Step 3: Implement compatible contracts and decision rules**

Map the 13 exact `ValidationReasonCode` values from the spec. Preserve `ValidationFinding.Code` as the stable string representation when a typed reason is present. Implement priority: byte-range/crypto/chain/policy/trust/revoked/suspended definitive failures first, then incomplete chain/unavailable/stale evidence, then passed.

- [ ] **Step 4: Run all Verify tests**

Run: `dotnet test tests/ImzaKit.Verify.Tests/ImzaKit.Verify.Tests.csproj`

Expected: PASS, including the pre-existing `PadesValidatorTests`.

- [ ] **Step 5: Commit verification contracts**

```powershell
git add src/ImzaKit.Verify tests/ImzaKit.Verify.Tests/Validation/ValidationContextTests.cs tests/ImzaKit.Verify.Tests/Validation/ValidationDecisionEngineTests.cs
git commit -m "feat: add structured validation context and decisions"
```

### Task 9: Instance PAdES validation orchestration and static compatibility facade

**Files:**
- Create: `src/ImzaKit.Verify/Validation/IPadesValidationService.cs`
- Create: `src/ImzaKit.Verify/Validation/PadesValidationService.cs`
- Create: `tests/ImzaKit.Verify.Tests/Validation/PadesValidationServiceTests.cs`
- Create: `tests/ImzaKit.Verify.Tests/Fixtures/SignedPdfFixture.cs`
- Modify: `src/ImzaKit.Verify/Validation/PadesValidator.cs`
- Modify: `tests/ImzaKit.Verify.Tests/Validation/PadesValidatorTests.cs`
- Modify: `tests/ImzaKit.Verify.Tests/ImzaKit.Verify.Tests.csproj`

**Interfaces:**
- Consumes: `ICertificateChainBuilder`, `ICertificateChainValidator`, `ITrustPolicyEvaluator`, `IOfflineRevocationEvaluator`, and `ValidationDecisionEngine`.
- Produces: `IPadesValidationService.Validate(ReadOnlySpan<byte> pdf)` and `Validate(ReadOnlySpan<byte> pdf, ValidationContext context)`.
- Produces: static facade overload `PadesValidator.Validate(ReadOnlySpan<byte> pdf, ValidationContext context)`; old overload retains exact behavior.

- [ ] **Step 1: Write failing end-to-end context tests before refactoring the facade**

```csharp
[Fact]
public void ValidPdfChainPolicyAndFreshEvidencePass()
{
    SignedPdfFixture fixture = SignedPdfFixture.CreateTurkiyeNes();

    PadesValidationReport report = CreateService().Validate(fixture.Pdf, fixture.ValidContext);

    Assert.Equal(ValidationStatus.Passed, report.Status);
    Assert.Equal(ValidationStatus.Passed, report.ChainStatus);
    Assert.Equal(ValidationStatus.Passed, report.PolicyStatus);
    Assert.Equal(RevocationStatus.Good, report.RevocationStatus);
    Assert.Equal("trust-test-v1", report.TrustStoreVersion);
}
```

Add cases for no evidence → `Indeterminate` + `RevocationDataUnavailable`, revoked/suspended → `Failed`, missing intermediate → `Indeterminate` + `CertificateChainIncomplete`, wrong policy → `Failed`, changed PDF → `Failed` before trust evaluation, and the old static overload retaining `TrustNotEvaluated`.

- [ ] **Step 2: Run service tests and observe failure**

Run: `dotnet test tests/ImzaKit.Verify.Tests/ImzaKit.Verify.Tests.csproj --filter FullyQualifiedName~PadesValidationServiceTests`

Expected: FAIL because `IPadesValidationService` and `PadesValidationService` do not exist.

- [ ] **Step 3: Extract PDF/CMS verification and implement orchestration**

Move the current byte-range/CMS pipeline into the instance service without changing finding codes. Extract the signer certificate and embedded CMS certificates, merge them into context embedded intermediates, invoke services only after byte-range and CMS success, map component failures to typed findings, populate every report metadata field, and calculate final status through `ValidationDecisionEngine`. The static context overload constructs stateless default services; the legacy overload follows its pre-Alpha.4 path and remains indeterminate for trust.

- [ ] **Step 4: Run Verify tests and full regression suite**

Run: `dotnet test tests/ImzaKit.Verify.Tests/ImzaKit.Verify.Tests.csproj`

Expected: PASS.

Run: `dotnet test ImzaKit.slnx -c Release --no-restore`

Expected: every existing and new test PASS; changed signed bytes remain `Failed` in both overloads.

- [ ] **Step 5: Commit PAdES trust orchestration**

```powershell
git add src/ImzaKit.Verify tests/ImzaKit.Verify.Tests
git commit -m "feat: orchestrate offline trust validation for pades"
```

### Task 10: Dependency injection registration and resolution tests

**Files:**
- Modify: `src/ImzaKit.DependencyInjection/ImzaKit.DependencyInjection.csproj`
- Modify: `src/ImzaKit.DependencyInjection/ImzaKitServiceCollectionExtensions.cs`
- Create: `tests/ImzaKit.Api.Tests/DependencyInjection/ValidationServiceRegistrationTests.cs`

**Interfaces:**
- Consumes: all interfaces and default implementations from Tasks 2, 3, 5, 7, and 9.
- Produces: singleton registrations for stateless certificate/trust/revocation/decision services and transient `IPadesValidationService`.

- [ ] **Step 1: Write the failing DI resolution test**

```csharp
[Fact]
public void AddImzaKitCoreResolvesOfflineValidationGraph()
{
    ServiceProvider provider = new ServiceCollection().AddImzaKitCore().BuildServiceProvider(
        new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

    Assert.IsType<PadesValidationService>(provider.GetRequiredService<IPadesValidationService>());
    Assert.IsType<CertificateChainBuilder>(provider.GetRequiredService<ICertificateChainBuilder>());
    Assert.IsType<OfflineRevocationEvaluator>(provider.GetRequiredService<IOfflineRevocationEvaluator>());
}
```

- [ ] **Step 2: Run the DI test and observe failure**

Run: `dotnet test tests/ImzaKit.Api.Tests/ImzaKit.Api.Tests.csproj --filter FullyQualifiedName~ValidationServiceRegistrationTests`

Expected: FAIL because the services are not registered.

- [ ] **Step 3: Add project references and registrations**

Register builder, validator, policy evaluator, BouncyCastle parser, revocation evaluator, and decision engine as singleton stateless services. Register `IPadesValidationService` as transient so its graph is resolved through DI; keep trust snapshots and validation contexts call-scoped and outside the container.

- [ ] **Step 4: Run DI and solution tests**

Run: `dotnet test tests/ImzaKit.Api.Tests/ImzaKit.Api.Tests.csproj`

Expected: PASS.

Run: `dotnet test ImzaKit.slnx -c Release --no-restore`

Expected: all tests PASS.

- [ ] **Step 5: Commit registrations**

```powershell
git add src/ImzaKit.DependencyInjection tests/ImzaKit.Api.Tests/DependencyInjection
git commit -m "feat: register offline validation services"
```

### Task 11: Single-package expansion and package smoke verification

**Files:**
- Modify: `Directory.Build.props`
- Modify: `packaging/ImzaKit/ImzaKit.csproj`
- Modify: `tests/ImzaKit.PackageSmoke/ImzaKit.PackageSmoke.csproj`
- Modify: `tests/ImzaKit.PackageSmoke/Program.cs`
- Modify: `scripts/verify-nuget-package.ps1`
- Create: `tests/ImzaKit.Verify.Tests/Packaging/PublicApiCompatibilityTests.cs`

**Interfaces:**
- Consumes: the 12 production assemblies and public validation APIs.
- Produces: `ImzaKit.1.0.0-alpha.4.nupkg` containing all 12 DLL/PDB pairs and no internal package dependency group.

- [ ] **Step 1: Update package contract tests first and observe alpha.3/9-DLL failure**

Add `ImzaKit.Certificate.dll`, `ImzaKit.Trust.dll`, and `ImzaKit.Revocation.dll` to the expected list in `verify-nuget-package.ps1`; assert exactly 12 ImzaKit DLLs, the package version `1.0.0-alpha.4`, and no dependency whose ID starts with `ImzaKit.`. Update package smoke code to instantiate `TrustStoreSnapshot`, create a `ValidationContext`, and call the new static overload.

Run: `dotnet build ImzaKit.slnx -c Release; dotnet pack packaging/ImzaKit/ImzaKit.csproj -c Release --no-build -o artifacts/packages; ./scripts/verify-nuget-package.ps1 -PackagePath artifacts/packages/ImzaKit.1.0.0-alpha.4.nupkg`

Expected: FAIL because version and packaging project still describe alpha.3 and nine module assemblies.

- [ ] **Step 2: Add the three production project references and package outputs**

Add each new project to `packaging/ImzaKit/ImzaKit.csproj` with `PrivateAssets="all"`, include its DLL in `IncludeProjectAssemblies`, include its PDB in `IncludeProjectSymbols`, and update `Directory.Build.props` to `1.0.0-alpha.4`.

- [ ] **Step 3: Add public API compatibility reflection tests**

```csharp
[Fact]
public void LegacyPadesValidatorAndReportConstructorRemainPublic()
{
    Assert.NotNull(typeof(PadesValidator).GetMethod("Validate", [typeof(ReadOnlySpan<byte>)]));
    Assert.Contains(typeof(PadesValidationReport).GetConstructors(), constructor =>
        constructor.GetParameters().Length == 6);
}
```

If reflection cannot directly bind `ReadOnlySpan<byte>`, identify the overload by name and a single parameter whose `ParameterType == typeof(ReadOnlySpan<byte>)`.

- [ ] **Step 4: Build, pack, verify, and run smoke consumption from the package**

Run: `dotnet build ImzaKit.slnx -c Release`

Expected: PASS with 0 warnings and 0 errors.

Run: `dotnet pack packaging/ImzaKit/ImzaKit.csproj -c Release --no-build -o artifacts/packages`

Expected: creates `.nupkg` and `.snupkg` for `1.0.0-alpha.4`.

Run: `./scripts/verify-nuget-package.ps1 -PackagePath artifacts/packages/ImzaKit.1.0.0-alpha.4.nupkg`

Expected: PASS with exactly 12 ImzaKit DLLs and zero internal package dependencies.

Run: `dotnet run --project tests/ImzaKit.PackageSmoke/ImzaKit.PackageSmoke.csproj -c Release`

Expected: exits 0 after compiling and exercising the packaged public APIs.

- [ ] **Step 5: Commit packaging changes**

```powershell
git add Directory.Build.props packaging/ImzaKit tests/ImzaKit.PackageSmoke scripts/verify-nuget-package.ps1 tests/ImzaKit.Verify.Tests/Packaging
git commit -m "build: package alpha.4 offline validation modules"
```

### Task 12: Bilingual documentation, FRD traceability, and live status report

**Files:**
- Modify: `README.md`
- Modify: `docs/imzakit-teknik-kullanim-rehberi.html`
- Modify: `site/index.html`
- Modify: `reports/imzakit-gelistirme-durum.html`
- Modify: `frd/ekler/gereksinim-izlenebilirlik-matrisi.md`
- Modify: `scripts/verify-technical-guide.ps1`
- Modify: `scripts/verify-landing-page.ps1`
- Modify: `scripts/validate-frd.ps1`

**Interfaces:**
- Consumes: finalized Alpha.4 public API names and package version.
- Produces: Turkish/English install and offline-validation examples, explicit offline/security limitations, 12-module inventory, and FRD evidence links.

- [ ] **Step 1: Extend documentation verification scripts before editing content**

Require these exact tokens in the relevant artifacts: `1.0.0-alpha.4`, `ValidationContext`, `GeneralX509`, `TurkiyeNes`, `RevocationDataUnavailable`, `ImzaKit.Certificate`, `ImzaKit.Trust`, `ImzaKit.Revocation`, and `12`. Require both Turkish headings (`Çevrimdışı güven doğrulaması`, `Sınırlamalar`) and English headings (`Offline trust validation`, `Limitations`).

Run: `./scripts/verify-technical-guide.ps1; ./scripts/verify-landing-page.ps1; ./scripts/validate-frd.ps1`

Expected: FAIL because Alpha.4 content and traceability are not yet present.

- [ ] **Step 2: Update bilingual README and interactive technical guide**

Add a complete C# example that constructs versioned trust/policy inputs, passes embedded/local evidence, calls `PadesValidator.Validate(pdf, context)`, and switches on `ValidationStatus`. State that no system trust store or network endpoint is used and that trusted distribution of snapshots is the caller's responsibility in Alpha.4.

- [ ] **Step 3: Update landing page, status report, and FRD matrix**

Add the three modules to the landing-page filter/cards, update the package badge/version and module count, mark the Alpha.4 offline trust slice complete in the live report only after all implementation tests pass, and link the relevant FRD requirements to certificate/trust/revocation test suites and the package verification evidence.

- [ ] **Step 4: Run every documentation and repository verification gate**

Run: `./scripts/verify-technical-guide.ps1`

Expected: PASS.

Run: `./scripts/verify-landing-page.ps1`

Expected: PASS.

Run: `./scripts/validate-frd.ps1`

Expected: PASS.

Run: `./scripts/verify-open-source-readiness.ps1`

Expected: PASS.

- [ ] **Step 5: Commit documentation and traceability**

```powershell
git add README.md docs/imzakit-teknik-kullanim-rehberi.html site/index.html reports/imzakit-gelistirme-durum.html frd/ekler/gereksinim-izlenebilirlik-matrisi.md scripts
git commit -m "docs: document alpha.4 offline trust validation"
```

### Task 13: Final Alpha.4 verification and evidence capture

**Files:**
- Create: `docs/evidence/alpha4-offline-trust-validation-2026-08-23.md`
- Modify: `reports/imzakit-gelistirme-durum.html` only if final measured counts differ from Task 12.

**Interfaces:**
- Consumes: complete Alpha.4 implementation.
- Produces: reproducible command/output summary, final test count, package hash, 12-DLL inventory, and explicit statement that publishing was not performed.

- [ ] **Step 1: Start from a clean build output and run release verification**

Run: `dotnet clean ImzaKit.slnx -c Release`

Expected: PASS.

Run: `dotnet restore ImzaKit.slnx; dotnet build ImzaKit.slnx -c Release --no-restore; dotnet test ImzaKit.slnx -c Release --no-build --logger "console;verbosity=normal"`

Expected: restore/build/test all PASS; build reports 0 warnings and 0 errors.

- [ ] **Step 2: Recreate and verify the package**

Run: `dotnet pack packaging/ImzaKit/ImzaKit.csproj -c Release --no-build -o artifacts/packages; ./scripts/verify-nuget-package.ps1 -PackagePath artifacts/packages/ImzaKit.1.0.0-alpha.4.nupkg`

Expected: PASS; package contains 12 production assemblies and zero internal package dependencies.

- [ ] **Step 3: Run security, FRD, site, workflow, and documentation gates**

Run: `./scripts/validate-frd.ps1; ./scripts/verify-technical-guide.ps1; ./scripts/verify-landing-page.ps1; ./scripts/verify-open-source-readiness.ps1; ./scripts/verify-pages-workflow.ps1; ./scripts/verify-publish-workflow.ps1`

Expected: every script PASS.

- [ ] **Step 4: Record evidence from actual outputs**

Write the exact commands, UTC timestamp, passed/failed/skipped test totals, package filename and SHA-256, DLL inventory, documentation gate results, and `git status --short` output to `docs/evidence/alpha4-offline-trust-validation-2026-08-23.md`. Do not claim NuGet publication; state that release requires a separate approval and Trusted Publishing run.

- [ ] **Step 5: Commit final evidence**

```powershell
git add docs/evidence/alpha4-offline-trust-validation-2026-08-23.md reports/imzakit-gelistirme-durum.html
git commit -m "test: record alpha.4 verification evidence"
```

- [ ] **Step 6: Confirm final repository state**

Run: `git status --short; git log -13 --oneline`

Expected: no Alpha.4 implementation files are uncommitted. Pre-existing unrelated user changes, if any, remain visible and untouched.
