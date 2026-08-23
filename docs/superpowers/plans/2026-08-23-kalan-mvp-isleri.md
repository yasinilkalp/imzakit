# Remaining MVP Work Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the locally implementable İmzaKit MVP path from hostile-PDF preflight through Verify, PKCS#11 contracts, Agent ticket security, API operation state, and an in-process end-to-end signing flow.

**Architecture:** Preserve the current prepare/external-sign/complete boundary. Add each subsystem behind small contracts and keep hardware, network, storage, and UI at adapters; deterministic in-memory implementations prove the flow without pretending to provide real AKİS hardware evidence.

**Tech Stack:** .NET 10 LTS, C# 14, xUnit 2.9.3, System.Security.Cryptography, PdfPig 0.1.15 (test only), PDFsharp 6.2.4 and Bouncy Castle 2.7.0 (test only).

**Spec:** `frd/ana-dokuman/imzakit-fonksiyonel-gereksinimler-dokumani.md`, `frd/gereksinimler/fonksiyonel-gereksinimler.md`, ADR-003, ADR-005, ADR-006, and `frd/api-ve-akislar/openapi.yaml`.

## Global Constraints

- Entire product remains Apache-2.0; production dependencies must be permissive-license compatible.
- Primary target is .NET 10 LTS; Agent target is Windows x64/arm64.
- MVP signing profile is PAdES B-B with RSA/SHA-256.
- PIN and private keys never cross the Agent/PKCS#11 boundary.
- Existing PDF bytes must remain byte-for-byte unchanged during incremental signing.
- Every completed slice updates `reports/imzakit-gelistirme-durum.html`.
- Commands use `--tl:off -m:1` in this workspace.
- No real-AKİS success claim is made without a physical reference card.

---

### Task 1: PDF Preflight and Explicit Support Matrix

**Files:**
- Create: `src/ImzaKit.PAdES/Preflight/PdfSigningPreflight.cs`
- Create: `src/ImzaKit.PAdES/Preflight/PdfPreflightLimits.cs`
- Create: `src/ImzaKit.PAdES/Preflight/PdfPreflightException.cs`
- Modify: `src/ImzaKit.PAdES/Incremental/PdfIncrementalSignatureWriter.cs`
- Test: `tests/ImzaKit.PAdES.Tests/Preflight/PdfSigningPreflightTests.cs`

**Interfaces:**
- Produces: `PdfSigningPreflight.Validate(ReadOnlySpan<byte> pdf, PdfPreflightLimits limits)`.
- Produces error codes `PdfTooLarge`, `UnsupportedVersion`, `Encrypted`, `XrefStream`, `ObjectStream`, `HybridReference`, `ExistingAcroForm`, `TooManyObjects`, `TooManyRevisions`.
- `PdfIncrementalSignatureWriter.Prepare` calls preflight before allocating output.

- [x] Write failing tests for size, version, encryption, xref/object streams, AcroForm, object count, and revision count.
- [x] Run `dotnet test tests/ImzaKit.PAdES.Tests/ImzaKit.PAdES.Tests.csproj -c Release --no-restore --tl:off -m:1 --filter FullyQualifiedName~PdfSigningPreflightTests` and confirm RED.
- [x] Implement byte-bounded token scanning; default limits are 32 MiB, 100,000 objects, and 32 revisions.
- [x] Run the focused tests and the full PAdES suite; confirm GREEN.
- [x] Update ADR-005 and the live report.

### Task 2: DocMDP and FieldMDP Policy Inspection

**Files:**
- Create: `src/ImzaKit.PAdES/Policy/PdfModificationPolicy.cs`
- Create: `src/ImzaKit.PAdES/Policy/PdfModificationPolicyInspector.cs`
- Test: `tests/ImzaKit.PAdES.Tests/Policy/PdfModificationPolicyInspectorTests.cs`

**Interfaces:**
- Produces: `PdfModificationPolicyInspector.Inspect(ReadOnlySpan<byte> pdf)` returning certification permission `None`, `NoChanges`, `FormFillAndSign`, or `FormFillSignAndAnnotate`, plus locked field names.
- Signing preparation rejects `NoChanges` and a locked target field with stable machine-readable codes.

- [x] Write failing fixtures for DocMDP `/P 1`, `/P 2`, `/P 3`, and FieldMDP `/Action /All`, `/Include`, `/Exclude`.
- [x] Run the focused tests and confirm RED.
- [x] Implement the classic-object policy reader without rewriting signed bytes.
- [x] Add enforcement to `PadesSignaturePreparer` and run all PAdES tests GREEN.
- [x] Update ADR-005 and the live report.

### Task 3: Basic PAdES Verify Engine

**Files:**
- Create project: `src/ImzaKit.Verify/ImzaKit.Verify.csproj`
- Create: `src/ImzaKit.Verify/Validation/ValidationStatus.cs`
- Create: `src/ImzaKit.Verify/Validation/PadesValidationReport.cs`
- Create: `src/ImzaKit.Verify/Validation/PadesValidator.cs`
- Create project: `tests/ImzaKit.Verify.Tests/ImzaKit.Verify.Tests.csproj`
- Test: `tests/ImzaKit.Verify.Tests/PadesValidatorTests.cs`

**Interfaces:**
- Produces: `PadesValidator.Validate(ReadOnlySpan<byte> pdf)` returning `Passed`, `Failed`, or `Indeterminate`, ByteRange integrity, CMS signature status, signer certificate fingerprint, and machine-readable findings.

- [x] Add projects to `ImzaKit.slnx` and write a failing golden-PDF validation test.
- [x] Write failing mutation tests for changed signed bytes, malformed ByteRange, missing CMS, and unsupported PDF.
- [x] Implement extraction and SignedCms verification; separate structural failure from trust indeterminacy.
- [x] Run Verify tests and the full solution GREEN.
- [x] Update the live report.

### Task 4: PKCS#11 and AKİS Adapter Contracts

**Files:**
- Create project: `src/ImzaKit.Pkcs11/ImzaKit.Pkcs11.csproj`
- Create: `src/ImzaKit.Pkcs11/Abstractions/IPkcs11Provider.cs`
- Create: `src/ImzaKit.Pkcs11/Models/Pkcs11Certificate.cs`
- Create: `src/ImzaKit.Pkcs11/Signing/Pkcs11SigningService.cs`
- Create: `src/ImzaKit.Pkcs11/Akis/AkisProviderProfile.cs`
- Create project: `tests/ImzaKit.Pkcs11.Tests/ImzaKit.Pkcs11.Tests.csproj`
- Test: `tests/ImzaKit.Pkcs11.Tests/Pkcs11SigningServiceTests.cs`

**Interfaces:**
- `IPkcs11Provider` exposes initialize/finalize, slot/token discovery, session/login, certificate/private-key lookup by identical `CKA_ID`, and RSA PKCS#1 SHA-256 signing.
- `Pkcs11SigningService.Sign` never accepts or returns PIN after the provider call boundary.

- [x] Write failing fake-provider tests for lifecycle, CKA_ID matching, wrong PIN, token removal, and unsupported mechanism.
- [x] Implement contract, result codes, and AKİS quirk profile without a vendor binary dependency.
- [x] Run all PKCS#11 tests GREEN.
- [x] Record real-card execution as a separate hardware evidence checklist, not a passing automated test.
- [x] Update the live report.

### Task 5: Agent Ticket and Replay Security Core

**Files:**
- Create project: `src/ImzaKit.Agent/ImzaKit.Agent.csproj`
- Create: `src/ImzaKit.Agent/Security/AgentTicket.cs`
- Create: `src/ImzaKit.Agent/Security/AgentTicketValidator.cs`
- Create: `src/ImzaKit.Agent/Security/INonceStore.cs`
- Create: `src/ImzaKit.Agent/Security/InMemoryNonceStore.cs`
- Create project: `tests/ImzaKit.Agent.Tests/ImzaKit.Agent.Tests.csproj`
- Test: `tests/ImzaKit.Agent.Tests/AgentTicketValidatorTests.cs`

**Interfaces:**
- Ticket binds issuer, audience, origin, operation, tenant, application, document SHA-256, action, nonce, issued-at, and expiry.
- `AgentTicketValidator.ValidateAndConsume` verifies Ed25519, 120-second maximum lifetime, exact origin/digest/action, and atomic single-use nonce.

- [x] Write failing tests for valid ticket, expiry, replay, origin mismatch, digest mismatch, action mismatch, and invalid signature.
- [x] Implement canonical ticket payload and atomic nonce consumption.
- [x] Add loopback endpoint binding configuration limited to `127.0.0.1` and `::1`, with a configuration test.
- [x] Run Agent tests and full solution GREEN.
- [x] Update the live report.

### Task 6: Operation State Machine and Idempotency Core

**Files:**
- Create project: `src/ImzaKit.Api/ImzaKit.Api.csproj`
- Create: `src/ImzaKit.Api/Operations/SignatureOperationState.cs`
- Create: `src/ImzaKit.Api/Operations/SignatureOperation.cs`
- Create: `src/ImzaKit.Api/Operations/SignatureOperationService.cs`
- Create: `src/ImzaKit.Api/Idempotency/IIdempotencyStore.cs`
- Create: `src/ImzaKit.Api/Idempotency/InMemoryIdempotencyStore.cs`
- Create project: `tests/ImzaKit.Api.Tests/ImzaKit.Api.Tests.csproj`
- Test: `tests/ImzaKit.Api.Tests/SignatureOperationServiceTests.cs`

**Interfaces:**
- Implements FRD/OpenAPI states `Created`, `WaitingForClient`, `ClientConnected`, `CertificateSelected`, `Prepared`, `Signing`, `Signed`, `Timestamping`, `Validating`, `Completed`, `Failed`, `Cancelled`, `Expired`.
- Every mutating method requires an idempotency key; same key/same request replays the response, same key/different request conflicts.

- [x] Write failing transition-table and idempotency tests.
- [x] Implement in-memory metadata service with optimistic version checks and terminal-state enforcement.
- [x] Add problem-code mapping for 409/413/422/429/503 semantics without starting external infrastructure.
- [x] Run API tests and full solution GREEN.
- [x] Update the live report.

### Task 7: Dependency Injection and In-Process End-to-End MVP

**Files:**
- Modify: `src/ImzaKit.DependencyInjection/ImzaKit.DependencyInjection.csproj`
- Create: `src/ImzaKit.DependencyInjection/ImzaKitServiceCollectionExtensions.cs`
- Create: `tests/ImzaKit.Api.Tests/InProcessSigningFlowTests.cs`

**Interfaces:**
- Registers digest, CMS, PAdES, Verify, operation, ticket, and fake PKCS#11 adapters through explicit extension methods.
- End-to-end test executes create → bind certificate → prepare → Agent-sign equivalent → complete → Verify.

- [x] Write a failing in-process flow test using the deterministic test key provider.
- [x] Add focused DI registrations and orchestration facade.
- [x] Assert final PDF keeps original bytes and Verify returns `Passed` cryptographically and `Indeterminate` for external trust.
- [x] Run all solution tests GREEN and Release build with zero warnings.
- [x] Update the live report and FRD evidence notes.

### Task 8: Final Evidence and Hardware Boundary

**Files:**
- Create: `docs/evidence/mvp-local-verification-2026-08-23.md`
- Create: `docs/evidence/akis-hardware-checklist.md`
- Modify: `reports/imzakit-gelistirme-durum.html`

**Interfaces:**
- Evidence report records commands, test counts, golden hashes, supported/unsupported PDF matrix, and explicit external blockers.

- [x] Run full tests, Release build, FRD validation, and package-license inventory.
- [x] Record locally proven requirements and remaining physical-card/installer/mTLS infrastructure evidence separately.
- [x] Ensure the status report never labels hardware-only evidence complete without a real AKİS run.
- [x] Perform placeholder, type-consistency, and requirement-coverage review of this plan and evidence.
