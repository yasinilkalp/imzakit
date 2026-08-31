# WinUI Masaüstü İmza İstemcisi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Paket dışı Windows host ile PDF seç–CredUI PIN–PAdES B-B–yerel `{ad}-imzali.pdf` bağlantısı üretmek; `setup.exe` yerleşimi ve sitede Releases vitrini.

**Architecture:** İmza mantığı `ImzaKit.Hosts.Desktop` (`net10.0`, Linux CI’de derlenir) içindedir. WinUI 3 kabuğu `ImzaKit.Hosts.Desktop.App` Windows’ta `WinExe`, Ubuntu’da boş kütüphane yer tutucudur. Agent/API/bilet yoktur; `InProcessPadesSigningOrchestrator` + CredUI + PKCS#11 allowlist kullanılır.

**Tech Stack:** .NET 10, WinUI 3 / Windows App SDK (Windows), xUnit, mevcut ImzaKit SDK, WiX kaynak üretici, GitHub Releases href.

## Global Constraints

- NuGet paketi 16 DLL kalır; `ImzaKit.Hosts.Desktop` ve `.App` `IsPackable=false`.
- PIN yalnız `INativePinPrompt` / CredUI; WinUI `PasswordBox` yok.
- Vendor `akisp11.dll` / `eTPKCS11.dll` installer ve site ikilisinde yok.
- Authenticode yoksa Desktop installer yayımlanmaz.
- `site/` içinde `.exe` yok; indirme `https://github.com/yasinilkalp/imzakit/releases/latest`.
- MVP Agent/AKİS kapısı değişmez.
- Ubuntu `dotnet test ImzaKit.slnx` kırılmaz.

---

### Task 1: SignedPdfOutput

**Files:**
- Create: `src/ImzaKit.Hosts.Desktop/ImzaKit.Hosts.Desktop.csproj`
- Create: `src/ImzaKit.Hosts.Desktop/Signing/SignedPdfOutput.cs`
- Create: `tests/ImzaKit.Desktop.Tests/ImzaKit.Desktop.Tests.csproj`
- Create: `tests/ImzaKit.Desktop.Tests/Signing/SignedPdfOutputTests.cs`
- Modify: `ImzaKit.slnx`

**Interfaces:**
- Produces: `SignedPdfOutput.Write(string originalPdfPath, byte[] signedPdf) -> string`

- [x] Failing test: `{stem}-imzali.pdf`, collision `-2`, write failure leaves no partial file
- [x] Implement `Write` with exclusive create
- [x] `dotnet test tests/ImzaKit.Desktop.Tests`

### Task 2: TokenCertificateCatalog

**Files:**
- Create: `src/ImzaKit.Hosts.Desktop/Pkcs11/DesktopCertificateItem.cs`
- Create: `src/ImzaKit.Hosts.Desktop/Pkcs11/TokenCertificateCatalog.cs`
- Create: `tests/ImzaKit.Desktop.Tests/Pkcs11/TokenCertificateCatalogTests.cs`

**Interfaces:**
- Produces: `TokenCertificateCatalog.List(IEnumerable<IPkcs11Provider>) -> IReadOnlyList<DesktopCertificateItem>`
- `DesktopCertificateItem(string ProviderName, ulong SlotId, Pkcs11Certificate Certificate, string Subject)`

- [x] Empty providers / discover throws → empty list, no throw
- [x] Session FindCertificates without login
- [x] Implement catalog with try/finally CloseSession + Finalize

### Task 3: DesktopPadesSigner

**Files:**
- Create: `src/ImzaKit.Hosts.Desktop/Signing/DesktopSignOutcome.cs`
- Create: `src/ImzaKit.Hosts.Desktop/Signing/DesktopPadesSigner.cs`
- Create: `tests/ImzaKit.Desktop.Tests/Signing/DesktopPadesSignerTests.cs`

**Interfaces:**
- Consumes: `InProcessPadesSigningOrchestrator`, `INativePinPrompt`
- Produces: `DesktopSignOutcome` (`Cancelled`, `Failed(string code, string message)`, `Succeeded(byte[] pdf, PadesValidationReport report)`)
- `DesktopPadesSigner.Sign(byte[] originalPdf, DesktopCertificateItem certificate)`

- [x] Cancelled when Acquire returns null
- [x] PinIncorrect mapped from PKCS#11
- [x] Fake PKCS#11 PAdES B-B like in-process flow
- [x] PIN cleared via NativePinSession.Dispose

### Task 4: SignSessionViewModel

**Files:**
- Create: `src/ImzaKit.Hosts.Desktop/Session/SignSessionState.cs`
- Create: `src/ImzaKit.Hosts.Desktop/Session/SignSessionViewModel.cs`
- Create: `tests/ImzaKit.Desktop.Tests/Session/SignSessionViewModelTests.cs`

**Interfaces:**
- `SelectPdf(string path)`, `RefreshCertificates()`, `Sign()`, `SaveSignedPdf(string path)`
- Properties: State, FilePath, DocumentSha256, Certificates, SelectedCertificate, ErrorCode, ErrorMessage, OutputPath, TrustWarning, CanSign, SignedPdf

- [x] Non-pdf / preflight fail → Error, CanSign false
- [x] Sign while Signing is no-op
- [x] Crypto Failed → no OutputPath
- [x] Write fail keeps SignedPdf for SaveSignedPdf

### Task 5: Installer + Authenticode policy

**Files:**
- Create: `packaging/ImzaKit.Release/Installer/DesktopInstallerLayout.cs`
- Modify: `packaging/ImzaKit.Release/Installer/AuthenticodeAndMsi.cs`
- Modify: `packaging/ImzaKit.Release/Signing/ReleaseSigningPolicy.cs`
- Create: `tests/ImzaKit.Release.Tests/Installer/DesktopInstallerAndUpdateTests.cs`
- Modify: `tests/ImzaKit.Release.Tests/Signing/ReleaseSigningPolicyTests.cs`

**Interfaces:**
- `DesktopInstallerPayload` install dir `%ProgramFiles%\ImzaKit\Desktop`, RIDs `win-x64`/`win-arm64`, AuthenticodeRequired true
- `ReleaseArtifactKind.DesktopPeOrInstaller` same Authenticode gate as Agent
- `DesktopMsiDocument.CreateWixSource`

### Task 6: WinUI shell

**Files:**
- Create: `src/ImzaKit.Hosts.Desktop.App/ImzaKit.Hosts.Desktop.App.csproj`
- Create: `src/ImzaKit.Hosts.Desktop.App/App.xaml` + `App.xaml.cs`
- Create: `src/ImzaKit.Hosts.Desktop.App/MainWindow.xaml` + `MainWindow.xaml.cs`
- Create: `src/ImzaKit.Hosts.Desktop.App/app.manifest`
- Create: `src/ImzaKit.Hosts.Desktop.App/NonWindowsPlaceholder.cs`
- Modify: `Directory.Packages.props` (WindowsAppSDK, Windows SDK BuildTools)

Four blocks: file, certificates, Sign, result hyperlink + folder. PIN is CredUI only.

### Task 7: Site + landing verification

**Files:**
- Modify: `site/index.html`
- Modify: `scripts/verify-landing-page.ps1`

Required copy: Windows uygulaması, setup.exe, Releases/latest, TR/EN, no `.exe` under `site/`.

### Task 8: Solution wiring

**Files:**
- Modify: `ImzaKit.slnx`
- Modify: `README.md` (Desktop not in NuGet, one sentence)

Verify: `dotnet test ImzaKit.slnx -c Release` and `powershell -File scripts/validate-frd.ps1` and `scripts/verify-landing-page.ps1`.
