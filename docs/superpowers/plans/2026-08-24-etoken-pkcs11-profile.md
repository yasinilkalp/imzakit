# eToken PKCS#11 Profili Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** AKİS’ten sonra ikinci doğrulanmış Windows PKCS#11 profili olarak eToken (`eTPKCS11.dll`) eklemek; FR-030’u FRD’ye yazmak; fiziksel token olmadan donanım kabulü iddia etmemek.

**Architecture:** Vendor farkı `EtokenProviderProfile` + `ForEtoken()` içinde kalır. Loader seçilen profilin dosya adlarını alır; allowlist profil başına uygulanır. `NativePkcs11Provider` ve hata kodları değişmez.

**Tech Stack:** .NET 10, mevcut `ImzaKit.Pkcs11` / `ImzaKit.Release`, xUnit, FRD markdown, PowerShell laboratuvar script’i.

## Global Constraints

- `eTPKCS11.dll` NuGet ve MSI içinde yoktur.
- Desteklenen ad yalnız `eTPKCS11.dll`; `eToken.dll` yok; `System32` varsayılan kök değildir.
- Quirk’ler `ForAkis()` ile aynı başlar; spekülatif sapma yok.
- PIN HTTP/CLI/log/audit’e girmez; gerçek CredUI testte açılmaz.
- `FR-028` metni “ilk = AKİS” olarak kalır; `FR-030` MVP = Hayır.
- FRD’de `TBD` / `TODO` yok; tanım `- **FR-030:**` biçiminde.
- Paket hâlâ 12 `ImzaKit.*` DLL. Fiziksel eToken yokken donanım başarısı yazılmaz.
- Commit yalnız kullanıcı isterse.

---

### Task 1: FRD FR-030

**Files:**
- Modify: `frd/gereksinimler/fonksiyonel-gereksinimler.md`
- Modify: `frd/ekler/gereksinim-izlenebilirlik-matrisi.md`
- Modify: `frd/ekler/terimler-sozlugu.md`
- Modify: `frd/ana-dokuman/imzakit-fonksiyonel-gereksinimler-dokumani.md`
- Modify: `frd/mimari/sistem-mimarisi.md`
- Modify: `frd/planlama/mvp-ve-fazlandirma.md`
- Modify: `frd/test-ve-kabul/test-ve-kabul-stratejisi.md`

**Interfaces:**
- Consumes: mevcut FR numaralandırması ve `validate-frd.ps1`
- Produces: `FR-030`, `TST-021`

- [ ] **Step 1: FR-030 tanımını ve sınıflandırma satırını ekle**

`frd/gereksinimler/fonksiyonel-gereksinimler.md` sınıflandırma tablosuna Agent/AKİS satırının altına:

```markdown
| Agent/eToken | FR-030 | Yüksek | 1 | Hayır |
```

PKCS#11 bölümünde FR-029’dan sonra:

```markdown
- **FR-030:** İkinci doğrulanmış Windows PKCS#11 profili eToken olmalıdır. Modül adı yalnız `eTPKCS11.dll` kabul edilmeli; varsayılan allowlist kökleri SafeNet Authentication Client `SAC\x64` ve Thales SafeNet Authentication Client `Program Files` yolları olmalıdır. Vendor DLL paketlenmemelidir. Quirk’ler `EtokenProviderProfile` içinde tutulmalı ve AKİS ile aynı güvenli varsayılanlarla başlamalıdır. Fiziksel eToken kabulü ayrı laboratuvar kanıtıdır; MVP çıkış kapısını değiştirmez.
```

FR-028 satırını değiştirme.

- [ ] **Step 2: Matris, terim, mimari, faz, test**

Matrise FR-029’dan sonra:

```markdown
| FR-030 | eToken PKCS#11 profili | Yüksek | 1 | Pkcs11 | ADR-003 | TST-021 | eToken profil birim testi ve laboratuvar listesi | Hayır |
```

Sözlüğe alfabetik sırada:

```markdown
| eToken | SafeNet/Thales USB token PKCS#11 ekosistemi; Windows modülü `eTPKCS11.dll` |
| eTPKCS11 | eToken PKCS#11 native kütüphane dosya adı |
```

Ana doküman 4.1: `PKCS#11; ilk doğrulanmış adaptör olarak AKİS, ikinci doğrulanmış Windows profili olarak eToken (`eTPKCS11.dll`)`

Mimari diyagram: `A --> P11[PKCS#11 / AKİS / eToken]`

Faz 1 madde listesine: `Windows Agent + AKİS + eToken profili + native onay/PIN` (çıkış kapısı cümlesi KamuSM/AKİS kartı olarak kalsın).

Faz 5: `Ek PKCS#11 vendor profilleri` maddesini `eToken dışında ek PKCS#11 vendor profilleri` yap.

TST listesine:

```markdown
- **TST-021:** eToken profil sözleşmesi, `eTPKCS11.dll` allowlist, sahte native imza; fiziksel token laboratuvar listesi CI’yi durdurmaz.
```

Entegrasyon maddesine “gerçek eToken tokenı (laboratuvar)” ekle; MVP kapısı maddesine AKİS kartı bırak.

- [ ] **Step 3: FRD doğrula**

Run: `pwsh -File scripts/validate-frd.ps1`

Expected: exit 0. `TBD`/`TODO` yok. `FR-030` hem kaynakta hem matriste.

---

### Task 2: EtokenProviderProfile (TDD)

**Files:**
- Create: `tests/ImzaKit.Pkcs11.Tests/Etoken/EtokenProviderProfileTests.cs`
- Create: `src/ImzaKit.Pkcs11/Etoken/EtokenProviderProfile.cs`
- Modify: `src/ImzaKit.Pkcs11/Native/NativePkcs11ProviderOptions.cs`

**Interfaces:**
- Consumes: `AkisProviderProfile` alan adları
- Produces: `EtokenProviderProfile`, `NativePkcs11ProviderOptions.ForEtoken()`

- [ ] **Step 1: Failing test**

```csharp
using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Etoken;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Etoken;

public sealed class EtokenProviderProfileTests
{
    [Fact]
    public void CapturesSecondVerifiedWindowsProviderContract()
    {
        Assert.Equal("eToken", EtokenProviderProfile.Name);
        Assert.Equal("CKM_SHA256_RSA_PKCS", EtokenProviderProfile.SigningMechanism);
        Assert.True(EtokenProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.True(EtokenProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(AkisProviderProfile.MatchPrivateKeyByCkaIdFirst, EtokenProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(AkisProviderProfile.RequiresSingleThreadedProviderAccess, EtokenProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(["eTPKCS11.dll"], EtokenProviderProfile.SupportedLibraryFileNames);
        Assert.DoesNotContain("eToken.dll", EtokenProviderProfile.SupportedLibraryFileNames, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(@"%ProgramFiles%\SafeNet\Authentication\SAC\x64", EtokenProviderProfile.RecommendedAllowlistRoots);
        Assert.Contains(@"%ProgramFiles%\Thales\SafeNet Authentication Client", EtokenProviderProfile.RecommendedAllowlistRoots);
        Assert.DoesNotContain(EtokenProviderProfile.RecommendedAllowlistRoots, root =>
            root.Contains("System32", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ForEtokenMatchesAkisSafeDefaults()
    {
        NativePkcs11ProviderOptions etoken = NativePkcs11ProviderOptions.ForEtoken();
        NativePkcs11ProviderOptions akis = NativePkcs11ProviderOptions.ForAkis();
        Assert.Equal(akis.RequiresSingleThreadedProviderAccess, etoken.RequiresSingleThreadedProviderAccess);
        Assert.Equal(akis.MatchPrivateKeyByCkaIdFirst, etoken.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(akis.AllowPublicKeyFallback, etoken.AllowPublicKeyFallback);
        Assert.Equal(akis.ExcludeCertificatesWithoutSignableKey, etoken.ExcludeCertificatesWithoutSignableKey);
    }
}
```

- [ ] **Step 2: Run failing test**

Run: `dotnet test tests/ImzaKit.Pkcs11.Tests/ImzaKit.Pkcs11.Tests.csproj -c Release --filter FullyQualifiedName~EtokenProviderProfileTests --nologo --tl:off`

Expected: FAIL (type not found).

- [ ] **Step 3: Minimal implementation**

```csharp
namespace ImzaKit.Pkcs11.Etoken;

public sealed record EtokenProviderProfile
{
    public static string Name => "eToken";
    public static string SigningMechanism => "CKM_SHA256_RSA_PKCS";
    public static bool MatchPrivateKeyByCkaIdFirst => true;
    public static bool RequiresSingleThreadedProviderAccess => true;
    public static IReadOnlyList<string> SupportedLibraryFileNames { get; } = ["eTPKCS11.dll"];
    public static IReadOnlyList<string> RecommendedAllowlistRoots { get; } =
    [
        @"%ProgramFiles%\SafeNet\Authentication\SAC\x64",
        @"%ProgramFiles%\Thales\SafeNet Authentication Client"
    ];
}
```

`NativePkcs11ProviderOptions.ForEtoken()`:

```csharp
using ImzaKit.Pkcs11.Etoken;

public static NativePkcs11ProviderOptions ForEtoken() => new()
{
    RequiresSingleThreadedProviderAccess = EtokenProviderProfile.RequiresSingleThreadedProviderAccess,
    MatchPrivateKeyByCkaIdFirst = EtokenProviderProfile.MatchPrivateKeyByCkaIdFirst,
    AllowPublicKeyFallback = true,
    ExcludeCertificatesWithoutSignableKey = true
};
```

- [ ] **Step 4: Run passing test**

Run: `dotnet test tests/ImzaKit.Pkcs11.Tests/ImzaKit.Pkcs11.Tests.csproj -c Release --filter FullyQualifiedName~EtokenProviderProfileTests --nologo --tl:off`

Expected: PASS.

---

### Task 3: Loader allowlist (TDD)

**Files:**
- Modify: `tests/ImzaKit.Pkcs11.Tests/Native/Pkcs11ModulePathTests.cs`
- Modify: `src/ImzaKit.Pkcs11/Native/Pkcs11NativeLibraryLoader.cs`

**Interfaces:**
- Consumes: `Pkcs11ModulePath.ResolveAllowed`, `EtokenProviderProfile.SupportedLibraryFileNames`
- Produces: `Pkcs11NativeLibraryLoader.Load(path, roots, allowedFileNames)`

- [ ] **Step 1: Failing tests**

Mevcut `Pkcs11ModulePathTests` sonuna:

```csharp
[Fact]
public void AllowlistedEtokenModulePathIsNormalized()
{
    string allowed = CreateTempDirectory();
    string path = Path.Combine(allowed, "SAC", "eTPKCS11.dll");
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    File.WriteAllBytes(path, [1]);

    try
    {
        string resolved = Pkcs11ModulePath.ResolveAllowed(
            path, [allowed], EtokenProviderProfile.SupportedLibraryFileNames);
        Assert.Equal(Path.GetFullPath(path), resolved);
    }
    finally
    {
        Directory.Delete(allowed, true);
    }
}

[Fact]
public void LegacyEtokenDllNameIsRejected()
{
    string allowed = CreateTempDirectory();
    string path = Path.Combine(allowed, "eToken.dll");
    File.WriteAllBytes(path, [1]);

    try
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            Pkcs11ModulePath.ResolveAllowed(path, [allowed], EtokenProviderProfile.SupportedLibraryFileNames));
        Assert.Contains("file name", exception.Message, StringComparison.OrdinalIgnoreCase);
    }
    finally
    {
        Directory.Delete(allowed, true);
    }
}

[Fact]
public void AkisFileNameIsRejectedOnEtokenAllowlist()
{
    string allowed = CreateTempDirectory();
    string path = Path.Combine(allowed, "akisp11.dll");
    File.WriteAllBytes(path, [1]);

    try
    {
        Assert.Throws<ArgumentException>(() =>
            Pkcs11ModulePath.ResolveAllowed(path, [allowed], EtokenProviderProfile.SupportedLibraryFileNames));
    }
    finally
    {
        Directory.Delete(allowed, true);
    }
}
```

`using ImzaKit.Pkcs11.Etoken;` ekle.

- [ ] **Step 2: Run path tests**

Run: `dotnet test tests/ImzaKit.Pkcs11.Tests/ImzaKit.Pkcs11.Tests.csproj -c Release --filter FullyQualifiedName~Pkcs11ModulePathTests --nologo --tl:off`

Expected: yeni testler FAIL veya mevcut ResolveAllowed zaten genel olduğu için PASS. Loader overload hâlâ yoksa bir loader testi ekle:

```csharp
[Fact]
public void LoaderRequiresExplicitFileNameListForNonAkisModules()
{
    // Compile-time: three-parameter overload must exist.
    var method = typeof(Pkcs11NativeLibraryLoader).GetMethod(
        nameof(Pkcs11NativeLibraryLoader.Load),
        [typeof(string), typeof(IReadOnlyList<string>), typeof(IReadOnlyList<string>)]);
    Assert.NotNull(method);
}
```

Bu reflection testi overload yokken FAIL eder.

- [ ] **Step 3: Loader overload**

```csharp
public static IPkcs11NativeApi Load(string path, IReadOnlyList<string> allowedDirectoryRoots) =>
    Load(path, allowedDirectoryRoots, AkisProviderProfile.SupportedLibraryFileNames);

public static IPkcs11NativeApi Load(
    string path,
    IReadOnlyList<string> allowedDirectoryRoots,
    IReadOnlyList<string> allowedFileNames)
{
    string resolved = Pkcs11ModulePath.ResolveAllowed(path, allowedDirectoryRoots, allowedFileNames);
    // mevcut NativeLibrary.Load gövdesi
}
```

- [ ] **Step 4: Re-run PKCS#11 tests**

Run: `dotnet test tests/ImzaKit.Pkcs11.Tests/ImzaKit.Pkcs11.Tests.csproj -c Release --nologo --tl:off`

Expected: PASS.

---

### Task 4: ForEtoken native provider + installer

**Files:**
- Modify: `tests/ImzaKit.Pkcs11.Tests/Native/NativePkcs11ProviderTests.cs`
- Modify: `packaging/ImzaKit.Release/Installer/AgentInstallerLayout.cs`
- Modify: `packaging/ImzaKit.Release/Installer/AuthenticodeAndMsi.cs`
- Modify: `tests/ImzaKit.Release.Tests/Installer/AgentInstallerAndUpdateTests.cs`
- Modify: `tests/ImzaKit.Release.Tests/Installer/AuthenticodeAndMsiLayoutTests.cs`

**Interfaces:**
- Consumes: `ForEtoken()`, `EtokenProviderProfile.RecommendedAllowlistRoots`
- Produces: `AgentInstallerPayload.EtokenPkcs11AllowlistRoots`

- [ ] **Step 1: Provider testi**

`NativePkcs11ProviderTests` içine:

```csharp
[Fact]
public void EtokenOptionsUseSingleThreadedAccessLikeAkis()
{
    FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
    api.CallDelay = TimeSpan.FromMilliseconds(10);
    using NativePkcs11Provider provider = new(api, NativePkcs11ProviderOptions.ForEtoken());
    provider.Initialize();
    Parallel.For(0, 8, _ => provider.DiscoverTokens());
    Assert.Equal(1, api.MaxConcurrentCalls);
}
```

- [ ] **Step 2: Payload alanı**

`AgentInstallerPayload` kaydına `IReadOnlyList<string> EtokenPkcs11AllowlistRoots` ekle.

`Create` içinde:

```csharp
EtokenPkcs11AllowlistRoots: EtokenProviderProfile.RecommendedAllowlistRoots,
```

`packaging/ImzaKit.Release` projesinin `ImzaKit.Pkcs11` referansı yoksa kök şablonlarını layout’ta tekrarlama (Release’in Pkcs11’e bağlanması tek paket sözleşmesini bozmaz; Release paketlenmez). Referans yoksa aynı iki string’i layout’ta kopyala ve testte profil ile karşılaştır.

WiX:

```csharp
xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="Pkcs11AllowlistRoots" Value="{string.Join(';', payload.Pkcs11AllowlistRoots)}" />""");
xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="EtokenPkcs11AllowlistRoots" Value="{string.Join(';', payload.EtokenPkcs11AllowlistRoots)}" />""");
```

- [ ] **Step 3: Installer testleri**

```csharp
Assert.Contains(@"%ProgramFiles%\AKIS", payload.Pkcs11AllowlistRoots);
Assert.DoesNotContain(payload.Pkcs11AllowlistRoots, root =>
    root.Contains("SafeNet", StringComparison.OrdinalIgnoreCase));
Assert.Equal(EtokenProviderProfile.RecommendedAllowlistRoots, payload.EtokenPkcs11AllowlistRoots);
Assert.DoesNotContain(payload.Files, file => file.Contains("etpkcs11", StringComparison.OrdinalIgnoreCase));
```

Wix testi:

```csharp
Assert.Contains(@"SafeNet\Authentication\SAC\x64", wxs, StringComparison.Ordinal);
Assert.Contains(@"Thales\SafeNet Authentication Client", wxs, StringComparison.Ordinal);
Assert.DoesNotContain("akisp11", wxs, StringComparison.OrdinalIgnoreCase);
Assert.DoesNotContain("etpkcs11.dll", wxs, StringComparison.OrdinalIgnoreCase);
```

Kök yolları Property Value içinde `eTPKCS11` geçmez; `etpkcs11.dll` iddiası dosya adına bakmalıdır.

- [ ] **Step 4: Test**

Run: `dotnet test tests/ImzaKit.Pkcs11.Tests/ImzaKit.Pkcs11.Tests.csproj tests/ImzaKit.Release.Tests/ImzaKit.Release.Tests.csproj -c Release --nologo --tl:off`

Expected: PASS. `ImzaKit.Release` Pkcs11’e referans veremezse layout string kopyası kullan; test yine profil sabitleriyle karşılaştırır.

Not: `dotnet test` birden fazla csproj’u bu şekilde almayabilir; ayrı çalıştır:

```
dotnet test tests/ImzaKit.Pkcs11.Tests/ImzaKit.Pkcs11.Tests.csproj -c Release --nologo --tl:off
dotnet test tests/ImzaKit.Release.Tests/ImzaKit.Release.Tests.csproj -c Release --nologo --tl:off
```

---

### Task 5: Laboratuvar kapısı ve dokümantasyon

**Files:**
- Create: `scripts/run-etoken-hardware-lab.ps1`
- Create: `docs/evidence/etoken-hardware-checklist.md`
- Modify: `README.md`
- Modify: `docs/imzakit-teknik-kullanim-rehberi.html`
- Modify: `reports/imzakit-gelistirme-durum.html`
- Modify: `site/index.html` yalnız PKCS#11 ikinci profil cümlesi gerekiyorsa

**Interfaces:**
- Consumes: AKİS lab script kalıbı
- Produces: çıkış kodu 2 skip; checklist işaretsiz

- [ ] **Step 1: Script**

`scripts/run-akis-hardware-lab.ps1` ile aynı yapı; PIN parametresi yok.

```powershell
param(
    [string]$ModulePath = $env:IMZAKIT_ETOKEN_MODULE
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    $default = Join-Path ${env:ProgramFiles} 'SafeNet\Authentication\SAC\x64\eTPKCS11.dll'
    if (Test-Path -LiteralPath $default) {
        $ModulePath = $default
    }
}

if ([string]::IsNullOrWhiteSpace($ModulePath) -or -not (Test-Path -LiteralPath $ModulePath)) {
    Write-Output 'ETOKEN_HARDWARE_SKIPPED: no PKCS#11 module. Set IMZAKIT_ETOKEN_MODULE to an allowlisted eTPKCS11.dll path.'
    exit 2
}

Write-Output "eToken module: $ModulePath"
Write-Output 'PIN is never accepted as a command-line argument. The Windows native PIN dialog must be used.'
Write-Output 'Physical token evidence is recorded in docs/evidence/etoken-hardware-checklist.md after a successful PAdES B-B round-trip.'
Write-Output "Repository: $repoRoot"
exit 0
```

Checklist: AKİS listesinin eToken kopyası; `akisp11.dll` yerine `eTPKCS11.dll`; durum “fiziksel token olmadan çalıştırılmadı”.

- [ ] **Step 2: Script smoke**

Run: `powershell -File scripts/run-etoken-hardware-lab.ps1; echo EXIT:$LASTEXITCODE`

Expected: modül yoksa 2 ve `ETOKEN_HARDWARE_SKIPPED`. `-Pin` parametresi yok (tanımsız parametre hatası vermeli eğer biri eklerse; varsayılan param bloğunda olmamalı).

- [ ] **Step 3: README**

AKİS örneğinin yanına:

```csharp
IPkcs11NativeApi native = Pkcs11NativeLibraryLoader.Load(
    @"C:\Program Files\SafeNet\Authentication\SAC\x64\eTPKCS11.dll",
    [@"C:\Program Files\SafeNet\Authentication\SAC\x64"],
    EtokenProviderProfile.SupportedLibraryFileNames);
services.AddSingleton<IPkcs11Provider>(new NativePkcs11Provider(native, NativePkcs11ProviderOptions.ForEtoken()));
```

Metin: quirk’ler `ForEtoken()`; DLL paketlenmez; `System32` varsayılan değil; fiziksel kabul ayrı liste.

Teknik rehber ve durum raporuna aynı sınır. `verify-technical-guide.ps1` / `verify-landing-page.ps1` kırılırsa zorunlu deseni güncelle; sürüm numarasını bu dilimde yükseltme.

- [ ] **Step 4: Doğrulama**

```
dotnet test ImzaKit.slnx -c Release --nologo --tl:off -m:1
pwsh -File scripts/validate-frd.ps1
```

Expected: testler yeşil; FRD yeşil. `eTPKCS11.dll` nupkg içinde yok (bu dilim pack etmez; mevcut pack sözleşmesi 12 DLL).

---

## Spec coverage

| Spec maddesi | Task |
|---|---|
| FR-030 / matris / terim / faz | 1 |
| EtokenProviderProfile / ForEtoken | 2 |
| Loader dosya adı listesi / allowlist | 3 |
| Per-profile installer roots | 4 |
| Lab script, checklist, docs | 5 |
| PIN/HTTP/System32/eToken.dll yasağı | 2–5 test iddiaları |
| MVP AKİS kapısı değişmez | 1 |
| Fiziksel iddia yok | 5 checklist |

Placeholder yok. `ForEtoken()` imzası Task 2 ve 4’te aynı.
