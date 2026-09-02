# ImzaKit Desktop GitHub Release ve Authenticode Tasarımı

**Tarih:** 2 Eylül 2026  
**Durum:** Onaylandı  
**Hedef:** `1.0.0-alpha.14` ile NuGet ve Authenticode imzalı Desktop `setup.exe` aynı etiket altında; Authenticode yoksa ne installer ne NuGet basılmaz  
**FRD:** [ADR-008](../../../frd/kararlar/ADR-008-winui-masaustu-imza-istemcisi.md), FR-121, SEC-028, TST-027

## Amaç

WinUI Desktop host `main`’dedir; GitHub Releases boştur; `publish.yml` yalnız NuGet basar ve sürümü `1.0.0-alpha.13` olarak sabitler. Bu dilim, kod imzalama sertifikası GitHub secret olarak varken `v1.0.0-alpha.14` etiketinde:

- tek `ImzaKit` NuGet paketini (16 DLL, Desktop yok) nuget.org ve GitHub Packages’e basmak,
- Authenticode imzalı `ImzaKit.Desktop-win-x64.setup.exe` dosyasını GitHub Release’e koymak,
- `site/index.html` mevcut `releases/latest` bağlantısını korumak (ikili `site/` veya git’e girmez)

için yayın hattını tamamlar.

## Kararlar

1. Sürüm `1.0.0-alpha.14`. Etiket `v1.0.0-alpha.14`. `Directory.Build.props` ile etiket semver’i birebir aynı değilse job düşer.
2. Pipeline üç iş: `verify-pack` (ubuntu) → `desktop` (windows-latest) → `publish` (her iki artifact hazırsa NuGet + Release). Desktop kırmızıysa NuGet basılmaz.
3. İlk installer RID yalnız `win-x64`. `win-arm64` yerleşimde kalır, bu Release’e asset konmaz.
4. Agent host/installer bu dilimde yoktur. Agent Authenticode politikası değişmez; Release’e Agent asset eklenmez.
5. Authenticode zorunludur. PFX yok, şifre yok veya PE güvenlik dizini yoksa Desktop asset ve tüm `publish` işi durur. Unsigned `setup.exe` artifact olarak da yayımlanmaz.
6. MSI `ProductVersion` Windows kuralına uyar: `1.0.0-alpha.N` → `1.0.N` (ör. `1.0.14`). Ürün adı, dosya adı ve NuGet semver `1.0.0-alpha.14` kalır.
7. `setup.exe` WiX v4 Burn bundle’dır; içinde per-machine MSI vardır. Kurulum dizini `%ProgramFiles%\ImzaKit\Desktop`. Vendor PKCS#11 DLL harvest edilmez.
8. Secret adları: `IMZAKIT_AUTHENTICODE_PFX` (PFX baytlarının base64’ü), `IMZAKIT_AUTHENTICODE_PFX_PASSWORD`, mevcut `IMZAKIT_RELEASE_ECDSA_KEY`. PFX geçici dosyaya yazılır, job sonunda silinir, log’a düşmez.
9. `contents: write` yalnız `publish` işindedir. NuGet Trusted Publishing (OIDC, `Kodekibi`) durur; uzun ömürlü `NUGET_API_KEY` secret’ı yok.

## Kapsam

Kapsar:

- Sürüm `1.0.0-alpha.14` (props, README, SECURITY, landing, teknik rehber, verify script’leri, `publish.yml`)
- `WindowsInstallerVersion` eşlemesi ve Desktop WiX harvest / Burn `setup.exe` kaynağı
- `emit-release-bundle --kind desktop`
- Windows job: self-contained publish, WiX, `signtool`, `AuthenticodeGate`
- GitHub Release + nuget.org + GitHub Packages aynı etiket
- Workflow sözleşme testleri

Kapsamaz:

- Agent Windows host veya Agent `setup.exe`
- `win-arm64` Desktop installer
- Authenticode politikasını alpha için gevşetmek
- `setup.exe` ikilisini `site/` veya NuGet’e koymak
- Faz 6 (ATSHashIndex-v3, ASiC-E ortak rapor, CAdES/XAdES preservation, host cron, Unix HostReady)
- Fiziksel AKİS laboratuvarı
- Hukuki NES/QES iddiası

## Değerlendirilen yaklaşımlar

### 1. İki koşu + atomik publish — seçilen

Ubuntu NuGet alışkanlığı ve Trusted Publishing korunur. WinUI yalnız Windows’ta derlenir. İmza veya Desktop başarısızsa paket de basılmaz.

### 2. Tek windows-latest job — reddedilen

YAML kısa kalır; koşu yavaşlar ve Ubuntu NuGet/OIDC yolu kırılır.

### 3. WiX’siz imzalı tek exe — reddedilen

FR-121 `setup.exe` adını tutar ama Program Files, kaldırıcı ve mevcut `DesktopInstallerLayout` sözleşmesi zayıf kalır.

## Mimari

```text
v1.0.0-alpha.14
  → verify-pack (ubuntu)
        test + pack nupkg/snupkg + nuget SBOM
        artifact: packages
  → desktop (windows-latest)
        publish WinUI self-contained win-x64
        WiX MSI (ProductVersion 1.0.14)
        Burn → ImzaKit.Desktop-win-x64.setup.exe
        signtool (SHA-256, RFC 3161 timestamp)
        AuthenticodeGate on App.exe + setup.exe
        emit-release-bundle --kind desktop
        artifact: desktop-installer
  → publish
        nuget.org + GitHub Packages
        gh release create v1.0.0-alpha.14
            ImzaKit.Desktop-win-x64.setup.exe
            sbom.cdx.json (nuget + desktop)
```

NuGet paketi 16 DLL kalır. `ImzaKit.Hosts.Desktop` ve `.App` `IsPackable=false`.

## Bileşenler

| Birim | Sorumluluk |
|---|---|
| `WindowsInstallerVersion` | Semver → MSI `major.minor.build`. `1.0.0-alpha.14` → `1.0.14`. Kararlı `1.0.0` → `1.0.0`. Desteklenmeyen biçim `ArgumentException`. |
| `DesktopMsiDocument` | Harvest dizini + payload dosya listesi. `Product/@Version` sayısal. `akisp11` / `eTPKCS11` yok. |
| `DesktopBurnDocument` | MSI’yı `ImzaKit.Desktop-win-x64.setup.exe` Burn bundle’ına sarar. |
| `ReleaseSigningPolicy` | `DesktopPeOrInstaller` Authenticode zorunlu (değişmez). |
| `scripts/emit-release-bundle.cs` | `--kind desktop` tanır; PFX yoksa exit 1 ve `IMZAKIT.RELEASE.AUTHENTICODE_CERTIFICATE_MISSING`. |
| `scripts/emit-desktop-installer.cs` | Publish çıktısından `.wxs` yazar (Ubuntu’da WiX derlemez; Windows job `wix build` çalıştırır). |
| `.github/workflows/publish.yml` | Üç iş; sürüm etiketten; hardcoded `alpha.13` yok. |
| `scripts/verify-publish-workflow.ps1` | Üç iş, `windows-latest`, Authenticode secret adları, `gh release`, `contents: write` yalnız publish, Desktop asset adı, sürümün etiket değişkeninden gelmesi. |

## Veri akışı

1. Operatör `v1.0.0-alpha.14` basar. Workflow `GITHUB_REF_NAME` içinden `v` önekini atar, `Directory.Build.props` `<Version>` ile karşılaştırır.
2. `verify-pack` Release test ve `dotnet pack` çalıştırır; `ImzaKit.1.0.0-alpha.14.nupkg` üretir. NuGet push bu işte yoktur.
3. `desktop` `ImzaKit.Hosts.Desktop.App` `win-x64` self-contained yayınlar. LICENSE, NOTICE, SBOM, provenance harvest listesine eklenir. `wix build` MSI ve Burn `setup.exe` üretir.
4. Secret PFX geçici `.pfx` olur. `signtool sign /fd SHA256 /td SHA256 /tr` (RFC 3161) önce `ImzaKit.Hosts.Desktop.App.exe`, sonra `setup.exe`. `AuthenticodeGate.RequireFile(..., required: true)`.
5. `publish` her iki artifact’i indirir, NuGet push ve `gh release create` yapar. Release gövdesi ön sürüm uyarısı içerir; fiziksel AKİS kabulü iddia etmez.

PIN, PFX şifresi ve private key log, SBOM veya Release notuna yazılmaz.

## Hata modeli

| Koşul | Kod / davranış |
|---|---|
| PFX secret boş veya geçici dosya yok | `IMZAKIT.RELEASE.AUTHENTICODE_CERTIFICATE_MISSING` |
| İmzalı olması gereken PE’de güvenlik dizini yok | `IMZAKIT.RELEASE.AUTHENTICODE_REQUIRED` |
| `--kind` bilinmiyor | `Unknown --kind` (mevcut) |
| Etiket semver ≠ props | Job `Version mismatch` ile düşer |
| Harvest listesinde vendor DLL | Birim test kırmızı; WiX kaynağı yazılmaz |
| NuGet sürümü zaten var | `--skip-duplicate` yok; push başarısız |

## Test ve kabul

Ubuntu CI WiX/`signtool` çalıştırmaz. Kanıt:

- `WindowsInstallerVersionTests`: `1.0.0-alpha.14` → `1.0.14`; `1.0.0` → `1.0.0`; `2.0.0-beta.1` → `2.0.1`; geçersiz semver reddi.
- `DesktopInstallerAndUpdateTests`: harvest `Source` yolları, `ProductVersion` 1.0.14, vendor yok, Burn çıktı adı `ImzaKit.Desktop-win-x64.setup.exe`.
- `ReleaseSigningPolicyTests`: Desktop installer PFX olmadan yayınlanamaz (mevcut).
- `emit-release-bundle --kind desktop` PFX yokken exit 1 (derleme kontrolü `--compile-check` yeşil kalır).
- `verify-publish-workflow.ps1`: üç iş, Windows runner, secret adları, `gh release create`, nuget push yalnız `publish` işinde, hardcoded `alpha.13` yok.
- Landing/README/SECURITY/teknik rehber verify script’leri `1.0.0-alpha.14`.
- Windows yayın job’u: `AuthenticodePeSignature.HasEmbeddedSignature` `setup.exe` ve App exe için true.

Laboratuvar: gerçek PFX GitHub secret; CI sertifika deposu yok. Fiziksel kart TST-027’nin laboratuvar ayağıdır, bu dilimi kilitlemez.

## Sürüm dokümanları

`1.0.0-alpha.13` geçen NuGet’dir. Alpha.14 ile güncellenir: `Directory.Build.props`, README, SECURITY.md, `site/index.html`, teknik rehber, `scripts/verify-*.ps1`, `publish.yml`, FRD izlenebilirlik dipnotu (Desktop host uygulandı; GitHub Release bu dilim).

İzlenebilirlik `FR-121` kabul kanıtı: imzalı Release asset + landing `releases/latest`. `MVP = Hayır` durur.

## Operatör önkoşulu

Yayından önce repo secret’ları:

- `IMZAKIT_AUTHENTICODE_PFX`
- `IMZAKIT_AUTHENTICODE_PFX_PASSWORD`
- `IMZAKIT_RELEASE_ECDSA_KEY` (prerelease NuGet ve prerelease Desktop için zorunlu değil; kararlı sürüm ve `UpdateManifest` için zorunlu)

Secret yokken `desktop` ve `publish` kasten kırmızı kalır. Bu, unsigned installer yayımlamaktan tercih edilir.
