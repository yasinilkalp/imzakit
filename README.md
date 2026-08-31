# ImzaKit

ImzaKit, .NET uygulamalarında elektronik imza iş akışları geliştirmek için hazırlanmış, sağlayıcıdan bağımsız ve Apache-2.0 lisanslı açık kaynak bir araç takımıdır. Tek NuGet paketi; CMS ve PAdES hazırlama/tamamlama, PKCS#11 soyutlamaları, imza doğrulama, yerel Agent güvenliği, API işlem modeli ve bağımlılık enjeksiyonu bileşenlerini birlikte sunar.

> **Ön sürüm:** `1.0.0-alpha.13` kararlı sürüm değildir ve API değişiklikleri içerebilir. Üretim kullanımından önce hukuki gereksinimleri, sertifika politikalarını, güven zincirini, iptal kontrollerini, donanım uyumluluğunu ve PDF okuyucu birlikte çalışabilirliğini kendi ortamınızda doğrulayın.

## Öne çıkan özellikler

- Tek `ImzaKit` paketi içinde 16 modül
- Haricî imzalama akışları için prepare/complete modeli
- CMS detached imza verisi hazırlama ve tamamlama
- PDF bütünlüğünü koruyan artımlı PAdES imzalama altyapısı
- PKCS#11 sağlayıcı sözleşmeleri ve kart imzalama orkestrasyonu
- PAdES `ByteRange` ve CMS kriptografik imza doğrulaması
- Sistem deposuna başvurmayan X.509 zincir, güven politikası ve OCSP/CRL değerlendirmesi
- RFC 3161 TSA ve PAdES B-T/B-LT/B-LTA uzatma hattı
- Bağımsız CAdES B-B/B-T/B-LT/B-LTA ve çoklu SignerInfo
- XAdES enveloped/enveloping/detached ve B-B/B-T/B-LT/B-LTA
- ASiC-S/E paketleme ve ZIP güvenlik kontrolleri
- DI kayıtları ve süreç içi örnek orkestrasyon
- Agent bileti, tekrar oynatma koruması, API durum makinesi ve idempotency bileşenleri

## Gereksinimler

- .NET 10 SDK veya uyumlu bir .NET 10 çalışma zamanı
- Kartla imzalama için hedef cihazınıza uygun bir `IPkcs11Provider` uygulaması
- Üretim ortamında uygulamanıza özel sertifika güveni ve iptal kontrolü politikası

## Kurulum

```shell
dotnet add package ImzaKit --version 1.0.0-alpha.13
```

Ya da proje dosyanıza doğrudan ekleyin:

```xml
<PackageReference Include="ImzaKit" Version="1.0.0-alpha.13" />
```

Paket ayrıca [GitHub Packages](https://github.com/yasinilkalp/imzakit/pkgs/nuget/ImzaKit) üzerinde görünür; kurulum kaynağı nuget.org’dur.

## Paketteki modüller

| Modül | Sorumluluk |
| --- | --- |
| `ImzaKit.Core` | Sağlayıcıdan bağımsız imzalama ve kriptografi sözleşmeleri |
| `ImzaKit.Cryptography` | Özet hesaplama ve algoritma modelleri |
| `ImzaKit.Cms` | CMS signed-attributes hazırlama ve SignedData tamamlama |
| `ImzaKit.CAdES` | Bağımsız CAdES B-B/B-T/B-LT/B-LTA ve çoklu SignerInfo |
| `ImzaKit.XAdES` | XAdES enveloped/enveloping/detached ve B-B/B-T/B-LT/B-LTA |
| `ImzaKit.ASiC` | ASiC-S/E paketleme, ASiCManifest ve ZIP güvenlik kontrolleri |
| `ImzaKit.PAdES` | PDF/PAdES ön kontrol, hazırlama, tamamlama ve değişiklik politikaları |
| `ImzaKit.Pkcs11` | PKCS#11 sağlayıcı sözleşmeleri ve imzalama orkestrasyonu |
| `ImzaKit.Certificate` | Çevrimdışı X.509 zinciri oluşturma ve kriptografik sertifika doğrulaması |
| `ImzaKit.Trust` | Sürümlü güven deposu, profil ve sertifika politikası değerlendirmesi |
| `ImzaKit.Revocation` | Gömülü, önbellek veya çevrimiçi OCSP/CRL kanıtlarının değerlendirilmesi |
| `ImzaKit.Timestamp` | RFC 3161 zaman damgası isteği, TSA failover ve token doğrulaması |
| `ImzaKit.Verify` | CMS/PAdES/CAdES/XAdES/ASiC ortak validation report |
| `ImzaKit.Agent` | Loopback Agent yapılandırması, imzalı bilet ve replay koruması |
| `ImzaKit.Api` | İdempotent imza işlemleri, durum makinesi ve problem eşlemeleri |
| `ImzaKit.DependencyInjection` | DI kayıtları ve süreç içi PAdES orkestrasyonu |

## Hızlı başlangıç

### Temel servisleri kaydetme

```csharp
using ImzaKit.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddImzaKitCore();

using ServiceProvider provider = services.BuildServiceProvider();
```

PKCS#11 kart imzalama için allowlist’teki mutlak yoldan vendor modülünü yükleyin. ImzaKit üretici DLL’i paketlemez; PIN HTTP’den geçmez.

```csharp
using ImzaKit.DependencyInjection;
using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Native;
using Microsoft.Extensions.DependencyInjection;

IPkcs11NativeApi native = Pkcs11NativeLibraryLoader.Load(
    @"C:\Program Files\AKIS\akisp11.dll",
    [@"C:\Program Files\AKIS"]);
var services = new ServiceCollection();
services.AddImzaKitCore();
services.AddSingleton<IPkcs11Provider>(new NativePkcs11Provider(native));
services.AddImzaKitPkcs11();
```

eToken (`eTPKCS11.dll`) ikinci doğrulanmış Windows profilidir. Varsayılan allowlist SafeNet/Thales `Program Files` kökleridir; `System32` varsayılan değildir. DLL paketlenmez.

```csharp
using ImzaKit.DependencyInjection;
using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Etoken;
using ImzaKit.Pkcs11.Native;
using Microsoft.Extensions.DependencyInjection;

IPkcs11NativeApi native = Pkcs11NativeLibraryLoader.Load(
    @"C:\Program Files\SafeNet\Authentication\SAC\x64\eTPKCS11.dll",
    [@"C:\Program Files\SafeNet\Authentication\SAC\x64"],
    EtokenProviderProfile.SupportedLibraryFileNames);
var services = new ServiceCollection();
services.AddImzaKitCore();
services.AddSingleton<IPkcs11Provider>(new NativePkcs11Provider(native, NativePkcs11ProviderOptions.ForEtoken()));
services.AddImzaKitPkcs11();
```

AKİS quirk’leri `NativePkcs11ProviderOptions.ForAkis()`, eToken quirk’leri `ForEtoken()` içindedir (aynı güvenli varsayılanlar). Faz 5 nShield (`cknfast.dll`, `ForNshield()`) ve Utimaco (`cs_pkcs11_R2.dll` / `cs_pkcs11_R3.dll`, `ForUtimaco()`) allowlist profilleri aynı güvenli varsayılanları kullanır; `cryptoki.dll` ve `System32` varsayılan değildir. Vendor DLL paketlenmez. Fiziksel nShield/Utimaco kabulü ayrıdır; CI sahte native API kullanır.

MVP HTTP sözleşmesi `SignatureApiRequestHandler` ile uygulanır. Üretim Kestrel host (`ImzaKit.Hosts.Api`) paket dışındadır; HTTPS üzerinde `AllowCertificate` mTLS kullanır, özel cihaz CA’sini OS store ile doğrulamaz ve client sertifikasını `MutualTlsRequestMapper` ile işler. Redis benzeri `RedisMetadataStore` belge tutmaz; `FileSystemBlobStore` object-store bağları içindir. PIN yalnız `AddImzaKitWindowsAgent()` native penceresinde alınır. Windows Desktop host (`ImzaKit.Hosts.Desktop` / WinUI) NuGet paketinde yoktur; Authenticode imzalı `setup.exe` GitHub Releases’te yayımlanır.

Saklama varsayılanları (ADR-007): Agent bileti 120 saniye, tamamlanmamış operasyon metadata’sı 24 saat, tamamlanan çıktı ve doğrulama raporu 7 gün. Redis benzeri `IMetadataStore` belge tutmaz ve TTL’siz kayıt kabul etmez. Belgeler `IDocumentStore` altında tenant izole, AES-GCM şifreli ve süreli URL ile okunur. Audit append-only hash-chain’dir; PIN, private key, ham belge ve credential yazılmaz.

### İmzalı PDF doğrulama

```csharp
using ImzaKit.Verify.Validation;

byte[] signedPdf = File.ReadAllBytes("signed-document.pdf");
PadesValidationReport report = PadesValidator.Validate(signedPdf);

Console.WriteLine($"Durum: {report.Status}");
Console.WriteLine($"Kriptografik doğrulama: {report.CryptographicStatus}");
Console.WriteLine($"Güven zinciri: {report.TrustStatus}");

foreach (ValidationFinding finding in report.Findings)
{
    Console.WriteLine($"{finding.Code}: {finding.Message}");
}
```

Tek parametreli `PadesValidator.Validate` çağrısı geriye dönük uyumluluk için yalnız PDF/CMS bütünlüğünü denetler; bu nedenle `TrustStatus` değeri `Indeterminate` olabilir.

### Çevrimdışı güven doğrulaması

```csharp
using ImzaKit.Certificate.Models;
using ImzaKit.Trust.Models;
using ImzaKit.Verify.Validation;

var trustStore = new TrustStoreSnapshot(
    "kurum-trust-2026.08",
    [new TrustAnchor(rootCertificate, [ValidationProfile.GeneralX509, ValidationProfile.TurkiyeNes], "kurumsal-kökler")]);

var policies = new CertificatePolicyCatalog(
    "kurum-policy-2026.08",
    [new CertificatePolicyEntry(
        ValidationProfile.TurkiyeNes,
        "2.16.792.1.2.1.1.5.7.1.1",
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        null,
        TimeSpan.FromHours(24))]);

var context = new ValidationContext(
    ValidationProfile.TurkiyeNes,
    DateTimeOffset.UtcNow,
    ValidationTimeSource.CurrentSystemTime,
    trustStore,
    policies,
    embeddedIntermediates,
    localIntermediates,
    revocationEvidence);

PadesValidationReport report = PadesValidator.Validate(signedPdf, context);
switch (report.Status)
{
    case ValidationStatus.Passed: Console.WriteLine("İmza ve güven kararı geçti."); break;
    case ValidationStatus.Failed: Console.WriteLine("İmza veya güven kararı başarısız."); break;
    default: Console.WriteLine("Karar için ek kanıt gerekiyor."); break;
}
```

`TurkiyeNes` profili işletim sistemi kök deposunu kullanmaz. `Eidas` profili Eidas etiketli kök, sürümlü katalog politika OID’i ve QcCompliance (`0.4.0.1862.1.1`) ister; EU TSL/EUTL içe aktarılmaz ve hukuki QES iddiası yoktur. Trust Maintainer imzalı paketleri `TrustStorePackageCodec` + `TrustStoreActivationService` ile atomik etkinleştirir, rollback ve acil kaldırma yapar. Gerçek ESHS kökleri bu repoya konmaz; sentetik test paketleri CI’de kullanılır.

Windows Agent installer yerleşimi (`AgentInstallerLayout`) yalnız `win-x64` ve `win-arm64`, `%ProgramFiles%\ImzaKit\Agent`, loopback bind ve profil başına PKCS#11 allowlist kökleri taşır; vendor `akisp11.dll` ve `eTPKCS11.dll` paketlenmez. Authenticode imzası release anahtarıyla yapılır (CI’de sertifika yoktur). Her sürüm CycloneDX 1.6 SBOM, commit/digest provenance ve imzalı update manifest’i üretir; GPL/AGPL/SSPL bağımlılık release’i durdurur.

`RevocationDataUnavailable`, seçilen zaman ve tazelik politikası için uygun OCSP/CRL kanıtı bulunmadığını bildirir; ağdan otomatik kanıt indirilmez.

### Sınırlamalar

- Sistem sertifika deposu, AIA, OCSP URL’si veya CRL URL’si otomatik kullanılmaz.
- Güven deposu ve politika kataloğunun doğrulanmış, bütünlüğü korunmuş dağıtımı çağıran uygulamanın sorumluluğundadır.
- Alpha.4 yalnız çağıranın sağladığı gömülü/yerel kanıtlarla deterministik çevrimdışı karar üretir; çevrimiçi toplama ve uzun dönem doğrulama kapsam dışıdır.

## Güvenlik notları

- PIN, özel anahtar, ham Agent bileti veya maskelenmemiş token seri numarasını loglamayın.
- Özel anahtar işlemlerini kart, HSM veya amaçlanan kriptografik sağlayıcı sınırında tutun.
- Sertifika güveni, OCSP/CRL, zaman damgası ve kurumsal politika kararlarını uygulama katmanında açıkça yönetin.
- Fiziksel kart, native kullanıcı onayı, mTLS ve kurulum/dağıtım senaryolarını hedef ortamınızda ayrıca test edin.

## Kaynak, durum ve lisans

- [Açık kaynak tanıtım sayfası](https://yasinilkalp.github.io/imzakit/)
- [Kaynak kodu](https://github.com/yasinilkalp/imzakit)
- [Etkileşimli teknik kullanım rehberi](https://github.com/yasinilkalp/imzakit/blob/main/docs/imzakit-teknik-kullanim-rehberi.html)
- [Geliştirme durum raporu](https://github.com/yasinilkalp/imzakit/blob/main/reports/imzakit-gelistirme-durum.html)
- [Katkı rehberi](CONTRIBUTING.md)
- [Davranış kuralları](CODE_OF_CONDUCT.md)
- [Güvenlik politikası](SECURITY.md)
- [Apache License 2.0](https://github.com/yasinilkalp/imzakit/blob/main/LICENSE)
- [NOTICE](https://github.com/yasinilkalp/imzakit/blob/main/NOTICE)

---

## English summary

ImzaKit is an Apache-2.0 licensed, provider-independent electronic-signature toolkit for .NET 10. A single NuGet package contains 16 modules covering signing, independent CAdES, XAdES, ASiC, RFC 3161 timestamps, PAdES B-T/B-LT/B-LTA, offline certificate/trust/revocation validation, local-agent security, API semantics, and dependency injection.

### Install

```shell
dotnet add package ImzaKit --version 1.0.0-alpha.13
```

### Included modules

`ImzaKit.Core`, `ImzaKit.Cryptography`, `ImzaKit.Cms`, `ImzaKit.CAdES`, `ImzaKit.XAdES`, `ImzaKit.ASiC`, `ImzaKit.PAdES`, `ImzaKit.Pkcs11`, `ImzaKit.Certificate`, `ImzaKit.Trust`, `ImzaKit.Revocation`, `ImzaKit.Timestamp`, `ImzaKit.Verify`, `ImzaKit.Agent`, `ImzaKit.Api`, and `ImzaKit.DependencyInjection` are distributed together.

### Offline trust validation

Create a versioned `TrustStoreSnapshot` and `CertificatePolicyCatalog`, then pass them through `ValidationContext` to `PadesValidator.Validate(pdf, context)`. Choose `GeneralX509` for general PKI rules, `TurkiyeNes` for the configured Turkish qualified-certificate policy, or `Eidas` for an Eidas-labeled anchor plus catalog policy OID and QcCompliance. `Eidas` is not an EU Trusted List import and does not claim QES. A `RevocationDataUnavailable` finding means suitable caller-supplied OCSP/CRL evidence was unavailable.

### Limitations

ImzaKit never consults the system trust store automatically. Signature verification stays offline unless the caller supplies evidence. RFC 3161 timestamping and PAdES B-T/B-LT/B-LTA extension fetch TSA/OCSP/CRL only through `IExternalResourceFetcher`.

### Prerelease and security notice

This is a prerelease and its APIs may change before `1.0.0`. Integrators must supply deployment-specific PKCS#11 adapters, trusted validation inputs, hardware validation, native user approval, secure transport, and operational controls before production use.

### Project and community

- [Project website](https://yasinilkalp.github.io/imzakit/)
- [Contributing guide](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)

Copyright 2026 ImzaKit contributors. Licensed under the [Apache License 2.0](https://github.com/yasinilkalp/imzakit/blob/main/LICENSE).
