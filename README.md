# ImzaKit

ImzaKit, .NET uygulamalarında elektronik imza iş akışları geliştirmek için hazırlanmış, sağlayıcıdan bağımsız ve Apache-2.0 lisanslı açık kaynak bir araç takımıdır. Tek NuGet paketi; CMS ve PAdES hazırlama/tamamlama, PKCS#11 soyutlamaları, imza doğrulama, yerel Agent güvenliği, API işlem modeli ve bağımlılık enjeksiyonu bileşenlerini birlikte sunar.

> **Ön sürüm:** `1.0.0-alpha.4` kararlı sürüm değildir ve API değişiklikleri içerebilir. Üretim kullanımından önce hukuki gereksinimleri, sertifika politikalarını, güven zincirini, iptal kontrollerini, donanım uyumluluğunu ve PDF okuyucu birlikte çalışabilirliğini kendi ortamınızda doğrulayın.

## Öne çıkan özellikler

- Tek `ImzaKit` paketi içinde dokuz modül
- Haricî imzalama akışları için prepare/complete modeli
- CMS detached imza verisi hazırlama ve tamamlama
- PDF bütünlüğünü koruyan artımlı PAdES imzalama altyapısı
- PKCS#11 sağlayıcı sözleşmeleri ve kart imzalama orkestrasyonu
- PAdES `ByteRange` ve CMS kriptografik imza doğrulaması
- DI kayıtları ve süreç içi örnek orkestrasyon
- Agent bileti, tekrar oynatma koruması, API durum makinesi ve idempotency bileşenleri

## Gereksinimler

- .NET 10 SDK veya uyumlu bir .NET 10 çalışma zamanı
- Kartla imzalama için hedef cihazınıza uygun bir `IPkcs11Provider` uygulaması
- Üretim ortamında uygulamanıza özel sertifika güveni ve iptal kontrolü politikası

## Kurulum

```shell
dotnet add package ImzaKit --version 1.0.0-alpha.4
```

Ya da proje dosyanıza doğrudan ekleyin:

```xml
<PackageReference Include="ImzaKit" Version="1.0.0-alpha.4" />
```

## Paketteki modüller

| Modül | Sorumluluk |
| --- | --- |
| `ImzaKit.Core` | Sağlayıcıdan bağımsız imzalama ve kriptografi sözleşmeleri |
| `ImzaKit.Cryptography` | Özet hesaplama ve algoritma modelleri |
| `ImzaKit.Cms` | CMS signed-attributes hazırlama ve SignedData tamamlama |
| `ImzaKit.PAdES` | PDF/PAdES ön kontrol, hazırlama, tamamlama ve değişiklik politikaları |
| `ImzaKit.Pkcs11` | PKCS#11 sağlayıcı sözleşmeleri ve imzalama orkestrasyonu |
| `ImzaKit.Verify` | CMS/PAdES doğrulama raporları |
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

PKCS#11 kart imzalama servislerini kullanacaksanız uygulamanızda `IPkcs11Provider` sözleşmesini gerçek kart/üretici kitaplığına bağlayın ve ardından modülü ekleyin:

```csharp
using ImzaKit.DependencyInjection;
using ImzaKit.Pkcs11.Abstractions;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddImzaKitCore();
services.AddSingleton<IPkcs11Provider, MyPkcs11Provider>();
services.AddImzaKitPkcs11();
```

Buradaki `MyPkcs11Provider`, hedef PKCS#11 sürücünüz için sizin geliştireceğiniz adaptörü temsil eder. ImzaKit üreticiye özel native sürücü veya PIN arayüzü paketlemez.

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

`PadesValidator`, PDF yapısını ve CMS imzasını denetler; sertifika güven zinciri ile iptal durumunu kendiliğinden doğrulamaz. Bu nedenle kriptografik imza geçerli olsa bile `TrustStatus` değeri `Indeterminate` olabilir.

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

ImzaKit is an Apache-2.0 licensed, provider-independent electronic-signature toolkit for .NET 10. A single NuGet package contains nine modules covering CMS and PAdES preparation/completion, PKCS#11 abstractions, signature validation, local-agent security primitives, API operation semantics, and dependency-injection integration.

### Install

```shell
dotnet add package ImzaKit --version 1.0.0-alpha.4
```

### Included modules

`ImzaKit.Core`, `ImzaKit.Cryptography`, `ImzaKit.Cms`, `ImzaKit.PAdES`, `ImzaKit.Pkcs11`, `ImzaKit.Verify`, `ImzaKit.Agent`, `ImzaKit.Api`, and `ImzaKit.DependencyInjection` are distributed together through the `ImzaKit` package.

### Prerelease and security notice

This is a prerelease and its APIs may change before `1.0.0`. ImzaKit validates PDF structure and CMS signatures but does not automatically establish certificate trust or revocation status. Integrators must supply deployment-specific PKCS#11 adapters, trust policy, hardware validation, native user approval, secure transport, and operational controls before production use.

### Project and community

- [Project website](https://yasinilkalp.github.io/imzakit/)
- [Contributing guide](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)

Copyright 2026 ImzaKit contributors. Licensed under the [Apache License 2.0](https://github.com/yasinilkalp/imzakit/blob/main/LICENSE).
