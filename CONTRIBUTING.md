# ImzaKit'e katkı

ImzaKit'e gösterdiğiniz ilgi için teşekkürler. Küçük, odaklı ve doğrulanabilir değişiklikler incelemeyi kolaylaştırır.

## Başlamadan önce

- Hata ve özellik talepleri için ilgili issue şablonunu kullanın.
- Güvenlik açıklarını public issue olarak bildirmeyin; [SECURITY.md](SECURITY.md) sürecini izleyin.
- Büyük API veya mimari değişiklikler için uygulamaya başlamadan önce bir tartışma açın.
- Değişikliklerinizi Apache-2.0 lisansı altında sunmayı kabul etmiş olursunuz.

## Geliştirme ortamı

.NET 10 SDK ve PowerShell 7 gerekir.

```shell
dotnet restore ImzaKit.slnx
dotnet build ImzaKit.slnx -c Release
dotnet test ImzaKit.slnx -c Release --no-build
pwsh -NoProfile -File scripts/validate-frd.ps1
```

Dokümantasyon veya yayın altyapısı değişikliklerinde ilgili `scripts/verify-*.ps1` denetimlerini de çalıştırın.

## Değişiklik ilkeleri

- Her pull request tek bir açık problemi çözmeli.
- Davranış değişikliklerine başarısızken hatayı gösteren, düzeltmeden sonra geçen test ekleyin.
- Yayınlanmış API sözleşmelerini gereksiz yere kırmayın; zorunlu kırılmayı gerekçelendirin.
- PIN, özel anahtar, gerçek sertifika, API anahtarı veya başka bir secret commit etmeyin.
- Test sertifikaları üretim kimliği taşımamalı ve yalnız test amacıyla oluşturulmalıdır.
- Kod stili ve nullable/warnings-as-errors kurallarıyla uyumlu olun.

## Pull request kontrolü

Pull request açıklamasında şunları belirtin:

1. Çözülen problem ve kapsam.
2. Uygulanan yaklaşım ve önemli kararlar.
3. Çalıştırılan testler ile sonuçları.
4. API, güvenlik veya uyumluluk etkisi.
5. Kullanıcıya dönük değişiklik varsa güncellenen dokümantasyon.

Bakım ekibi kapsamı küçültmenizi, ek kanıt sağlamanızı veya tasarım değişikliği yapmanızı isteyebilir.

---

## English summary

Use the issue templates, keep each pull request focused, add tests for behavior changes, and run the .NET build/test plus relevant PowerShell verification commands. Never commit secrets, private keys, PINs, real identity certificates, or production credentials. Describe scope, approach, verification evidence, compatibility impact, and documentation changes in every pull request.
