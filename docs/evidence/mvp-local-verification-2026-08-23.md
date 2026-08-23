# İmzaKit MVP Yerel Doğrulama Kanıtı — 23 Ağustos 2026

## Sonuç

Yerelde uygulanabilir MVP çekirdeği tamamlandı ve doğrulandı. Bu sonuç fiziksel AKİS kartı, native Windows kullanıcı deneyimi, mTLS callback altyapısı veya çevrimiçi sertifika güven/iptal servisleri için üretim kabulü anlamına gelmez.

## Taze doğrulama

| Kapı | Sonuç |
|---|---|
| Core testleri | 4/4 |
| Cryptography testleri | 3/3 |
| CMS testleri | 12/12 |
| PAdES testleri | 35/35 |
| Verify testleri | 6/6 |
| PKCS#11 sözleşme testleri | 5/5 |
| Agent güvenlik testleri | 9/9 |
| API ve süreç içi E2E testleri | 16/16 |
| Toplam | 90/90 başarılı |
| Release build | 0 hata, 0 uyarı |
| FRD doğrulama | passed |
| FRD izlenebilirliği | 109/109 |

Testler Windows ortamındaki çözüm test başlatıcısının gereksiz alt süreç üretmesini önlemek için sekiz test projesi üzerinde sıralı ve `-m:1` ile çalıştırıldı. Release build tüm `ImzaKit.slnx` üzerinde çalıştırıldı.

## Kanıtlanan yerel kapsam

- SHA-256, algoritma profili ve prepare/completion domain sınırları.
- CMS required signed attributes, deterministik DER ve detached `SignedData` roundtrip.
- Append-only PAdES B-B, `/Prev`, `/ByteRange`, `/Contents`, AcroForm imza alanı ve özgün byte koruması.
- PdfPig + SignedCms ile birinci, PDFsharp + Bouncy Castle ile ikinci bağımsız doğrulama.
- Golden PAdES SHA-256: `8206460B35BBFF225605A2679BE003A917567D960FF2EEE0192B50CDAC3EBC83`.
- PDF preflight limitleri ve DocMDP/FieldMDP politika reddi.
- Temel Verify: yapısal ByteRange, CMS imzası, imzalayan sertifika parmak izi ve `PASSED/FAILED/INDETERMINATE` ayrımı.
- PKCS#11 sağlayıcı yaşam döngüsü, aynı `CKA_ID` eşleme ve ayrı PIN/token/mekanizma sonuçları.
- Ed25519 Agent bileti, 120 saniye sınırı, origin/digest/action bağlama, atomik nonce tüketimi ve literal loopback binding.
- FRD durumlarıyla uyumlu operasyon makinesi: `Created → WaitingForClient → ClientConnected → CertificateSelected → Prepared → Signing → Signed → Validating → Completed`; opsiyonel `Timestamping` kolu ve terminal durumlar.
- İyimser sürüm, idempotent tekrar ve deterministik çakışma.
- DI üzerinden create → prepare → bellek içi PKCS#11 sınırı → complete → verify süreç içi akışı.

## PDF destek matrisi

| Girdi/özellik | MVP davranışı |
|---|---|
| PDF 1.4–1.7, klasik xref, tekil basit AcroForm'suz belge | Desteklenir |
| En fazla 32 MiB, 100.000 obje ve 32 revision | Desteklenir |
| Şifreli PDF | Açık kodla reddedilir |
| Xref stream, object stream veya hybrid-reference | Açık kodla reddedilir |
| Mevcut AcroForm | Bu MVP diliminde reddedilir |
| DocMDP `P=1` | Değişiklik yasak olduğu için reddedilir |
| Hedef imza alanını kilitleyen FieldMDP | Reddedilir |
| Bozuk ByteRange veya değiştirilmiş imzalı içerik | Verify `Failed` |
| Dış trust/revocation değerlendirmesi olmayan geçerli imza | Kriptografi `Passed`, genel sonuç `Indeterminate` |

## Kullanılan paketler ve lisanslar

| Paket | Sürüm | Lisans |
|---|---:|---|
| BouncyCastle.Cryptography | 2.7.0 | MIT |
| coverlet.collector | 6.0.4 | MIT |
| Microsoft.Extensions.DependencyInjection | 10.0.11 | MIT |
| Microsoft.Extensions.DependencyInjection.Abstractions | 10.0.11 | MIT |
| Microsoft.NET.Test.Sdk | 17.14.1 | MIT |
| PdfPig | 0.1.15 | Apache-2.0 |
| PDFsharp | 6.2.4 | MIT |
| System.Security.Cryptography.Pkcs | 10.0.11 | MIT |
| xunit | 2.9.3 | Apache-2.0 |
| xunit.runner.visualstudio | 3.1.4 | Apache-2.0 |

Envanter, gerçek `PackageReference` girdileri ile geri yüklenen `.nuspec` lisans ifadelerinden çıkarıldı. Ürün lisansı Apache-2.0 ile uyumsuz veya lisansı belirsiz paket saptanmadı.

## Harici kabul sınırları

| Kanıt | Durum |
|---|---|
| Fiziksel referans AKİS kartıyla keşif, `CKA_ID` ve RSA/SHA-256 | Çalıştırılmadı |
| Vendor DLL allowlist/ACL ve gerçek driver restart senaryosu | Çalıştırılmadı |
| Native Windows onay/PIN ekranı | Uygulanmadı |
| Agent → API mTLS callback ve cihaz enrollment | Uygulanmadı |
| Türkiye NES/ESHS zinciri, OCSP/CRL ve revocation freshness | MVP temel Verify dışında |
| Installer, kod imzalama ve Windows x64/arm64 dağıtım | Çalıştırılmadı |
| Redis/storage, yatay ölçek ve yük/kaos kabulü | Yerel süreç içi kanıt dışında |

Bu maddeler tamamlanmadan ürün “üretime hazır” veya “gerçek AKİS kabulü geçti” olarak etiketlenmemelidir.
