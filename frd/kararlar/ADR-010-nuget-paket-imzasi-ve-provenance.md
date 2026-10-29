# ADR-010 — NuGet Paket İmzası ve Provenance

## Durum

Kabul edildi — 29 Ekim 2026

## Tarih

29 Ekim 2026

## Bağlam

SEC-027, release sürecinin NuGet paketini imzalamasını ve kaynak commit ile artefakt digest ilişkisini provenance olarak yayımlamasını ister. `ReleaseSigningPolicy` bu nedenle kararlı NuGet paketinde Authenticode sertifikası ve release ECDSA anahtarı arıyordu.

Haziran 2023’ten beri herkese açık sertifika otoriteleri kod imzalama özel anahtarını donanımda (USB token veya bulut HSM) tutmayı zorunlu kılar; anahtar PFX olarak CI secret’ına konamaz. NuGet.org’da sertifika kaydı yapıldıktan sonra hesabın bütün paketleri o sertifikayla imzalanmak zorundadır. Bulut HSM hizmeti tek bakımcılı açık kaynak proje için sürekli maliyet ve hesap kilidi getirir.

NuGet.org her paketi kendi depo imzasıyla imzalar. Yayın, uzun ömürlü API anahtarı yerine bu deponun `publish.yml` iş akışına bağlı OIDC (Trusted Publishing) ile yapılır.

## Karar

NuGet paketi için yazar imzası (Authenticode sertifikası) zorunlu değildir. Paket bütünlüğü NuGet.org depo imzasıyla, yayıncı kimliği OIDC ile yapılan yayınla sağlanır.

Kararlı NuGet sürümü release ECDSA P-256 anahtarıyla imzalı provenance olmadan yayımlanamaz. Anahtar `IMZAKIT_RELEASE_ECDSA_KEY` secret’ında base64 PKCS#8 olarak durur. Provenance; ürün, sürüm, kaynak commit, paket SHA-256’sı, SBOM SHA-256’sı, builder kimliği ve zamanı imzalar. SBOM imzası bu bağ üzerinden sağlanır.

Paket, sembol paketi, `sbom.cdx.json` ve `provenance.json` etiket için açılan GitHub Release’e eklenir. NuGet.org depo imzası paketi yeniden yazdığı için provenance, GitHub Release’teki paketle doğrulanır (`scripts/verify-release-provenance.cs`). Release açık anahtarı `packaging/release-keys/imzakit-release.pub.pem` dosyasında yayımlanır. Yayın iş akışı provenance’ı bu anahtarla doğrular; secret depodaki anahtarla uyuşmazsa yayın durur.

Agent installer, update manifest ve Trust Store artefaktları için mevcut kurallar değişmez; Authenticode ve release anahtarı şartları sürer.

## Sonuçlar

Kararlı 1.0.0 yalnız release ECDSA anahtarı ile yayımlanabilir; kod imzalama sertifikası gerekmez. Tüketiciler `dotnet nuget trust author` ile ImzaKit yazar imzasına güven tanımlayamaz. Yazar imzası ileride yeni bir ADR ile eklenebilir; bu durumda NuGet.org sertifika kaydı ve HSM tabanlı imzalama birlikte planlanır.
