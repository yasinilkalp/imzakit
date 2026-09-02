# ADR-009 — WinUI Masaüstü İmza İstemcisinin Geri Çekilmesi

## Durum

Kabul edildi — 3 Eylül 2026

## Tarih

3 Eylül 2026

## Bağlam

[ADR-008](ADR-008-winui-masaustu-imza-istemcisi.md) birinci taraf WinUI 3 host’unu ve Authenticode imzalı `setup.exe` yayınını ürün ailesine eklemişti. Authenticode kod imzalama sertifikası üretimde kullanılamadı; masaüstü installer güvenilir biçimde yayımlanamadı. Ürün konumlandırması developer-first SDK, Agent, API ve Verify’dır. Birinci taraf Windows uygulaması bu konumlandırmayı dağıtım ve güven modelinde karmaşıklaştırır.

## Karar

WinUI masaüstü imza istemcisi geri çekilir. [ADR-008](ADR-008-winui-masaustu-imza-istemcisi.md) geçersiz kılınır.

`ImzaKit.Hosts.Desktop`, `ImzaKit.Hosts.Desktop.App`, Desktop installer/WiX kaynakları, Desktop testleri ve sitedeki Windows uygulaması vitrini ürün yüzeyinden çıkarılır. Yayın hattı yalnız NuGet paketidir. Agent loopback host’u ve PKCS#11 Windows native PIN bu karardan etkilenmez.

FR-119, FR-120, FR-121, SEC-028 ve TST-027 bağlayıcı olmaktan çıkar.

## Sonuçlar

Ürün ailesi SDK, Agent, API ve Verify olarak kalır. Kartla imza tarayıcı + Agent veya müşteri uygulamasının kendi host’u üzerinden yapılır. Git geçmişindeki ADR-008 kaydı silinmez.
