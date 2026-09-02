# ADR-008 — WinUI Masaüstü İmza İstemcisi

## Durum

Geçersiz kılındı — 3 Eylül 2026 ([ADR-009](ADR-009-winui-masaustu-imza-istemcisi-geri-cekildi.md))

## Tarih

31 Ağustos 2026

## Bağlam

ImzaKit developer-first bir entegrasyon kitidir. Windows Agent tarayıcıyı karta bağlar; NuGet paketi kütüphane yüzeyidir. Sitede sergilenecek, PDF seçip native PIN ile PAdES B-B üreten birinci taraf bir Windows uygulaması için ayrı bir host gerekir. Bu host SDK’ya karışmamalı, Agent güven modelini tarayıcı senaryosuna zorlamamalı ve `setup.exe` ikilisini git/Pages kaynağına gömmemelidir.

## Karar

Birinci taraf masaüstü imza istemcisi `ImzaKit.Hosts.Desktop` olarak WinUI 3 unpackaged host’tur. İmzalama süreç içinde `InProcessPadesSigningOrchestrator` ile yapılır. PIN Windows CredUI native diyaloğunda alınır; WinUI `PasswordBox` kullanılmaz. Agent bileti, loopback HTTP ve API host bu ürün için zorunlu değildir.

Host NuGet paketine girmez (`IsPackable=false`). Authenticode imzalı `setup.exe` GitHub Releases’te yayımlanır; `site/index.html` bu sürümü ImzaKit özelliği olarak sergiler. Vendor PKCS#11 DLL’leri ve `setup.exe` ikilisi `site/` klasörüne veya NuGet’e konmaz.

İlk sürüm PAdES B-B, görünmez imza, AKİS ve eToken allowlist, self-contained `win-x64` (gerekirse `win-arm64`) ile sınırlıdır. Bu karar MVP Agent/AKİS kabul kapısını değiştirmez.

## Sonuçlar

Ürün ailesine SDK, Agent, API ve Verify yanında paket dışı Desktop host eklenir. Agent installer tarayıcı köprüsü olarak ayrı kalır. Desktop çıktısı yerel `{ad}-imzali.pdf` dosyası ve indirme/açma bağlantısıdır; HTTP indirme sunucusu açılmaz. Güven zinciri ve TSA bu dilimde yoktur; kriptografik doğrulama ile hukuki/kurumsal güven kararı ayrılır.

## Doğrulama

FR-119–121, SEC-028 ve TST-027 izlenebilirlik matrisine bağlıdır. CI sahte PKCS#11, çıktı adlandırma, installer yerleşimi, NuGet dışlama ve landing page bağlantısını doğrular. Fiziksel kart ve CredUI laboratuvar kabulüdür. Authenticode yoksa masaüstü installer yayımlanmaz.
