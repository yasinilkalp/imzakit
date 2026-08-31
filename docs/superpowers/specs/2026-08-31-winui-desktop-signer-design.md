# ImzaKit WinUI Masaüstü İmza İstemcisi Tasarımı

**Tarih:** 31 Ağustos 2026  
**Durum:** Onaylandı  
**Hedef:** Paket dışı Windows host + `setup.exe` vitrini; NuGet paketi değişmez  
**FRD:** [ADR-008](../../../frd/kararlar/ADR-008-winui-masaustu-imza-istemcisi.md), FR-119–121, SEC-028, TST-027

## Amaç

ImzaKit’e, kullanıcının PDF seçip kart PIN’i ile PAdES B-B ürettiği ve imzalı dosya için yerel indirme/açma bağlantısı gördüğü birinci taraf bir **WinUI 3** uygulaması eklemek. Uygulama ImzaKit özelliği olarak sitede sergilenir; `ImzaKit` NuGet paketine girmez.

## Kararlar

1. Mimari yol: tamamen yerel WinUI 3 host; süreç içi SDK (`InProcessPadesSigningOrchestrator`). Agent bileti, loopback ve API host zorunlu değildir.
2. PIN yalnız mevcut Windows CredUI native diyaloğunda alınır. WinUI `PasswordBox` yedek değildir.
3. Çıktı yerel dosyadır (`{ad}-imzali.pdf`); HTTP indirme sunucusu açılmaz.
4. Dağıtım: Authenticode imzalı `setup.exe`, GitHub Releases. `site/index.html` Releases’e bağlanır. İkili `site/` veya git’e gömülmez.
5. Vendor `akisp11.dll` / `eTPKCS11.dll` kuruluma ve pakete konmaz; Agent ile aynı allowlist kökleri kullanılır.
6. İlk sürüm: PAdES B-B, görünmez imza, AKİS + eToken, self-contained `win-x64` (gerekirse `win-arm64`). TSA, Trust Store, görünür imza, XML/ASiC yoktur.
7. MVP kabul kapısı değişmez: gerçek AKİS + Agent + API yolu kilidi durur (FR-119–121 için `MVP = Hayır`).

## Kapsam

Kapsar:

- `src/ImzaKit.Hosts.Desktop` (WinUI 3, unpackaged, `IsPackable=false`)
- `tests/ImzaKit.Desktop.Tests` (oturum, çıktı, sahte PKCS#11)
- Agent’tan ayrı `DesktopInstallerLayout` + WiX `setup.exe`
- `site/index.html` Windows bölümü ve Releases indirme bağlantısı
- FRD: ADR-008, FR-119–121, SEC-028, TST-027, terim, mimari, izlenebilirlik

Kapsamaz:

- Agent installer ile tek MSI birleştirme
- `setup.exe` ikilisinin `site/` içine commit edilmesi
- NuGet’e Desktop DLL ekleme
- WinUI içinde PIN kutusu
- PAdES B-T/B-LT/B-LTA, görünür imza, XAdES/ASiC
- Türkiye Trust Store veya hukuki NES/QES iddiası
- macOS/Linux masaüstü istemcisi

## Mimari

`ImzaKit.Hosts.Desktop`, `ImzaKit.Hosts.Api` gibi paket dışı host’tur. Self-contained `win-x64` yayımlanır; kullanıcıda .NET 10 kurulumu beklenmez.

```text
Kullanıcı
  → WinUI kabuğu (tek pencere)
      → oturum (dosya, sertifika, sonuç yolu)
          → InProcessPadesSigningOrchestrator  (mevcut SDK)
              → PKCS#11 (AKİS / eToken allowlist)
              → CredUI PIN
          → imzalı PDF diske yazılır
          → “İndir / aç” bağlantısı
```

Agent installer ayrı kalır: tarayıcı köprüsü. Desktop, birinci taraf masaüstü imza istemcisidir.

## Bileşenler

| Birim | Görevi | Bağımlılığı |
|---|---|---|
| `App` | DI kökü: `AddImzaKitCore`, PKCS#11, CredUI | SDK, Windows App SDK |
| `MainWindow` | Pencere çerçevesi | `SignPage` |
| `SignPage` | Dört blok: dosya, sertifika, imzala, sonuç | ViewModel |
| `SignSessionViewModel` | Durum: boş → dosya → sertifika → imzalanıyor → hazır / hata | `DesktopPadesSigner` |
| `TokenCertificateCatalog` | Slot ve sertifika özeti listesi | `IPkcs11Provider` |
| `DesktopPadesSigner` | CredUI PIN + orchestrator | SDK, `INativePinPrompt` |
| `SignedPdfOutput` | `{ad}-imzali.pdf` yazar, dosya yolu üretir | dosya sistemi |

İmzalama mantığı XAML kod-behind’de durmaz.

## Veri akışı

1. PDF seçilir; ekranda yol ve SHA-256 özeti gösterilir; baytlar imza anında okunur.
2. Allowlist’ten `akisp11` / `eTPKCS11` varsa yüklenir. `DiscoverTokens` ve PIN’siz `FindCertificates` liste üretir. Kart yoksa liste boştur; uygulama kapanmaz.
3. **İmzala** CredUI PIN alır; `char[]` bitince sıfırlanır. Orchestrator prepare → `C_Login`/`C_Sign` → complete → `PadesValidator.Validate(pdf)` çalıştırır.
4. Başarıda aynı klasöre `{ad}-imzali.pdf` yazılır (çakışmada `-2`, `-3`). HyperlinkButton dosyayı açar; “Klasörde göster” Explorer `/select` kullanır.

PIN log, disk ve UI alanına yazılmaz. Doğrulama ilk sürümde ByteRange ve kriptografik imza ile sınırlıdır; güven zinciri `Indeterminate` olabilir. Ekran “imza belgede; kurumsal güven deposu bu uygulamada yok” uyarısını gösterir.

## Hata işleme

Fail-closed: PIN, özel anahtar veya yarım PDF sızdırılmaz. Hatalar kullanıcı dilinde ve kodla gösterilir.

| Durum | Davranış |
|---|---|
| PDF değil / PAdES ön kontrol reddi | İmza başlamaz |
| Kart yok / DLL allowlist dışında | Boş liste; sürücü/kart uyarısı |
| Kart imza sırasında çıktı | `TokenRemoved` |
| Yanlış PIN | `PinIncorrect`; kilit sayacı karta bırakılır |
| PIN kilitli | `PinLocked`; tekrar deneme yok |
| CredUI iptali | İptal; dosya ve sertifika seçimi kalır |
| Sürücü / mekanizma | `DriverError` / `MechanismUnsupported` |
| Çıktı yazılamaz | Bellekteki imzalı bayt; SaveFileDialog |
| İkinci İmzala | Buton kilitli |

Başarısız complete’te çıktı dosyası oluşmaz veya yarım dosya silinir. Cryptographic `Failed` ise bağlantı gösterilmez. CredUI yoksa imza üretilmez.

## Test, kurulum ve site

CI gerçek kart, CredUI veya `setup.exe` ikilisi çalıştırmaz.

- `SignedPdfOutput`, `SignSessionViewModel`, `TokenCertificateCatalog`, sahte PKCS#11 ile `DesktopPadesSigner`
- `DesktopInstallerLayout`: `%ProgramFiles%\ImzaKit\Desktop`, Authenticode zorunlu, vendor DLL yok
- NuGet paketi `ImzaKit.Hosts.Desktop` içermez
- `verify-landing-page.ps1`: TR/EN Windows bölümü, Releases href, `site/` içinde `.exe` yok, NuGet birincil eylem
- Fiziksel AKİS/eToken kabulü CI dışı laboratuvar listesidir
- Authenticode yoksa masaüstü installer yayımlanmaz

## Açık noktalar

Yok. Uygulama sırası ayrı implementation planındadır.
