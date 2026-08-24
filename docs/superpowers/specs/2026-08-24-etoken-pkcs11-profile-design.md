# ImzaKit eToken PKCS#11 Profili Tasarımı

**Tarih:** 24 Ağustos 2026  
**Durum:** Onaylandı  
**Hedef sürüm:** `1.0.0-alpha.7`

## Amaç

Windows Agent/PKCS#11 sınırına, AKİS’ten sonra ikinci doğrulanmış üretici profili olarak SafeNet/Thales **eToken** (`eTPKCS11.dll`) eklemek. Profil yazılımda ve FRD’de resmi olur; fiziksel token kabulü ayrı laboratuvar listesine bağlanır. MVP çıkış kapısı AKİS kartından kopmaz.

## Kararlar

1. İlk doğrulanmış sağlayıcı AKİS kalır (`FR-028` metni bu önceliği korur).
2. İkinci doğrulanmış Windows PKCS#11 profili eToken’dır (`FR-030`).
3. `eTPKCS11.dll` NuGet paketinde ve MSI’de yoktur; yalnız allowlist’teki mutlak yoldan yüklenir.
4. Varsayılan allowlist kökleri üretici `Program Files` klasörleridir. `%WINDIR%\System32` varsayılan kök değildir; host kendi allowlist’ine ekleyebilir.
5. Desteklenen dosya adı yalnız `eTPKCS11.dll`’dir. Eski `eToken.dll` bu dilimde yoktur.
6. Quirk başlangıcı AKİS ile aynıdır: tek iş parçacığı, `CKA_ID` öncelikli eşleme, `CKM_SHA256_RSA_PKCS`. Sapma yalnız laboratuvar kanıtından sonra profile yazılır.
7. PIN HTTP gövdesine, CLI argümanına, loga ve audit’e girmez; mevcut native PIN penceresi kullanılır.
8. CI ve birim testler sahte native API kullanır. Fiziksel eToken yokken eToken donanım kabulü iddia edilmez.
9. `FR-030` Faz 1 yazılım kapsamındadır; izlenebilirlikte **MVP = Hayır**. MVP kabulü gerçek AKİS kartına bağlı kalır.

## Kapsam

Bu dilim şunları kapsar:

- `EtokenProviderProfile` ve `NativePkcs11ProviderOptions.ForEtoken()`
- PKCS#11 loader’ın seçilen profilin izinli dosya adlarını kabul etmesi
- Agent installer allowlist köklerine SafeNet/Thales `Program Files` yollarının eklenmesi
- eToken laboratuvar script’i ve kontrol listesi (modül yoksa çıkış kodu 2)
- FRD: `FR-030`, terim, mimari, faz notu, izlenebilirlik, test kimliği
- README / teknik rehber / durum raporunda ikinci profilin belgelenmesi

Bu dilim şunları kapsamaz:

- `%WINDIR%\System32` varsayılan allowlist kökü
- `eToken.dll` veya diğer SafeNet DLL adları
- `eTPKCS11.dll` veya `akisp11.dll` paketleme/MSI kopyası
- Spekülatif eToken sapmaları (`CKM_RSA_PKCS` yedek mekanizma, boş `CKA_ID` için yeni eşleme kuralı)
- Linux `libeTPkcs11.so` / macOS Agent
- Fiziksel eToken PAdES B-B kanıtı (kart ve sürücü olmadan kapanmaz)
- Yeni PKCS#11 native API veya yeni hata kodu ailesi

## Mimari

Mevcut katmanlar değişmez: format motorları PKCS#11 bilmez; `NativePkcs11Provider` `IPkcs11Provider` uygular; vendor farkı profil + `NativePkcs11ProviderOptions` içindedir.

```text
Host / Agent
  -> Pkcs11NativeLibraryLoader.Load(path, roots, profile.SupportedLibraryFileNames)
  -> NativePkcs11Provider(api, NativePkcs11ProviderOptions.ForEtoken() | ForAkis())
  -> Pkcs11SigningService
  -> CMS / PAdES (yalnız SignatureValue + sertifika)
```

Dosya adından otomatik vendor tahmini yoktur. Host hangi profili yüklediğini açıkça seçer. `Pkcs11ProviderCatalog` adları: `AKİS` ve `eToken`.

Yükleme anı allowlist **profil başına** uygulanır. eToken `Load` çağrısı yalnız eToken köklerini (ve host’un bilinçle eklediği ekstra kökleri, örneğin `System32`) alır. AKİS `Load` çağrısı yalnız AKİS köklerini alır. İki kök kümesi tek listede birleştirilip her iki dosya adına açılmaz; aksi halde `AKIS\eTPKCS11.dll` gibi isim çakışması allowlist’i deler.

## Bileşenler

### `EtokenProviderProfile`

Yol: `src/ImzaKit.Pkcs11/Etoken/EtokenProviderProfile.cs`

| Alan | Değer |
|---|---|
| `Name` | `eToken` |
| `SigningMechanism` | `CKM_SHA256_RSA_PKCS` |
| `MatchPrivateKeyByCkaIdFirst` | `true` |
| `RequiresSingleThreadedProviderAccess` | `true` |
| `SupportedLibraryFileNames` | `["eTPKCS11.dll"]` |
| `RecommendedAllowlistRoots` | aşağıdaki iki kök |

Önerilen kök şablonları (installer / dokümantasyon):

- `%ProgramFiles%\SafeNet\Authentication\SAC\x64`
- `%ProgramFiles%\Thales\SafeNet Authentication Client`

Çalışma anında `Load` çağrısı genişletilmiş mutlak yollar alır (`Environment.SpecialFolder.ProgramFiles`). Şablon dizgesi `Path.GetFullPath` ile çözülmez.

### Loader

`Pkcs11NativeLibraryLoader.Load` bugün `AkisProviderProfile.SupportedLibraryFileNames` sabitler. Bu dilimde:

- Mevcut iki parametreli `Load(path, roots)` AKİS adlarını kullanmaya devam eder (geriye uyum).
- Üç parametreli `Load(path, roots, allowedFileNames)` eToken ve diğer profiller için zorunludur.
- `Pkcs11ModulePath.ResolveAllowed` kuralları değişmez: mutlak yol, izinli dosya adı, kök altında olma, `..` normalizasyonu.

Reddedilen örnekler:

- göreli `eTPKCS11.dll`
- allowlist dışı klasör
- SafeNet kökünde `akisp11.dll`
- AKİS kökünde `eTPKCS11.dll` (o kök eToken adını taşımaz)
- `eToken.dll`

### Seçenekler

`NativePkcs11ProviderOptions.ForEtoken()` `ForAkis()` ile aynı bayrakları üretir:

- `RequiresSingleThreadedProviderAccess = true`
- `MatchPrivateKeyByCkaIdFirst = true`
- `AllowPublicKeyFallback = true`
- `ExcludeCertificatesWithoutSignableKey = true`

`NativePkcs11Provider` varsayılanı `ForAkis()` olarak kalır; eToken host’u `ForEtoken()` geçirmek zorundadır.

### Installer

`AgentInstallerPayload.Pkcs11AllowlistRoots` AKİS kökü olarak kalır. Yeni `EtokenPkcs11AllowlistRoots` alanı eToken kök şablonlarını taşır. Agent yüklemede profil adına göre ilgili listeyi kullanır. WiX kaynağı her iki kök kümesini yayımlayabilir; `eTPKCS11` ve `akisp11` dosya adı içermez.

### Laboratuvar

`scripts/run-etoken-hardware-lab.ps1`:

- Varsayılan yol: `%ProgramFiles%\SafeNet\Authentication\SAC\x64\eTPKCS11.dll`
- Aksi halde `IMZAKIT_ETOKEN_MODULE`
- Modül yoksa `ETOKEN_HARDWARE_SKIPPED` ve çıkış kodu **2**
- PIN kabul etmez (parametre yok)

`docs/evidence/etoken-hardware-checklist.md` AKİS listesinin eToken karşılığıdır; maddeler işaretlenmeden eToken donanım kabulü yazılmaz.

## Hata modeli

Yeni `Pkcs11ErrorCode` eklenmez. Yanlış PIN, kilit, token çıkarma, mekanizma uyumsuzluğu ve sürücü hataları mevcut `Pkcs11RvMapper` ile kalır. Allowlist/ad reddi `ArgumentException` üretir; native yükleme başarısızlığı `Pkcs11ProviderException` / `DriverError` üretir.

## Test

Birim testler gerçek `eTPKCS11.dll` yüklemez ve CredUI açmaz.

- `EtokenProviderProfileTests`: ad, mekanizma, dosya adı, kök şablonları, AKİS ile aynı concurrency/`CKA_ID` bayrakları
- `Pkcs11ModulePathTests`: `eTPKCS11.dll` allowlist kabulü; `eToken.dll` reddi; AKİS adının eToken kökünde reddi
- `NativePkcs11ProviderTests`: `ForEtoken()` ile sahte native API üzerinde keşif/imza (mevcut fake API)
- `AuthenticodeAndMsiLayoutTests`: köklerde SafeNet/Thales var; `etpkcs11` WiX metninde yok
- Laboratuvar script’i: PIN parametresi yok; modül yokken çıkış 2 (mevcut AKİS script doğrulama stili)

`TST-021`: eToken profil sözleşmesi, allowlist ve sahte native imza. Fiziksel token `TST-001` benzeri laboratuvar maddesidir; CI’yi kırmızıya çekmez.

## FRD değişiklikleri

Kaynak tanım `frd/gereksinimler/fonksiyonel-gereksinimler.md` içinde `- **FR-030:**` biçiminde olmak zorundadır (`scripts/validate-frd.ps1`).

**FR-030:** İkinci doğrulanmış Windows PKCS#11 profili eToken olmalıdır. Modül adı yalnız `eTPKCS11.dll` kabul edilir; varsayılan allowlist kökleri SafeNet Authentication Client `SAC\x64` ve Thales SafeNet Authentication Client `Program Files` yollarıdır. Vendor DLL paketlenmez. Quirk’ler `EtokenProviderProfile` içinde tutulur ve AKİS ile aynı güvenli varsayılanlarla başlar. Fiziksel eToken kabulü ayrı laboratuvar kanıtıdır; MVP çıkış kapısını değiştirmez.

Ayrıca:

- Sınıflandırma tablosuna Agent/eToken satırı (`FR-030`, Yüksek, Faz 1, MVP hayır)
- `FR-028` metni “ilk doğrulanmış sağlayıcı AKİS” olarak kalır
- Terimler: eToken, eTPKCS11
- Ana doküman ve mimari: PKCS#11 ilk AKİS, ikinci eToken profili
- Fazlandırma: Faz 1 yazılım profili; Faz 1 çıkış kapısı hâlâ KamuSM/AKİS kartı
- Faz 5 “ek vendor” maddesi eToken’ı ikinci kez vaat etmez; eToken bu dilimde kapanır
- Matris satırı: `FR-030 | eToken PKCS#11 profili | Yüksek | 1 | Pkcs11 | ADR-003 | TST-021 | eToken profil birim testi ve laboratuvar listesi | Hayır`
- `TST-021` test stratejisine eklenir
- FRD dosyalarında `TBD` / `TODO` olmaz

## Güvenlik

- SEC-009 korunur: allowlist + tam dosya adı; `System32` varsayılan değildir.
- Vendor DLL search-order hijack için Agent `DisableDllSearchPathHijacking` mevcut kuralı sürer.
- PIN, özel anahtar ve ham belge log/audit yasağı değişmez.

## Başarı ölçütü

- `dotnet test` PKCS#11 ve Release testleri yeşil
- `scripts/validate-frd.ps1` yeşil
- Paket hâlâ 12 `ImzaKit.*` DLL; `eTPKCS11.dll` yok
- Fiziksel eToken yokken donanım kabulü iddia edilmez
