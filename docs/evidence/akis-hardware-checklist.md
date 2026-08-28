# AKİS Donanım Kabul Kontrol Listesi

**Durum:** Adaptör kodu hazır; fiziksel referans kart, izinli vendor sürücüsü ve kontrollü Windows laboratuvarı olmadan **çalıştırılmadı**. CI sahte native API ile yeşil kalır. Bu listedeki MVP maddeleri işaretlenmeden ürün “gerçek AKİS kabulü geçti” veya “üretime hazır” olarak etiketlenmez.

**Kapsam:** Faz 0 AKİS kapısı, Faz 1 MVP çıkış kapısının kart ayağı, `TST-001`, `TST-002`, `FR-021`–`FR-029`. eToken ayrı listededir ve MVP’yi kilitlemez.

**Nasıl çalıştırılır:** Kart takılı Windows laboratuvarında `scripts/run-akis-hardware-lab.ps1`. PIN asla komut satırı, ortam değişkeni, HTTP veya git’e yazılmaz; `CredUI` (`ISecurePinDialog`) kullanılır.

İlgili kısa özet: [akis-gercek-kart-kontrol-listesi.md](./akis-gercek-kart-kontrol-listesi.md).

## Yasaklar

- PIN, özel anahtar, ham PDF, tam sertifika DER/PEM, kişi adı veya maskelenmemiş seri bu depoya eklenmez.
- `akisp11.dll` paketlenmez ve MSI’ya kopyalanmaz.
- Laboratuvar çıktısı olarak yalnız tarih, mimari, sürücü sürümü, kart modeli, maskeli seri ve SHA-256 hash yazılır.

## 0. Ortam

- [ ] Windows `win-x64` veya `win-arm64`; ImzaKit sürümü veya commit kaydı.
- [ ] KamuSM AKİS ara katmanı kurulu; `akisp11.dll` mutlak yolda. Agent varsayılan kök `%ProgramFiles%\AKIS`. KamuSM kurulumu sıkça `%WINDIR%\System32\akisp11.dll` kopyalar; laboratuvar script’i bunu keşfeder ama System32 üretim Agent allowlist’ine otomatik eklenmez (SEC-009).
- [ ] Referans KamuSM/AKİS kartı takılı; kişisel üretim kartı zorunlu değil, laboratuvar kartı tercih.
- [ ] `IMZAKIT_AKIS_MODULE` (isteğe bağlı) `akisp11.dll` mutlak yolunu gösteriyor.
- [ ] `scripts/run-akis-hardware-lab.ps1` ortam özetini üretti (modül yolu, dosya sürümü, DLL SHA-256). PIN parametresi yok.

## 1. Modül yükleme ve yaşam döngüsü — FR-020, FR-021, FR-028, FR-029, SEC-009

- [ ] `Pkcs11NativeLibraryLoader.Load` yalnız allowlist kökünden ve `akisp11.dll` adıyla yükleniyor; göreli yol ve allowlist dışı dizin reddediliyor.
- [ ] `NativePkcs11ProviderOptions.ForAkis()`: tek iş parçacığı, `CKA_ID` öncelikli eşleme.
- [ ] `C_Initialize` süreç/sağlayıcı seviyesinde; oturum operasyon seviyesinde. İkinci `Initialize` sağlayıcıda no-op.
- [ ] Packed `CK_ATTRIBUTE` (Cryptoki `pack(1)`): `C_GetAttributeValue` gerçek sürücüde `CKA_VALUE` / `CKA_ID` döndürüyor; boş veya kaymış tampon yok.
- [ ] Oturum `Logout` + `CloseSession`; sağlayıcı `Finalize` (FR-029).

## 2. Keşif (PIN yok) — FR-022, TST-001

PIN’siz otomatik adım: script, `-p:AKIS_HARDWARE_LAB=true` ile `AkisHardwareLabTests.DiscoverTokensFromAllowlistedVendorModule` çalıştırır. Bu test CI süitine dahil değildir.

- [ ] Yalnız takılı token listeleniyor.
- [ ] Etiket, üretici, model dolu.
- [ ] Seri `****` + son en fazla 4 karakter (`Pkcs11Token.MaskedSerialNumber`).

## 3. Sertifika ve anahtar — FR-023, FR-024, FR-025, TST-001

PIN yalnız native pencerede.

- [ ] `CKO_CERTIFICATE` + `CKC_X_509`; `CKA_VALUE`, `CKA_ID`, `CKA_LABEL` okunuyor.
- [ ] Private key aynı `CKA_ID` ile bulunuyor; gerekirse kontrollü public-key fallback.
- [ ] İmza yetkisi olmayan sertifikalar seçim listesinde ayrışıyor (`ExcludeCertificatesWithoutSignableKey`).
- [ ] Private key `CKA_VALUE` okunmuyor.

## 4. PAdES B-B round-trip — FR-026, FR-040–042, TST-001, MVP çıkış

- [ ] PIN `CredUI` ile alındı; sunucu, tarayıcı, log ve komut satırına yazılmadı.
- [ ] `CKM_SHA256_RSA_PKCS` kart içinde üretildi (`Pkcs11SigningStatus.Succeeded`).
- [ ] Incremental PAdES B-B: `/ByteRange` `/Contents`’i hariç tutuyor; CMS detached.
- [ ] `PadesValidator.Validate`: kriptografi geçerli. Gömülü/yerel iptal kanıtı yoksa genel sonuç `INDETERMINATE`, alt neden `REVOCATION_DATA_UNAVAILABLE` beklenir (ADR-006).
- [ ] İki bağımsız doğrulayıcı (laboratuvar: PdfPig+SignedCms ve PDFsharp+BouncyCastle; mümkünse Adobe/EU DSS) beklenen sonucu veriyor.
- [ ] Çıktı PDF git’e konmadı; yalnız SHA-256 kaydı.

## 5. Olumsuz senaryolar — FR-027, TST-002

Her biri ayrı kod; `DriverError` çöp kovası değil.

| Senaryo | Beklenen |
|---|---|
| [ ] Yanlış PIN | `PinIncorrect` |
| [ ] Kilitli PIN | `PinLocked` |
| [ ] Kart çekme / token yok | `TokenRemoved` veya `TokenNotFound` |
| [ ] Desteklenmeyen mekanizma | `MechanismUnsupported` |
| [ ] Sürücü restart / yükleme hatası | `DriverError` |

## 6. Hijyen — TST-014, SEC

- [ ] Log, audit ve crash dump taraması: PIN, private key, credential, ham belge, tam sertifika yok.
- [ ] Audit varsa append-only; kişisel alan yok.

## Kanıt kaydı

Laboratuvar oturumu bittikten sonra aşağıdaki bloğu doldurup bu dosyada işaretleri güncelleyin. Kişisel veri yok.

```
Tarih (UTC):
Windows sürümü / mimari:
ImzaKit sürüm veya commit:
akisp11.dll yolu:
akisp11.dll dosya sürümü:
akisp11.dll SHA-256:
Kart modeli (kişisel olmayan):
Maskeli seri:
Token etiketi:
PAdES çıktı SHA-256:
PadesValidator durumu / kriptografi / trust:
Bağımsız doğrulayıcı 1:
Bağımsız doğrulayıcı 2:
Olumsuz senaryo sonuçları:
Operatör (baş harf):
```

## Bu listenin kilitlemediği işler

- Native onay erişilebilirliği (NFR-008) ve yerelleştirme (NFR-009)
- Agent → API mTLS enrollment
- Authenticode / installer dağıtım imzası
- eToken fiziksel kabulü
- Çevrimiçi OCSP/CRL ve PAdES B-T/B-LT/B-LTA (Faz 2)
- İkinci görünür imza (`/Annots` zaten varsa)
