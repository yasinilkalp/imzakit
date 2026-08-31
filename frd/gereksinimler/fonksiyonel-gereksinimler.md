# Fonksiyonel Gereksinimler

## Gereksinim sınıflandırma politikası

Her gereksinimin tekil fazı, önceliği ve MVP engelleyici durumu [izlenebilirlik matrisinde](../ekler/gereksinim-izlenebilirlik-matrisi.md) bağlayıcı olarak tutulur. Özet sınıflandırma şöyledir:

| Alan | Kimlikler | Öncelik | Faz | MVP engelleyici |
|---|---|---|---:|---|
| Ortak MVP çekirdeği | FR-003–006 | Zorunlu | 1 | Evet |
| Agent/AKİS | FR-021–029 | Zorunlu | 1 | Evet |
| Agent/eToken | FR-030 | Yüksek | 1 | Hayır |
| PAdES B-B ve revision | FR-040–042, FR-046–051 | Zorunlu | 1 | Evet |
| PAdES için CMS alt kümesi | FR-060–063 | Zorunlu | 1 | Evet |
| Temel trust ve validation | FR-090–094, VAL-001–007 | Zorunlu | 1 | Evet |
| Uzun dönem PAdES ve online iptal | FR-043–045, FR-096–099 | Yüksek | 2 | Hayır |
| Bağımsız CAdES ve workflow | FR-064–065, FR-111–115 | Orta | 3 | Hayır |
| XAdES/ASiC | FR-070–076 | Sonraki | 4 | Hayır |
| eIDAS profil sınırı | FR-100 | Zorunlu | 5 | Hayır |
| CAdES archive-time-stamp-v3 | FR-066 | Sonraki | 6 | Hayır |
| ASiC-E ortak rapor bağ | VAL-008 | Sonraki | 6 | Hayır |
| Preservation CAdES/XAdES | FR-116 | Sonraki | 6 | Hayır |
| Preservation host tetikleyici | FR-117 | Sonraki | 6 | Hayır |
| Unix Agent HostReady | FR-118 | Sonraki | 6 | Hayır |
| Windows Desktop host | FR-119–121 | Yüksek | 1 | Hayır |

## 1. Ortak SDK

- **FR-001:** SDK; PAdES, CAdES, XAdES ve ASiC formatlarını ortak `ImzaFormatı` modeliyle sunmalıdır.
- **FR-002:** İmza seviyesi B-B/B-T/B-LT/B-LTA olarak açıkça belirtilmeli; desteklenmeyen geçiş reddedilmelidir.
- **FR-003:** Hazırlama ve tamamlama ayrılmalı; hazırlama sonucu deterministik `DataToBeSigned`, algoritma ve operasyon bağlamı içermelidir.
- **FR-004:** Format motorları yalnız sertifika ve `SignatureValue` kabul etmeli; PKCS#11 ayrıntısı bilmemelidir.
- **FR-005:** Hash, anahtar algoritması, token mekanizması ve CMS algoritma tanımlayıcısı ayrı modeller olmalıdır.
- **FR-006:** Tüm dışa açık asenkron işlemler cancellation ve correlation kimliği desteklemelidir.

## 2. PKCS#11 ve Agent

- **FR-020:** Birden fazla yapılandırılmış PKCS#11 sağlayıcısı ve modül yolu desteklenmelidir.
- **FR-021:** Agent `C_Initialize` yaşam döngüsünü process/provider seviyesinde, session yaşam döngüsünü operasyon seviyesinde yönetmelidir.
- **FR-022:** Slot ve token keşfi yalnız takılı tokenları listeleyebilmeli; token etiketi, üretici, model ve maskeli seri numarası sunmalıdır.
- **FR-023:** X.509 sertifikaları `CKO_CERTIFICATE`, `CKC_X_509`, `CKA_VALUE`, `CKA_ID` ve `CKA_LABEL` üzerinden okunmalıdır.
- **FR-024:** Sertifika ile private key öncelikle `CKA_ID`, kontrollü fallback ile public-key ilişkisi üzerinden eşlenmelidir.
- **FR-025:** İmza yetkisi olmayan/uygunsuz sertifikalar seçim ekranında ayrıştırılmalıdır.
- **FR-026:** PIN yalnız Agent’ın native güvenli arayüzünde alınmalı, sunucuya/browser’a/loga yazılmamalıdır.
- **FR-027:** Yanlış PIN, kilitli token, token çıkarılması, mekanizma uyumsuzluğu ve driver hataları ayrı hata kodları üretmelidir.
- **FR-028:** İlk doğrulanmış sağlayıcı AKİS olmalı; vendor özel davranışları adaptör/quirk profiline hapsedilmelidir.
- **FR-029:** Provider bazlı concurrency lock ve güvenli session cleanup uygulanmalıdır.
- **FR-030:** İkinci doğrulanmış Windows PKCS#11 profili eToken olmalıdır. Modül adı yalnız `eTPKCS11.dll` kabul edilmeli; varsayılan allowlist kökleri SafeNet Authentication Client `SAC\x64` ve Thales SafeNet Authentication Client `Program Files` yolları olmalıdır. Vendor DLL paketlenmemelidir. Quirk’ler `EtokenProviderProfile` içinde tutulmalı ve AKİS ile aynı güvenli varsayılanlarla başlamalıdır. Fiziksel eToken kabulü ayrı laboratuvar kanıtıdır; MVP çıkış kapısını değiştirmez.

## 3. PAdES ve PDF

- **FR-040:** PAdES B-B üretimi incremental update ile yapılmalı; `/ByteRange` imza placeholder’ını hariç tutmalıdır.
- **FR-041:** `/Contents` kapasitesi imza/timestamp/sertifika büyüklüğü için güvenli biçimde yönetilmeli; taşma atomik hata üretmelidir.
- **FR-042:** CMS detached olmalı ve PDF digest’i yalnız ByteRange kapsamındaki byte’lardan hesaplanmalıdır.
- **FR-043:** PAdES B-T, `SignatureValue` hash’i için RFC 3161 tokenı içermelidir.
- **FR-044:** B-LT, imzacı ve TSA zincirleri ile uygun OCSP/CRL kanıtlarını DSS’e gömmelidir.
- **FR-045:** B-LTA, validation material’ı kapsayan document timestamp revision’ı üretmelidir.
- **FR-046:** Mevcut imzaya dokunmadan yeni imza/revision eklenebilmelidir.
- **FR-047:** Her imza için kapsanan revision ve sonraki değişiklikler ayrı raporlanmalıdır.
- **FR-048:** DocMDP izin seviyesi ve ihlal durumu okunup uygulanmalıdır.
- **FR-049:** FieldMDP referansları okunmalı; kilitli alan değişikliği doğrulamada gösterilmelidir.
- **FR-050:** Görünür imza sayfa, koordinat, boyut, metin, tarih ve opsiyonel görsel modeliyle tanımlanmalıdır.
- **FR-051:** Görünür temsil kriptografik imzanın kanıtı gibi sunulmamalı; görünmez imza desteklenmelidir.

## 4. CMS ve CAdES

- **FR-060:** CMS çekirdeği detached ve encapsulated SignedData okuyup yazabilmelidir.
- **FR-061:** B-B başlangıç profili `contentType`, `messageDigest` ve `signingCertificateV2` signed attribute’larını içermelidir.
- **FR-062:** ESSCertIDv2 sertifikanın tam DER kodunun hash’iyle oluşturulmalıdır.
- **FR-063:** Signed attributes canonical DER olarak kodlanmalı ve doğrulamada orijinal imzalı byte’lar korunmalıdır.
- **FR-064:** CAdES B-T/B-LT/B-LTA uzatma hattı format-özel unsigned attribute’larla desteklenmelidir.
- **FR-065:** Çoklu SignerInfo yapıları ayrı ayrı doğrulanmalıdır.
- **FR-066:** CAdES B-LTA, ETSI EN 319 122-1 `archive-time-stamp-v3` ve `ATSHashIndex-v3` ile yazılmalı ve doğrulanmalıdır. Yalnız SignedData’nın tamamının SHA-256 özeti üzerine `archive-time-stamp` (id-aa-ets-archiveTimestampV2) yeterli sayılmaz.

## 5. XAdES ve ASiC

- **FR-070:** XAdES, enveloped/enveloping/detached XMLDSig kullanım biçimlerini politika ile sınırlandırarak desteklemelidir.
- **FR-071:** XML canonicalization, reference URI, transform ve namespace işlemleri güvenli allowlist üzerinden yürütülmelidir.
- **FR-072:** Harici URI dereference varsayılan olarak kapalı olmalıdır.
- **FR-073:** XAdES B-B/B-T/B-LT/B-LTA kanıtları ortak timestamp/trust/revocation hizmetlerini kullanmalıdır.
- **FR-074:** ASiC-S tek veri nesnesi, ASiC-E birden çok veri nesnesi ve imza için desteklenmelidir.
- **FR-075:** ASiC ZIP path traversal, duplicate entry, zip bomb ve aşırı sıkıştırma kontrolleri yapmalıdır.
- **FR-076:** `mimetype` ve `META-INF` yerleşimi deterministik/interoperable paketleme kurallarına uymalıdır.

## 6. Zaman damgası

- **FR-080:** RFC 3161 istekleri SHA-256 messageImprint, kriptografik nonce ve `certReq=true` ile üretilebilmelidir.
- **FR-081:** Yalnız `granted` ve `grantedWithMods` başarı sayılmalıdır.
- **FR-082:** Cevap nonce, messageImprint, politika OID, TSA CMS imzası, EKU `id-kp-timeStamping`, zincir ve iptal durumuyla doğrulanmalıdır.
- **FR-083:** Birden fazla TSA öncelik/failover ile desteklenmeli; timeout/503 gibi geçici hatalar retry/failover, bad request/policy gibi kalıcı hatalar doğrudan hata olmalıdır.
- **FR-084:** TSA credential’ları secret store’dan alınmalıdır.

## 7. Sertifika, Trust Store ve iptal kontrolü

- **FR-090:** Zincir kurma ve zincir doğrulama ayrı servisler olmalıdır.
- **FR-091:** Zincir kaynak önceliği embedded → local cache → yapılandırılmış repository/AIA olmalıdır.
- **FR-092:** Sistem trust store’u ile İmzaKit Türkiye ESHS Trust Store’u ayrı tutulmalıdır.
- **FR-093:** NES kararı tek bir sabit OID’e değil sürümlü ESHS/politika kataloğuna dayanmalıdır.
- **FR-094:** Doğrulama profilleri en az `TurkiyeNes`, `GenelX509` ve sonraki faz için `Eidas` olarak ayrılmalıdır.
- **FR-095:** Trust Store güncelleme paketi sürümlü ve imzalı olmalı; güvenilir release key ile doğrulanmadan etkinleşmemelidir.
- **FR-096:** İptal kaynağı önceliği embedded OCSP → cached OCSP → online OCSP → embedded CRL → cached CRL → online CRL olmalıdır.
- **FR-097:** OCSP cevap imzası, responder yetkisi, CertificateID, zaman alanları ve politika/nonce doğrulanmalıdır.
- **FR-098:** CRL imzası, issuer, AKI, thisUpdate/nextUpdate ve seri numarası doğrulanmalıdır.
- **FR-099:** Cache TTL’i kanıtın `nextUpdate`/freshness politikasından türetilmelidir.
- **FR-100:** `Eidas` doğrulama profili EU TSL/EUTL içe aktarmaz ve hukuki nitelikli elektronik imza (QES) kararı üretmez. Profil yalnız yapılandırılmış Eidas etiketli kök, sürümlü katalog politika OID’i ve QcCompliance uzantısını değerlendirir.

## 8. Doğrulama

- **VAL-001:** Nihai durum yalnız `PASSED`, `FAILED` veya `INDETERMINATE` olmalıdır.
- **VAL-002:** Kriptografik doğruluk, belge bütünlüğü, sertifika zinciri, politika, revocation, timestamp ve validation time ayrı sonuçlanmalıdır.
- **VAL-003:** Güvenilir zaman önceliği archive/document/signature timestamp kanıtlarına dayanmalı; CMS `signingTime` güvenilir zaman olarak etiketlenmemelidir.
- **VAL-004:** Her imza ve revision için ayrı rapor üretilmelidir.
- **VAL-005:** Ağ/kanıt yokluğu Türkiye NES varsayılan profilinde sessiz PASSED değil INDETERMINATE üretmelidir.
- **VAL-006:** Alt durumlar; signature/content invalid, certificate expired/not-yet-valid/revoked/suspended, chain/trust/policy failure, revocation unavailable/stale, timestamp invalid ve algorithm disallowed nedenlerini kapsamalıdır.
- **VAL-007:** Rapor, kullanılan Trust Store/politika sürümünü, validation time kaynağını ve kanıt kaynağını içermelidir.
- **VAL-008:** Ortak doğrulama raporu ASiC-E konteynerde ASiCManifest imza-veri bağını değerlendirmelidir. ASiC-S dışı paketler `AsicExtendedBindingNotEvaluated` ile INDETERMINATE bırakılamaz; bağ başarısızsa FAILED, bağ kanıtı yoksa INDETERMINATE üretilir.

Faz 1’de çevrimiçi OCSP/CRL sorgusu yapılmaz. Gerekli gömülü/yerel iptal kanıtı bulunmadığında VAL-005 sonucu `INDETERMINATE`, VAL-006 alt nedeni `REVOCATION_DATA_UNAVAILABLE` olur. API raporu çevrimiçi kontrolün yapılmadığını açıkça belirtir.

## 9. Çoklu ve iş akışlı imza

- **FR-110:** Bir belgeye birden çok bağımsız imza incremental revision’larla eklenebilmelidir.
- **FR-111:** Seri akışta bir adım tamamlanmadan sonraki adım hazırlanamaz; revision zinciri korunur.
- **FR-112:** Paralel akışta imzacılar aynı onaylanmış belge digest’ine bağlı ayrı imza artefaktları üretir; birleştirme stratejisi formatın kapasitesine göre açıkça seçilir.
- **FR-113:** PAdES paralel imzalarında her imzanın farklı revision’a eklenmesi nedeniyle imzalama sırası ve sonraki değişiklik semantiği raporlanmalıdır.
- **FR-114:** İmza politikası gerekli imzacı sayısı, rol, sıra, son tarih ve reddetme davranışını tanımlamalıdır.
- **FR-115:** Aynı imzacının tekrar imzası, sertifika parmak izi/kimlik politikasıyla kontrol edilmelidir.

## 10. Preservation ve platform olgunlaştırma

- **FR-116:** Preservation scheduler CAdES B-LTA archive-time-stamp ve XAdES B-LTA ArchiveTimeStamp yenilemesini PAdES B-LTA DocTimeStamp ile aynı due/lead-time sözleşmesinde uygulamalıdır. Bir nesnenin başarısızlığı diğer due öğeleri durdurmamalıdır.
- **FR-117:** Host, due preservation nesnelerini yapılandırılmış aralıkla tetikleyen bir zamanlayıcı (hosted service veya eşdeğer) çalıştırmalıdır. Yalnız çağıranın `PreservationScheduler.Run` çağırması yeterli sayılmaz.
- **FR-118:** Unix Agent’ta `HostReady` true ise native PIN ve onay işletim sisteminin güvenli deposu (macOS Keychain, Linux secret-service veya eşdeğeri) üzerinden alınmalıdır. `HostReady` false iken imza oturumu açılmamalıdır. Üretim Windows Agent hedefi [ADR-002](../kararlar/ADR-002-dotnet-platform-tabani.md) ile değişmez.

## 11. Windows Desktop host

- **FR-119:** İmzaKit Desktop, WinUI 3 unpackaged host olarak Windows’ta yerel PAdES B-B imzası üretmelidir. Host `ImzaKit.Hosts.Desktop` adıyla NuGet paketine girmez. Agent bileti, loopback ve API host zorunlu değildir ([ADR-008](../kararlar/ADR-008-winui-masaustu-imza-istemcisi.md)).
- **FR-120:** Kullanıcı PDF seçmeli, PKCS#11 sertifikasını seçmeli ve PIN’i native CredUI ile girmelidir. İmzalama `InProcessPadesSigningOrchestrator` ile yapılmalı; imzalı PDF `{ad}-imzali.pdf` olarak yazılmalı ve indirme/açma bağlantısı gösterilmelidir. WinUI `PasswordBox` PIN yedek değildir. Vendor PKCS#11 DLL paketlenmemelidir.
- **FR-121:** Desktop `setup.exe` Authenticode imzalı olmalı, GitHub Releases’te yayımlanmalı ve `site/index.html` bu özelliği sergilemelidir. `setup.exe` ikilisi `site/` klasörüne veya git kaynağına gömülmemelidir. Authenticode yoksa masaüstü installer yayımlanmamalıdır.

## 12. Fonksiyonel olmayan gereksinimler

- **NFR-001 Performans:** 10 MB tipik PDF için sunucu hazırlama/tamamlama hedefi, dış ağ gecikmesi hariç p95 2 saniyenin altında olmalıdır.
- **NFR-002 Ölçeklenebilirlik:** API ve Verify stateless yatay ölçeklenmelidir.
- **NFR-003 Dayanıklılık:** Tamamlama ve callback uçları idempotent olmalı; aynı istek aynı sonucu veya deterministik çakışmayı üretmelidir.
- **NFR-004 Limitler:** Belge boyutu, PDF nesne/revision sayısı, XML derinliği, ASiC entry sayısı ve ağ cevap boyutu yapılandırılabilir sınırlarla korunmalıdır.
- **NFR-005 Uyumluluk:** .NET sürüm tabanı LTS/kurumsal destek politikasıyla sürümlenmeli; public API semantic versioning izlemelidir.
- **NFR-006 Gözlemlenebilirlik:** Correlation/operation/tenant kimlikleri, metrikler ve dağıtık tracing desteklenmelidir.
- **NFR-007 Gizlilik:** Tenant ayrımı, aktarım/depolama şifrelemesi ve saklama süresi uygulanmalıdır.
- **NFR-008 Erişilebilirlik:** Agent native onay ekranı klavye ve ekran okuyucu kullanımına uygun olmalıdır.
- **NFR-009 Yerelleştirme:** Kullanıcı mesajları Türkçe ve İngilizce kaynaklarla sunulmalı; hata kodları dilden bağımsızdır.
- **NFR-010 Bakım:** Trust/policy/algorithm listeleri binary release gerektirmeden imzalı paketlerle güncellenebilmelidir.
