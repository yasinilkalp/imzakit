# Fonksiyonel Gereksinimler

## Gereksinim sınıflandırma politikası

Her gereksinimin tekil fazı, önceliği ve MVP engelleyici durumu [izlenebilirlik matrisinde](../ekler/gereksinim-izlenebilirlik-matrisi.md) bağlayıcı olarak tutulur. Özet sınıflandırma şöyledir:

| Alan | Kimlikler | Öncelik | Faz | MVP engelleyici |
|---|---|---|---:|---|
| Ortak MVP çekirdeği | FR-003–006 | Zorunlu | 1 | Evet |
| Agent/AKİS | FR-021–029 | Zorunlu | 1 | Evet |
| PAdES B-B ve revision | FR-040–042, FR-046–051 | Zorunlu | 1 | Evet |
| PAdES için CMS alt kümesi | FR-060–063 | Zorunlu | 1 | Evet |
| Temel trust ve validation | FR-090–094, VAL-001–007 | Zorunlu | 1 | Evet |
| Uzun dönem PAdES ve online iptal | FR-043–045, FR-096–099 | Yüksek | 2 | Hayır |
| Bağımsız CAdES ve workflow | FR-064–065, FR-111–115 | Orta | 3 | Hayır |
| XAdES/ASiC | FR-070–076 | Sonraki | 4 | Hayır |

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

## 8. Doğrulama

- **VAL-001:** Nihai durum yalnız `PASSED`, `FAILED` veya `INDETERMINATE` olmalıdır.
- **VAL-002:** Kriptografik doğruluk, belge bütünlüğü, sertifika zinciri, politika, revocation, timestamp ve validation time ayrı sonuçlanmalıdır.
- **VAL-003:** Güvenilir zaman önceliği archive/document/signature timestamp kanıtlarına dayanmalı; CMS `signingTime` güvenilir zaman olarak etiketlenmemelidir.
- **VAL-004:** Her imza ve revision için ayrı rapor üretilmelidir.
- **VAL-005:** Ağ/kanıt yokluğu Türkiye NES varsayılan profilinde sessiz PASSED değil INDETERMINATE üretmelidir.
- **VAL-006:** Alt durumlar; signature/content invalid, certificate expired/not-yet-valid/revoked/suspended, chain/trust/policy failure, revocation unavailable/stale, timestamp invalid ve algorithm disallowed nedenlerini kapsamalıdır.
- **VAL-007:** Rapor, kullanılan Trust Store/politika sürümünü, validation time kaynağını ve kanıt kaynağını içermelidir.

Faz 1’de çevrimiçi OCSP/CRL sorgusu yapılmaz. Gerekli gömülü/yerel iptal kanıtı bulunmadığında VAL-005 sonucu `INDETERMINATE`, VAL-006 alt nedeni `REVOCATION_DATA_UNAVAILABLE` olur. API raporu çevrimiçi kontrolün yapılmadığını açıkça belirtir.

## 9. Çoklu ve iş akışlı imza

- **FR-110:** Bir belgeye birden çok bağımsız imza incremental revision’larla eklenebilmelidir.
- **FR-111:** Seri akışta bir adım tamamlanmadan sonraki adım hazırlanamaz; revision zinciri korunur.
- **FR-112:** Paralel akışta imzacılar aynı onaylanmış belge digest’ine bağlı ayrı imza artefaktları üretir; birleştirme stratejisi formatın kapasitesine göre açıkça seçilir.
- **FR-113:** PAdES paralel imzalarında her imzanın farklı revision’a eklenmesi nedeniyle imzalama sırası ve sonraki değişiklik semantiği raporlanmalıdır.
- **FR-114:** İmza politikası gerekli imzacı sayısı, rol, sıra, son tarih ve reddetme davranışını tanımlamalıdır.
- **FR-115:** Aynı imzacının tekrar imzası, sertifika parmak izi/kimlik politikasıyla kontrol edilmelidir.

## 10. Fonksiyonel olmayan gereksinimler

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
