# ImzaKit Alpha.4 Çevrimdışı Trust ve Validation Tasarımı

**Tarih:** 23 Ağustos 2026  
**Durum:** Onaylandı  
**Hedef sürüm:** `1.0.0-alpha.4`

## Amaç

ImzaKit'in mevcut PDF/CMS kriptografik doğrulamasını FRD Faz 1 güven modeline genişletmek; sertifika zinciri, doğrulama profili ve çevrimdışı iptal kanıtlarını ayrı sonuçlandırarak güvenli `PASSED / FAILED / INDETERMINATE` kararı üretmek.

Bu dilim mevcut `PadesValidator.Validate(pdf)` kullanımını korur ve yapılandırılmış doğrulama için yeni bir bağlam kabul eden overload ekler.

## Kapsam

Alpha.4 şunları kapsar:

- X.509 sertifika zinciri kurma ve zincir doğrulama
- `GeneralX509` ve `TurkiyeNes` doğrulama profilleri
- Değişmez, sürümlü trust store ve politika kataloğu modelleri
- Embedded ve yerel OCSP/CRL kanıtlarının çevrimdışı değerlendirilmesi
- Kanıt yokluğunda `INDETERMINATE / RevocationDataUnavailable`
- Zincir, politika, revocation ve validation-time alt sonuçları
- Trust/politika sürümü ile kanıt kaynağının raporlanması
- Mevcut doğrulama API'sinin geriye uyumlu genişletilmesi

Alpha.4 şunları kapsamaz:

- Çevrimiçi AIA, OCSP veya CRL erişimi
- Revocation cache ve freshness tabanlı ağ cache TTL yönetimi
- RFC 3161 zaman damgası
- PAdES B-T, B-LT veya B-LTA
- Trust store paketinin indirilmesi, release-key ile imza doğrulaması, atomik güncelleme veya rollback
- `Eidas` profilinin çalıştırılması

Bu kapsam FRD Faz 1 ile sınırlıdır; ağ erişimi ve uzun dönem imza Faz 2'de ele alınır.

## Modül mimarisi

Üç yeni üretim modülü tek `ImzaKit` NuGet paketine eklenir:

### `ImzaKit.Certificate`

X.509 ayrıştırma, zincir kurma ve zincir doğrulama sorumluluğunu taşır. Trust politikası veya revocation kaynak önceliği bilmez.

Temel servisler:

- `ICertificateChainBuilder`
- `CertificateChainBuilder`
- `ICertificateChainValidator`
- `CertificateChainValidator`

Zincir kaynak önceliği Alpha.4 için `embedded → local` olur. Ağ tabanlı repository/AIA kaynağı yoktur.

### `ImzaKit.Trust`

Trust anchor, doğrulama profili ve politika kataloğunu taşır. Sertifika zincirinin seçilen profile göre kabul edilip edilmediğini değerlendirir.

Temel tipler:

- `ValidationProfile`
- `TrustStoreSnapshot`
- `CertificatePolicyCatalog`
- `ITrustPolicyEvaluator`
- `TrustPolicyEvaluator`

Trust store ve politika kataloğu değişmezdir. Her ikisi de rapora yazılacak zorunlu bir sürüm kimliğine sahiptir. Alpha.4 bu girdilerin dağıtımını veya imzasını doğrulamaz; çağıranın daha önce doğruladığı girdileri kabul eder.

### `ImzaKit.Revocation`

Çevrimdışı revocation kanıt modellerini, kaynaklarını ve değerlendirme sonucunu taşır. Ağ erişimi yapmaz.

Temel tipler:

- `RevocationEvidenceSet`
- `RevocationEvidenceSource`
- `RevocationStatus`
- `IOfflineRevocationEvaluator`
- `OfflineRevocationEvaluator`

Kaynak önceliği `embedded OCSP → local OCSP → embedded CRL → local CRL` olur. Kanıtlar hedef sertifika, issuer, zaman aralığı ve kriptografik geçerlilik bağlamıyla değerlendirilir.

### `ImzaKit.Verify`

Mevcut PDF `ByteRange` ve CMS doğrulamasını korur; yeni Certificate, Trust ve Revocation servislerini birleştirerek ayrıntılı raporu ve nihai kararı üretir.

Yeni `IPadesValidationService` ve `PadesValidationService` instance tabanlı orkestrasyonu sağlar. Mevcut statik `PadesValidator`, kaynak uyumluluğu için facade olarak kalır; eski overload mevcut davranışı korur, bağlam alan overload varsayılan stateless servislerle `PadesValidationService` oluşturup çağrıyı devreder. DI kullanıcıları doğrudan `IPadesValidationService` tüketir.

## Bağımlılık yönü

- `ImzaKit.Certificate` yalnız `ImzaKit.Core` ve platform X.509 API'lerine bağlıdır.
- `ImzaKit.Trust`, `ImzaKit.Certificate` modellerini tüketir.
- `ImzaKit.Revocation`, sertifika kimliğini tüketir ancak `ImzaKit.Trust` bilmez.
- `ImzaKit.Verify`, Certificate, Trust ve Revocation modüllerini orkestre eder.
- `ImzaKit.Revocation`, OCSP ve CRL ASN.1 ayrıştırma/kriptografik doğrulaması için `BouncyCastle.Cryptography` kullanır.
- Format modülleri PKCS#11, trust store veya revocation uygulamasına doğrudan bağlanmaz.
- `ImzaKit.DependencyInjection`, varsayılan servisleri kaydeder.

Bağımlılık döngüsüne izin verilmez.

## Doğrulama bağlamı

Yeni `ValidationContext`, tek bir doğrulama çalışmasının bütün girdilerini taşır:

- `ValidationProfile Profile`
- `DateTimeOffset ValidationTimeUtc`
- `ValidationTimeSource ValidationTimeSource`
- `TrustStoreSnapshot TrustStore`
- `CertificatePolicyCatalog PolicyCatalog`
- embedded ara sertifikalar
- yerel ara sertifikalar
- `RevocationEvidenceSet RevocationEvidence`

Bağlam oluşturulurken koleksiyonlar kopyalanır veya değişmez koleksiyona çevrilir. UTC olmayan doğrulama zamanı reddedilir. Alpha.4 için güvenilir timestamp bulunmadığından varsayılan zaman kaynağı `CurrentSystemTime` olarak raporlanır; bu kaynak güvenilir imza zamanı sayılmaz.

## Doğrulama veri akışı

1. `PadesValidator` PDF yapısını ve `ByteRange` alanını doğrular.
2. Detached CMS imzası doğrulanır ve imzacı sertifikası çıkarılır.
3. `CertificateChainBuilder`, embedded ve yerel sertifikalardan aday zinciri kurar.
4. `CertificateChainValidator`, sertifika imzalarını, geçerlilik zamanını, Basic Constraints, Key Usage ve zincir bütünlüğünü doğrular.
5. `TrustPolicyEvaluator`, root anchor ve sertifika politikalarını seçilen profile göre değerlendirir.
6. `OfflineRevocationEvaluator`, zincirde değerlendirilmesi gereken sertifikalar için mevcut çevrimdışı kanıtları inceler.
7. `ValidationDecisionEngine`, alt sonuçları deterministik biçimde birleştirir.
8. `PadesValidationReport`, alt durumları, reason code'ları, kullanılan sürümleri, zamanı ve kanıt kaynaklarını döndürür.

## Profiller

### `GeneralX509`

- Zincirin yapılandırılmış trust anchor'lardan birine ulaşmasını ister.
- Sertifika imzaları, zaman geçerliliği, CA kısıtları ve imzalama Key Usage kontrol edilir.
- Belirli bir Türkiye NES politika OID'i şart koşmaz.
- Revocation gereksinimi bağlamdaki katalog politikasıyla açıkça belirtilir; Alpha.4 varsayılanı kanıt yokluğunda `INDETERMINATE` olur.

### `TurkiyeNes`

- Zincirin Türkiye profiline atanmış trust anchor'lardan birine ulaşmasını ister.
- İmzacı sertifikasının izin verilen politika kataloğu kaydıyla eşleşmesini ister.
- Tek sabit OID kullanmaz; sürümlü katalog girdileri değerlendirilir.
- Gerekli çevrimdışı revocation kanıtı yoksa sessiz `PASSED` üretmez.

`Eidas` enum üyesi Alpha.4 public sözleşmesine eklenmez. Sonraki fazda gerçek davranışıyla birlikte eklenir.

## Zincir kurma ve doğrulama

Zincir kurma ile doğrulama ayrı servislerdir.

`CertificateChainBuilder`:

- Sertifikaları subject/issuer ve Authority Key Identifier/Subject Key Identifier ilişkileriyle eşler.
- Aynı sertifika için embedded kaynağı local kaynağa tercih eder.
- Döngüleri ve azami zincir derinliğini kontrol eder.
- Aday zinciri ve her elemanın kaynağını döndürür.
- Eksik zinciri sonuç modeliyle bildirir; olağan doğrulama problemi için exception fırlatmaz.

`CertificateChainValidator`:

- Zincirdeki imzaları doğrular.
- Leaf ve issuer geçerlilik zamanlarını kontrol eder.
- Issuer sertifikalarında Basic Constraints ve keyCertSign kullanımını kontrol eder.
- Leaf sertifikasında digitalSignature kullanımını kontrol eder.
- İzin verilmeyen algoritmaları reason code ile bildirir.

Platformun sistem trust store'u otomatik olarak kullanılmaz. Sistem trust store ve ImzaKit trust store birbirinden ayrı kalır.

## Trust store ve politika kataloğu

`TrustStoreSnapshot` en az şunları taşır:

- `Version`
- trust anchor sertifikaları
- her anchor için geçerli profil etiketleri
- isteğe bağlı provenance tanımı

`CertificatePolicyCatalog` en az şunları taşır:

- `Version`
- profil
- izin verilen sertifika politika OID'leri
- katalog girdisinin etkinlik zaman aralığı

Boş sürüm, yinelenen anchor veya sözdizimsel olarak geçersiz OID oluşturma zamanında reddedilir. Katalog güncelleme ve paket imzası Alpha.4 kapsamında değildir.

## Çevrimdışı revocation

`RevocationEvidenceSet`, OCSP ve CRL kanıtlarını kaynak bilgisiyle taşır. Kanıt kaynağı `Embedded` veya `Local` olur.

Değerlendirici şu sonuçlardan birini üretir:

- `Good`
- `Revoked`
- `Suspended`
- `Unavailable`
- `Stale`
- `Invalid`

Kanıt hedef sertifikaya ait değilse kullanılmaz ve bulgu üretilir. Freshness, bağlam doğrulama zamanına göre `thisUpdate`, `nextUpdate` ve katalog toleransıyla değerlendirilir. Kriptografik olarak doğrulanamayan veya yetkisiz responder/issuer tarafından üretilen kanıt `Invalid` olur.

Alpha.4 hiçbir kanıt URL'sini izlemez ve ağ isteği oluşturmaz.

## Rapor sözleşmesi ve geriye uyumluluk

Mevcut alanlar korunur:

- `Status`
- `ByteRangeStatus`
- `CryptographicStatus`
- `TrustStatus`
- `SignerCertificateSha256`
- `Findings`

Yeni ayrıntılar eklenir:

- `ChainStatus`
- `PolicyStatus`
- `RevocationStatus`
- `ValidationTime`
- `ValidationTimeSource`
- `ValidationProfile`
- `TrustStoreVersion`
- `PolicyCatalogVersion`
- kullanılan kanıt kaynakları

Mevcut positional record constructor'ını kırmamak için rapor modeli geriye uyumlu birincil alanları korur; yeni alanlar varsayılan değerli özellikler veya uyumlu factory üzerinden eklenir. Mevcut `Validate(ReadOnlySpan<byte>)` imzası korunur.

Yeni overload:

```csharp
PadesValidationReport Validate(
    ReadOnlySpan<byte> pdf,
    ValidationContext context);
```

Varsayılan overload trust kaynağı sağlanmadığı için geçerli kriptografik imzada mevcut davranışı korur: genel sonuç ve trust sonucu `Indeterminate`, bulgu `TrustNotEvaluated` olur.

## Durum ve reason code modeli

Alt bileşenler mevcut `ValidationStatus` değerlerini kullanır:

- `Passed`
- `Failed`
- `Indeterminate`

Makinece okunur `ValidationReasonCode` başlangıç kümesi:

- `CertificateExpired`
- `CertificateNotYetValid`
- `CertificateChainIncomplete`
- `CertificateChainInvalid`
- `TrustAnchorNotFound`
- `CertificatePolicyNotAllowed`
- `RevocationDataUnavailable`
- `RevocationDataStale`
- `RevocationDataInvalid`
- `CertificateRevoked`
- `CertificateSuspended`
- `ValidationTimeUntrusted`
- `AlgorithmDisallowed`

`ValidationFinding`, mevcut `Code` ve `Message` kullanımını korur; yeni typed reason code bilgisi geriye uyumlu olarak eklenir. Uygulamalar karar verirken mesaj metnine bağlı kalmamalıdır.

## Nihai karar kuralları

Karar önceliği deterministiktir:

1. PDF bütünlüğü veya CMS kriptografisi başarısızsa `FAILED`.
2. Zincir kriptografisi, sertifika zamanı, trust anchor veya zorunlu politika kesin başarısızsa `FAILED`.
3. Sertifika `Revoked` veya `Suspended` ise `FAILED`.
4. Gerekli zincir ya da revocation kanıtı yoksa/stale ise `INDETERMINATE`.
5. Doğrulama zamanı güvenilir timestamp'e dayanmıyorsa bu bilgi raporlanır; Faz 1 sistem zamanı tek başına diğer kesin kontrolleri başarısız yapmaz.
6. Bütün zorunlu kontroller geçtiyse `PASSED`.

Kesin başarısızlık, aynı rapordaki belirsizlikten önceliklidir.

## Hata davranışı

- Beklenen doğrulama olumsuzlukları exception değil rapor sonucu üretir.
- Null, UTC olmayan zaman, boş sürüm veya yapısal olarak geçersiz katalog gibi programlama/yapılandırma hataları oluşturma zamanında argument exception üretir.
- Sertifika ve kanıt byte dizileri savunmacı biçimde kopyalanır.
- Hassas sertifika alanları ve kanıt gövdeleri loglanmaz.
- Ağ erişimi yapılmadığı için AIA/OCSP/CRL URL'leri SSRF yüzeyi oluşturmaz.

## Bağımlılık enjeksiyonu

`AddImzaKitCore()` aşağıdaki varsayılan stateless servisleri kaydeder:

- `ICertificateChainBuilder`
- `ICertificateChainValidator`
- `ITrustPolicyEvaluator`
- `IOfflineRevocationEvaluator`
- `ValidationDecisionEngine`
- `IPadesValidationService`

Trust store, katalog ve doğrulama zamanı çağrı bazlı `ValidationContext` üzerinden sağlanır; global mutable singleton kullanılmaz.

## Test stratejisi

Üç yeni test projesi eklenir:

- `ImzaKit.Certificate.Tests`
- `ImzaKit.Trust.Tests`
- `ImzaKit.Revocation.Tests`

Test sertifikaları çalışma sırasında üretilir. Gerçek kimlik veya üretim sertifikası depoya konmaz.

Zincir testleri:

- geçerli leaf/intermediate/root zinciri
- eksik ara sertifika
- güvenilmeyen root
- expired ve not-yet-valid sertifika
- bozuk sertifika imzası
- CA olmayan issuer ve eksik keyCertSign
- leaf üzerinde eksik digitalSignature
- zincir döngüsü ve derinlik sınırı

Profil testleri:

- `GeneralX509` trust anchor kabulü
- `TurkiyeNes` profil etiketli anchor kabulü
- izin verilen ve verilmeyen politika OID'i
- katalog etkinlik zamanı
- trust/politika sürümünün rapora taşınması

Revocation testleri:

- kanıt yokluğu
- fresh ve stale kanıt
- good, revoked ve suspended
- yanlış sertifikaya ait kanıt
- geçersiz kanıt imzası veya yetkisiz issuer/responder
- embedded kaynağın local kaynağa önceliği

Karar motoru testleri:

- kesin hata → `Failed`
- kanıt eksikliği/stale → `Indeterminate`
- bütün kontroller geçerli → `Passed`
- kesin hata ile belirsizlik birlikteyken `Failed`

Uyumluluk ve entegrasyon testleri:

- mevcut `Validate(pdf)` davranışı
- mevcut rapor alanlarının kaynak uyumluluğu
- PAdES B-B + test trust kataloğu + çevrimdışı kanıt uçtan uca sonucu
- değiştirilmiş belge her bağlamda `Failed`
- bağlam koleksiyonlarında savunmacı kopyalama

## Paketleme ve dokümantasyon

Tek `ImzaKit` NuGet paketi yeni üç modülle toplam 12 üretim DLL'i taşır. Paket doğrulama script'i yeni modül listesini ve iç paket bağımlılığının sıfır kalmasını kontrol eder.

Güncellenecek artefaktlar:

- bilingual `README.md`
- NuGet README içeriği
- etkileşimli teknik kullanım rehberi
- landing page modül/yetenek bilgisi
- canlı geliştirme durum raporu
- paket doğrulama ve yayın sözleşmeleri

Alpha.4, geliştirme ve testler tamamlanmadan yayımlanmaz. Yayın ayrı bir onay ve Trusted Publishing çalışması gerektirir.

## Kabul ölçütleri

- Mevcut 90 test gerileme olmadan geçer.
- Yeni modül testleri tamamen geçer.
- Mevcut `PadesValidator.Validate(pdf)` kaynak davranışı korunur.
- Yapılandırılmış bağlamla geçerli zincir/politika/kanıt `Passed` üretir.
- Kanıt yokluğu `Indeterminate / RevocationDataUnavailable` üretir.
- Revoked/suspended sertifika `Failed` üretir.
- Sistem trust store otomatik kullanılmaz.
- Hiçbir doğrulama yolu ağ erişimi yapmaz.
- Tek NuGet 12 DLL, iki dilli README ve sıfır iç paket bağımlılığıyla doğrulanır.
- Release build sıfır hata ve sıfır uyarıyla tamamlanır.
- FRD izlenebilirlik ve dokümantasyon kontrolleri geçer.
