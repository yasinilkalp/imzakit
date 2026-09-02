# İmzaKit Fonksiyonel Gereksinimler Dokümanı

## 1. Doküman bilgileri

| Alan | Değer |
|---|---|
| Ürün | İmzaKit — Türkiye Elektronik İmza Entegrasyon Kiti |
| Hedef kitle | Teknoloji şirketleri, SaaS/ERP/EBYS üreticileri, fintech ve kurumsal yazılım ekipleri |
| Birincil platform | .NET |
| Ürün ailesi | İmzaKit SDK, İmzaKit Agent, İmzaKit API, İmzaKit Verify |
| Durum | Ürün ve mimari temeli oluşturan FRD |
| Kaynak lisansı | Apache License 2.0; ürünün tamamı açık kaynak |
| Platform tabanı | .NET 10 LTS; MVP Agent Windows x64/arm64 |

## 2. Amaç ve ürün konumlandırması

İmzaKit birincil olarak **developer-first entegrasyon kiti ve platformudur**; teknoloji şirketleri elektronik imza işlevlerini kendi ürünlerine ekler. Belge yönetim portalı veya tekil e-imza hizmeti değildir.

Ürün; PAdES, CAdES, XAdES ve ASiC formatlarında imza oluşturma/doğrulama, RFC 3161 zaman damgası, Türkiye NES/ESHS güven politikası, PKCS#11 tabanlı akıllı kart/token/HSM erişimi ve ayrıntılı doğrulama raporlamasını ortak bir çekirdek üzerinde sağlar.

İmzaKit’in Türkiye katmanı, ETSI formatlarını “Türkiye’ye özgü standartlar” olarak yeniden tanımlamaz. Yerel uyum; 5070 sayılı Elektronik İmza Kanunu ve ilgili düzenlemeler, NES niteliklerinin değerlendirilmesi, ESHS sertifika politikaları ve OID katalogları, güven çapaları ile yerel zaman damgası/iptal kontrol altyapısında ortaya çıkar. Hukuki uygunluk, teknik doğrulama sonucundan ayrı değerlendirilir ve ürün dokümantasyonu hukuk görüşü yerine geçmez.

## 3. İş hedefleri

- MA3 benzeri kapalı/lisanslı bir bağımlılığa alternatif, modüler ve sağlayıcıdan bağımsız bir entegrasyon temeli sunmak.
- .NET geliştiricilerinin düşük seviyeli ASN.1, CMS, PDF incremental update ve PKCS#11 ayrıntılarını yönetmeden güvenli imza akışları kurabilmesini sağlamak.
- Özel anahtarı kart/token/HSM dışına çıkarmadan web, masaüstü ve sunucu uygulamalarını aynı ürün ailesiyle desteklemek.
- “Geçerli/geçersiz” ikilisinin ötesinde kanıtları açıklayan PASSED, FAILED ve INDETERMINATE sonuçları üretmek.
- İmza formatlarını, kriptografik sağlayıcıları ve güven politikalarını gevşek bağlı bileşenler olarak tutmak.

## 4. Kapsam

### 4.1 Kapsam içi

- .NET SDK ve bağımlılık enjeksiyonu uzantıları
- Windows odaklı yerel Agent; loopback güvenli iletişim
- REST tabanlı İmzaKit API
- Bağımsız doğrulama servisi/kütüphanesi olan İmzaKit Verify
- PKCS#11; ilk doğrulanmış adaptör olarak AKİS, ikinci doğrulanmış Windows profili olarak eToken (`eTPKCS11.dll`)
- RSA/SHA-256 başlangıç profili; SHA-384/SHA-512 ve ECDSA genişleme noktaları
- PAdES B-B, B-T, B-LT, B-LTA
- CMS çekirdeği ve CAdES baseline profilleri
- XAdES baseline profilleri
- ASiC-E/ASiC-S paketleme yaklaşımı
- RFC 3161 TSA, sertifika zinciri, Trust Store, OCSP ve CRL
- Çoklu, seri ve paralel imza iş akışları
- Görünür PDF imzası, PDF revisions, DocMDP ve FieldMDP
- Redis tabanlı kısa ömürlü durum; ayrı belge/nesne saklama
- Gözlemlenebilirlik, güvenlik, test, paketleme ve fazlandırma

### 4.2 Kapsam dışı veya sonraki faz

- Özel kriptografik primitive geliştirmek
- Sertifika veya zaman damgası hizmet sağlayıcısı olmak
- Nitelikli sertifika üretmek ya da kullanıcı kimlik doğrulaması yapmak
- İlk MVP’de macOS/Linux Agent, mobil imza ve tüm HSM/uzak imza sağlayıcıları
- İlk MVP’de görsel iş akışı tasarım aracı veya son kullanıcı belge yönetim portalı (Desktop tek ekranlı yerel imza host’udur; portal değildir)
- Hukuki geçerlilik hakkında otomatik ve mutlak hüküm vermek
- EU TSL/EUTL içe aktarma ve hukuki nitelikli elektronik imza (QES) kararı (FR-100)
- CAdES `archive-time-stamp-v3` / `ATSHashIndex-v3` (FR-066, Faz 6)
- Ortak doğrulama raporunda ASiC-E ASiCManifest bağ değerlendirmesi (VAL-008, Faz 6)
- CAdES/XAdES archive timestamp yenileme ve host periyodik tetikleyici (FR-116/FR-117, Faz 6)
- macOS/Linux üretim Agent `HostReady` (FR-118, Faz 6); fizibilite Faz 5’te kapanmıştır

## 5. Paydaşlar ve kullanıcı rolleri

| Rol | Beklenti |
|---|---|
| Entegrasyon geliştiricisi | Tutarlı .NET API, örnekler, hata kodları ve test ortamı |
| Ürün sahibi | Format/faz seçimi, SLA ve lisans yönetimi |
| Son kullanıcı/imzacı | Açık belge özeti, sertifika seçimi, kontrollü PIN girişi ve onay |
| Sistem yöneticisi | Agent dağıtımı, sağlayıcı/TSA/Trust Store yapılandırması |
| Güvenlik ekibi | Anahtar izolasyonu, audit, allowlist, bütünlük ve güncelleme güvenliği |
| Denetçi | Yeniden üretilebilir doğrulama raporu ve kanıt kaynakları |

## 6. Ürün bileşenleri

### 6.1 İmzaKit SDK

NuGet üzerinden tüketilen ortak domain, CMS, format, sertifika, iptal, zaman damgası ve doğrulama modülleridir. PDF veya XML gibi format modülleri PKCS#11’a doğrudan bağımlı olmaz; yalnızca `SignatureValue` ve sertifika/kanıt modelleriyle çalışır.

### 6.2 İmzaKit Agent

Kullanıcının cihazında çalışan, kart/token keşfi, sertifika seçimi, yerel onay, PIN girişi ve PKCS#11 `C_Sign` işlemlerini yürüten uygulamadır. Özel anahtar ve PIN Agent sınırını terk etmez.

### 6.3 İmzaKit API

Belge hazırlama, imza operasyonu oluşturma, Agent bağlantısı, imzanın tamamlanması, timestamp/uzatma, doğrulama ve sonuç indirme akışlarını yöneten sunucu katmanıdır.

### 6.4 İmzaKit Verify

İmzalama yeteneğinden bağımsız kullanılabilen format tespiti ve doğrulama motorudur. Belge ve her imza için ayrı rapor üretir; çevrimdışı kanıtları önceler, ağ erişimini politika ile sınırlar.

## 7. Temel ürün ilkeleri

1. Özel anahtar hiçbir zaman token/kart/HSM dışına çıkmaz.
2. Kriptografik geçerlilik ile güvenilir/hukuken nitelikli imza aynı sonuç olarak gösterilmez.
3. Format motoru, imza sağlayıcısından bağımsızdır.
4. Ağ hatası ya da kanıt yokluğu sessizce PASSED sonucuna çevrilmez.
5. Ham belge ve PIN varsayılan olarak loglanmaz.
6. İmza seviyeleri uzatma hattıyla ilerler: B-B → B-T → B-LT → B-LTA.
7. Büyük ikili veriler Redis’te tutulmaz; Redis operasyon durumu ve kısa ömürlü metadata içindir.
8. Her operasyon idempotent, süreli ve denetlenebilir olmalıdır.

## 8. Üst seviye yetenekler

| Yetenek | Beklenen sonuç |
|---|---|
| Kart/token keşfi | PKCS#11 slot/token/sertifika listesinin güvenli sunumu |
| İmzalama hazırlığı | Formatın imzalanacak kesin byte dizisini üretmesi |
| Yerel imza | Kullanıcı onayı ve PIN sonrası `SignatureValue` üretimi |
| Tamamlama | CMS/format yapısının imza değeriyle birleştirilmesi |
| Zaman damgası | RFC 3161 token alma ve bağımsız doğrulama |
| Uzun dönem imza | Sertifika/OCSP/CRL kanıtlarını gömme ve document/archive timestamp |
| Doğrulama | PASSED/FAILED/INDETERMINATE ve alt nedenler |
| İş akışı | Tekli, çoklu, seri ve paralel imza |
| Görsel imza | PDF sayfasına görünür temsil; kriptografik imzadan ayrı model |

## 9. Başarı ölçütleri

- Referans AKİS kartıyla uçtan uca PAdES B-B imzası üretilebilir ve Verify ile doğrulanabilir.
- İmza öncesi/sonrası PDF byte bütünlüğü ve revision değişiklikleri açıklanabilir.
- RFC 3161, OCSP ve CRL hataları belirgin hata/alt durumlara dönüşür.
- En az iki harici doğrulayıcıyla PAdES/CAdES interoperabilite matrisi çalışır.
- Agent yalnız loopback’te hizmet verir; geçersiz/tekrar kullanılan operasyon bileti reddedilir.
- Her fonksiyonel gereksinimin kabul testi veya planlanan fazı bulunur.

## 10. Kabul edilmiş kararlar ve Faz 0 kapıları

- Ürünün tamamı Apache License 2.0 altında açık kaynaktır; bağımlılık politikası [ADR-001](../kararlar/ADR-001-acik-kaynak-ve-lisans.md) ile bağlayıcıdır.
- Birincil taban .NET 10 LTS; MVP Agent hedefleri Windows x64/arm64 ve ilk sağlayıcı AKİS’tir ([ADR-002](../kararlar/ADR-002-dotnet-platform-tabani.md)). İkinci doğrulanmış Windows PKCS#11 profili eToken’dır; MVP çıkış kapısını değiştirmez.
- İlk imzalama profili RSA/SHA-256’dır; algoritma politikası sürümlenir.
- Agent loopback HTTP, Ed25519 imzalı 120 saniyelik tek kullanımlık bilet, native onay ve mTLS callback kullanır ([ADR-003](../kararlar/ADR-003-agent-loopback-guven-modeli.md)).
- Türkiye Trust Store işletim sistemi deposundan ayrıdır; imzalı ve sürümlü paket olarak yayımlanır ([ADR-004](../kararlar/ADR-004-turkiye-trust-store.md)).
- PDF motoru yalnız sekiz maddelik Faz 0 kapısını geçerse seçilir ([ADR-005](../kararlar/ADR-005-pdf-motoru-secim-kapisi.md)). Bu ölçüm kararı sahipsiz bırakmaz; seçilecek uygulamayı kanıta bağlar.
- MVP PAdES B-B ile sınırlıdır. Çevrimiçi OCSP/CRL Faz 2’dedir; Faz 1’de kanıt yokluğu `INDETERMINATE/REVOCATION_DATA_UNAVAILABLE` üretir ([ADR-006](../kararlar/ADR-006-mvp-kapsami-ve-revocation.md)).
- Varsayılan saklama süreleri ve audit modeli [ADR-007](../kararlar/ADR-007-saklama-ve-audit.md) ile belirlenmiştir.
- Birinci taraf WinUI masaüstü imza istemcisi geri çekilmiştir ([ADR-009](../kararlar/ADR-009-winui-masaustu-imza-istemcisi-geri-cekildi.md); [ADR-008](../kararlar/ADR-008-winui-masaustu-imza-istemcisi.md) geçersizdir).

## 11. Kesin MVP kapsamı

MVP; PAdES B-B görünür/görünmez imza, PAdES için gerekli detached CMS alt kümesi, AKİS/PKCS#11, Windows Agent, operasyon API’si, temel Verify, PASSED/FAILED/INDETERMINATE kararları ve temel çoklu PDF revision desteğidir. PAdES B-T/B-LT/B-LTA Faz 2; bağımsız CAdES Faz 3; XAdES/ASiC Faz 4’tedir.
