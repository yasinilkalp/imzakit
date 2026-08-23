# İmzaKit FRD Kesinleştirme Tasarımı

## 1. Amaç

Bu çalışma, mevcut İmzaKit FRD setini Faz 0 çalışmalarının başlatılabildiği ve Faz 1 MVP geliştirmesinin ölçülebilir kapılarla yönetilebildiği bağlayıcı ürün tabanına dönüştürür. Çalışma uygulama kodu üretmez; ürün kapsamını, varsayılan teknik kararları, API sözleşmesini, gereksinim izlenebilirliğini ve kabul koşullarını kesinleştirir.

## 2. Başarı ölçütü

FRD seti aşağıdaki koşullar birlikte sağlandığında kesinleştirilmiş sayılır:

1. Her MVP gereksinimi tekil faz, bileşen, test senaryosu ve kabul kanıtına bağlıdır.
2. MVP API uçları OpenAPI 3.1 ile makine tarafından doğrulanabilir biçimde tanımlanmıştır.
3. MVP mimarisini etkileyen sahipsiz veya kararsız kritik konu kalmamıştır.
4. PDF ve AKİS teknik risk azaltma çalışmalarının ölçülebilir giriş ve çıkış kriterleri vardır.
5. Faz 1 kapsamı ile MVP kabul kapısı arasında çelişki yoktur.
6. Lisans, bağımlılık, güvenlik, saklama ve audit varsayımları bağlayıcı kararlara dönüştürülmüştür.

## 3. Ürün ve lisans kararları

- İmzaKit; SDK, Agent, API ve Verify bileşenlerinin tamamını içeren açık kaynak bir ürün olacaktır.
- Proje kaynak kodu Apache License 2.0 altında yayımlanacaktır.
- Dağıtılan çekirdek bileşenlerin zorunlu bağımlılıkları Apache-2.0 ile uyumlu izin verici lisanslara sahip olmalıdır. Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause ve ISC varsayılan kabul listesidir.
- GPL, AGPL, SSPL, yalnız araştırma amaçlı, kaynak-kullanılabilir veya ticari lisans gerektiren bir bağımlılık zorunlu çalışma zamanı bağımlılığı yapılamaz.
- LGPL/MPL veya ikili istisna içeren diğer lisanslar otomatik kabul edilmez; dağıtım etkisi yazılı lisans incelemesiyle onaylanır.
- Bağımlılık lisansı, NOTICE yükümlülükleri ve SBOM sürüm kapısında otomatik olarak denetlenir.

## 4. Platform tabanı

- Sunucu, SDK ve test projelerinin birincil tabanı .NET 10 LTS olacaktır.
- Agent MVP platformu Windows x64 ve Windows arm64 olacaktır.
- Public .NET API semantic versioning uygular; geriye uyumsuz değişiklik yalnız ana sürümde yapılır.
- Windows dışı Agent uygulamaları Faz 5 kapsamındadır. Ortak Agent protokolü platform bağımsız modellenir fakat MVP kabulünü etkilemez.

## 5. Kesin MVP kapsamı

Faz 1 MVP aşağıdaki yeteneklerle sınırlıdır:

- PAdES B-B görünür ve görünmez imza
- Mevcut PDF imzalarını bozmadan incremental revision ekleme
- PAdES için gereken detached CMS SignedData üretimi ve doğrulaması
- RSA/SHA-256 başlangıç profili
- AKİS üzerinden PKCS#11 token, sertifika ve private-key eşleme
- Windows Agent üzerinde native onay ve PIN girişi
- Operasyon oluşturma, Agent bileti, sertifika seçme, prepare, complete, cancel ve sonuç alma akışı
- Temel Verify raporu: kriptografik doğruluk, PDF bütünlüğü, sertifika zamanı, zincir/güven ve kanıt bulunabilirliği
- PASSED, FAILED ve INDETERMINATE nihai durumları
- Temel çoklu PAdES revision desteği
- Tenant izolasyonu, idempotency, audit ve süreli belge saklama

Bağımsız CAdES ürünü ve çoklu SignerInfo Faz 3; XAdES ve ASiC Faz 4 kapsamındadır. PAdES’in kullandığı CMS alt kümesinin Faz 1’de bulunması, bağımsız CAdES ürününün MVP’ye alındığı anlamına gelmez.

## 6. Revocation ve doğrulama semantiği

- Faz 1, gömülü veya yerel olarak sağlanan iptal kanıtını okuyabilecek model sınırlarını içerir; çevrimiçi OCSP/CRL alma, cache, freshness ve SSRF korumalı fetcher Faz 2’dedir.
- Türkiye NES profilinde gerekli iptal kanıtı bulunamadığında sonuç PASSED değil `INDETERMINATE` olur ve alt neden `REVOCATION_DATA_UNAVAILABLE` olarak raporlanır.
- Geçerli ve güvenilir bir gömülü kanıt açıkça revoked/suspended sonucu verirse sonuç `FAILED` olur.
- Faz 1’in çevrimiçi iptal kontrolü yapmaması kullanıcıya ve API tüketicisine açıkça raporlanır; ağ kontrolü yapılmış izlenimi verilmez.
- PAdES B-T/B-LT/B-LTA, RFC 3161, çevrimiçi OCSP/CRL ve tam validation-time karar motoru Faz 2’dedir.

## 7. PDF motoru kararı

PDF motoru adı dokümana doğrulanmadan sabitlenmez. Faz 0’da Apache-2.0 ile uyumlu adaylar aynı test paketiyle değerlendirilir. Bir aday aşağıdaki koşulların tamamını sağlamadan seçilemez:

1. Mevcut byte’ları yeniden yazmadan incremental update üretebilme
2. Doğru `/ByteRange` ve boyutlandırılmış `/Contents` placeholder üretme
3. Mevcut imzaları ve revision zincirini koruma
4. DocMDP ve FieldMDP yapılarını en azından güvenilir biçimde okuma
5. Faz 2’de DSS/VRI ve document timestamp eklemeye izin veren genişleme noktası
6. Bozuk ve düşmanca PDF girdileri için boyut, obje, xref, stream ve dekompresyon limitleri
7. En az iki bağımsız doğrulayıcıyla uyumlu golden PAdES B-B çıktısı
8. Apache-2.0 dağıtımıyla uyumlu lisans ve NOTICE yükümlülükleri

Hiçbir aday kapıyı geçmezse `ImzaKit.PAdES` içinde yalnız incremental-signing ihtiyacına odaklanan izole bir PDF yazma katmanı geliştirilecektir. Bu katman genel amaçlı PDF kütüphanesi olmayacak; parsing mümkün olduğunda izin verici lisanslı bir okuyucu adaptörü üzerinden yapılacaktır.

## 8. Agent güven modeli

- Agent yalnız `127.0.0.1` ve `::1` üzerinde loopback HTTP dinler; dış ağ arayüzüne bind etmez.
- İstek yetkisi taşıma katmanı sertifikasına değil sunucu tarafından Ed25519 ile imzalanmış operasyon biletine dayanır.
- Bilet en fazla 120 saniye geçerlidir ve `issuer`, `audience`, `origin`, `operationId`, `tenantId`, `applicationId`, `documentSha256`, `allowedAction`, `nonce`, `issuedAt` ve `expiresAt` alanlarını bağlar.
- Nonce atomik ve tek kullanımlık tüketilir. Origin, audience, digest veya operasyon durumu uyuşmazlığı isteği reddeder.
- Geçerli bir bilet native kullanıcı onayının yerine geçmez. Agent belge adı, SHA-256 özeti, çağıran uygulama, sertifika özeti ve algoritmayı native pencerede gösterir.
- PIN yalnız native güvenli kontrol üzerinden alınır; managed `string`, browser, API payload’ı, telemetry, crash dump veya log içine girmez.
- CORS wildcard kullanılmaz. Yalnız bilete bağlı origin için gerekli yöntem ve başlıklara izin verilir.
- Agent imza sonucunu API’ye doğrudan gönderir. Callback kimlik doğrulaması cihaz kaydı sırasında verilen mTLS istemci sertifikasıyla yapılır.
- Cihaz kaydı yetkili uygulama yöneticisinin tek kullanımlık enrollment token’ı ile başlar. İstemci private key’i Agent içinde üretilir ve cihazı terk etmez; sertifika en fazla 30 gün geçerli olur, süresinin üçte ikisinde yenilenir ve yönetici tarafından anında iptal edilebilir.

## 9. API ve kimlik modeli

- OpenAPI 3.1, MVP HTTP sözleşmesinin kaynak tanımıdır.
- İnsan/kullanıcı bağlamlı istemciler OAuth 2.1 Authorization Code + PKCE/OIDC; servis istemcileri OAuth 2.0 Client Credentials veya mTLS kullanır.
- `tenantId` ve `applicationId` yetkili token claim’lerinden türetilir. İstemci payload’ındaki değerler yetki kaynağı olarak kabul edilmez.
- Operasyon oluşturma, Agent bileti oluşturma, sertifika bağlama, prepare, complete, cancel, validation oluşturma ve Agent callback işlemlerinde `Idempotency-Key` zorunludur.
- Aynı anahtar ve canonical request hash’i önceki yanıtı döndürür. Aynı anahtar farklı request hash’iyle kullanılırsa `409 Conflict` ve `IMZAKIT.CORE.IDEMPOTENCY_CONFLICT` üretilir.
- Problem Details hata modeli; dil bağımsız `code`, correlation kimliği, operasyon kimliği, retry bilgisi ve güvenli metadata içerir.
- OpenAPI; alan zorunluluklarını, enum değerlerini, boyut sınırlarını, durum geçişlerini, güvenlik şemalarını, callback modelini ve tüm hata yanıtlarını içerir.

## 10. Trust Store ve politika dağıtımı

- Türkiye Trust Store, işletim sistemi güven deposundan ayrıdır ve `TurkiyeNes` profiline özeldir.
- Trust Store içeriği açık bir Git deposunda şeffaf biçimde yayımlanır. Her sürüm release anahtarıyla imzalanır.
- Paket; sürüm, yayımlanma zamanı, sağlayıcı, sertifika DER/hash, rol, geçerlilik aralığı, politika OID’leri, kaynak URL/belge, provenance ve ekleme/kaldırma gerekçesi içerir.
- Çalışma zamanı yalnız güvenilir release public key ile doğrulanan paketleri atomik olarak etkinleştirir.
- Önceki paket sürümüne rollback ve acil trust removal prosedürü bulunur. Her doğrulama raporu kullanılan paket ve algoritma politikası sürümünü kaydeder.
- Güven çapalarının ve NES politika girdilerinin içerik onayı proje yönetişiminde tanımlanmış Trust Maintainer rolüne aittir. Teknik doğrulama, hukuki geçerlilik hükmü olarak sunulmaz.

## 11. Veri saklama ve audit

- Agent operasyon bileti TTL’i 120 saniyedir.
- Tamamlanmamış operasyon metadata’sı varsayılan 24 saat saklanır.
- Tamamlanan çıktı ve doğrulama raporu varsayılan 7 gün saklanır.
- Kurulum sahibi bu süreleri kısaltabilir veya açık bir ürün kararıyla uzatabilir; süresiz saklama varsayılan değildir.
- Redis yalnız kısa ömürlü operasyon durumu, nonce ve idempotency metadata’sı tutar. Belge içeriği Redis’te tutulmaz.
- Audit olayları append-only olarak yazılır ve olay zinciri önceki olay hash’iyle bütünlük koruması sağlar.
- Audit; ham belge, PIN, private key, credential, tam sertifika kişisel alanları veya raw token içermez.

## 12. Release ve tedarik zinciri

- NuGet paketleri, Agent installer’ı, container imajları, SBOM ve Trust Store paketleri CI tarafından imzalanır.
- Kaynak commit, build workflow ve artefakt digest ilişkisi release provenance içinde yayımlanır.
- Reproducible build hedeflenir; deterministik üretilemeyen artefaktların nedeni ve doğrulama yöntemi release notunda belirtilir.
- Kritik veya yüksek güvenlik bulgusu açıkken stabil sürüm yayımlanmaz.

## 13. Doküman değişiklikleri

### Güncellenecek dosyalar

- `frd/README.md`: doküman durumu, karar ve OpenAPI okuma sırası
- `frd/ana-dokuman/imzakit-fonksiyonel-gereksinimler-dokumani.md`: ürün/lisans/platform kararları, kesin MVP kapsamı ve kapanan açık kararlar
- `frd/gereksinimler/fonksiyonel-gereksinimler.md`: öncelik, faz ve doğrulanabilir kabul bağlantıları
- `frd/mimari/sistem-mimarisi.md`: Agent callback, kimlik sınırı, Trust Store dağıtımı ve saklama varsayımları
- `frd/api-ve-akislar/api-ve-is-akislari.md`: idempotency, auth, callback, durum geçişi ve OpenAPI kaynak sözleşmesi
- `frd/guvenlik/guvenlik-ve-guven-modeli.md`: bilet claim’leri, Ed25519, mTLS, audit bütünlüğü ve tedarik zinciri
- `frd/planlama/mvp-ve-fazlandirma.md`: Faz 0 kapıları ve Faz 1/Faz 2 revocation ayrımı
- `frd/test-ve-kabul/test-ve-kabul-stratejisi.md`: sözleşme, lisans, build ve tekil gereksinim testleri
- `frd/ekler/gereksinim-izlenebilirlik-matrisi.md`: gereksinim → faz → bileşen → test → kabul kanıtı eşlemesi
- `frd/ekler/terimler-sozlugu.md`: idempotency, operation ticket, provenance ve SBOM terimleri

### Oluşturulacak dosyalar

- `frd/api-ve-akislar/openapi.yaml`
- `frd/kararlar/README.md`
- `frd/kararlar/ADR-001-acik-kaynak-ve-lisans.md`
- `frd/kararlar/ADR-002-dotnet-platform-tabani.md`
- `frd/kararlar/ADR-003-agent-loopback-guven-modeli.md`
- `frd/kararlar/ADR-004-turkiye-trust-store.md`
- `frd/kararlar/ADR-005-pdf-motoru-secim-kapisi.md`
- `frd/kararlar/ADR-006-mvp-kapsami-ve-revocation.md`
- `frd/kararlar/ADR-007-saklama-ve-audit.md`

## 14. İzlenebilirlik modeli

Her bağlayıcı gereksinim için aşağıdaki alanlar tutulur:

- Gereksinim kimliği
- Kısa tanım
- Öncelik
- Hedef faz
- Sorumlu bileşen
- İlgili ADR/API şeması
- Test senaryosu kimliği
- Kabul kanıtı
- MVP engelleyici olup olmadığı

Aralık biçimindeki toplu eşleme yardımcı özet olarak kalabilir; tekil satırlar bağlayıcı kayıttır. Bir gereksinim testsiz veya fazsız bırakılamaz.

## 15. Doğrulama yaklaşımı

Doküman güncellemesi aşağıdaki kontrollerle doğrulanır:

1. Tüm `FR-*`, `NFR-*`, `SEC-*`, `VAL-*`, `API-*` ve `TST-*` kimliklerinin benzersizliği
2. Her bağlayıcı gereksinimin izlenebilirlik matrisinde bulunması
3. Her MVP gereksiniminin en az bir test senaryosuna bağlanması
4. OpenAPI 3.1 sözdizimi ve `$ref` bütünlüğü
5. Dokümanlar arasında Faz 1/Faz 2, TTL, algoritma, auth ve durum adlarının aynı olması
6. `TBD`, `TODO`, “sonra belirlenecek” ve sahipsiz açık karar taraması
7. Markdown bağlantılarının ve Mermaid bloklarının doğrulanması

## 16. Kapsam dışı

- Uygulama solution’ı veya üretim kodu oluşturmak
- PDF kütüphanesini prototip testleri yapılmadan seçmek
- Gerçek Trust Store sertifika listesini hukuki/operasyonel içerik onayı olmadan yayımlamak
- Faz 2–5 özellikleri için tam OpenAPI veya uygulama tasarımı üretmek
- Hukuki geçerlilik hakkında otomatik ya da mutlak hüküm tanımlamak
