# Test ve Kabul Stratejisi

## 1. Test katmanları

1. Birim: DER, ByteRange, state transition, policy ve hata eşlemeleri.
2. Golden vector: sabit PDF/CMS/XML/ASiC girdileri ve beklenen byte/raporlar.
3. Entegrasyon: mock PKCS#11, gerçek AKİS kartı, gerçek eToken (laboratuvar), TSA, OCSP/CRL ve storage.
4. Interoperabilite: en az iki bağımsız doğrulayıcı ve mümkün olduğunda ETSI/EU DSS test araçları.
5. Güvenlik: kötü niyetli belge corpus’u, SSRF, replay, CORS/origin, zip/XML/PDF bombaları.
6. Dayanıklılık: token çıkarma, Agent kapanması, network timeout, Redis/storage kesintisi, duplicate callback.
7. Performans: tipik ve maksimum belge boyutları, çoklu imza/revision ve eşzamanlı operasyon.

## 2. Zorunlu senaryolar

- **TST-001:** AKİS token keşfi, sertifika okuma, CKA_ID/private key eşleme ve RSA/SHA-256 imza.
- **TST-002:** Yanlış PIN, kilitli token, kart çıkarma, desteklenmeyen mekanizma ve driver restart.
- **TST-003:** PAdES B-B üretimi, ByteRange manipülasyonu ve yetersiz `/Contents` kapasitesi.
- **TST-004:** Geçerli/yanlış nonce, messageImprint, TSA imzası, EKU, politika ve zincir senaryoları.
- **TST-005:** B-B → B-T → B-LT → B-LTA uzatma ve çevrimdışı B-LT doğrulama.
- **TST-006:** Birden çok PDF imzası, önceki revision değişikliği, DocMDP ve FieldMDP ihlali.
- **TST-007:** Geçerli, süresi dolmuş, henüz geçerli olmayan, iptal/suspend ve trust anchor bulunmayan sertifika.
- **TST-008:** OCSP good/revoked/unknown, stale cevap, yetkisiz responder; CRL signature/freshness hataları.
- **TST-009:** PASSED/FAILED/INDETERMINATE karar tablosunun tüm ana dalları.
- **TST-010:** XAdES canonicalization/reference wrapping ve external entity/URI saldırıları.
- **TST-011:** ASiC zip-slip, duplicate entry, zip bomb, bozuk mimetype ve çoklu imza.
- **TST-012:** Agent ticket expiry, replay, origin mismatch, değiştirilmiş document digest ve duplicate completion.
- **TST-013:** Tenant izolasyonu, süreli URL ve saklama süresi silme politikası.
- **TST-014:** Loglarda PIN/credential/ham belge bulunmadığının otomatik taraması.
- **TST-015:** OpenAPI 3.1 parse, `$ref`, operationId benzersizliği ve geriye uyumluluk sözleşme testi.
- **TST-016:** Aynı idempotency anahtarıyla aynı/farklı canonical request hash ve duplicate callback senaryoları.
- **TST-017:** mTLS enrollment, cihaz private-key izolasyonu, 30 günlük rotation ve anlık revocation.
- **TST-018:** Apache-2.0 bağımlılık allowlist’i, NOTICE ve reddedilen lisanslarla release kapısı.
- **TST-019:** İmzalı artefakt, SBOM, provenance ve kaynak commit/digest doğrulaması.
- **TST-020:** 120 saniye/24 saat/7 gün TTL, tenant izolasyonu, audit hash-chain bozulması ve hassas veri taraması.
- **TST-021:** eToken profil sözleşmesi, `eTPKCS11.dll` allowlist, sahte native imza; fiziksel token laboratuvar listesi CI’yi durdurmaz.
- **TST-022:** CAdES B-LTA `archive-time-stamp-v3` ve `ATSHashIndex-v3` yazma/doğrulama; yalnız v2 `archive-time-stamp` yeterli sayılmaz.
- **TST-023:** ASiC-E ortak raporda ASiCManifest bağ PASSED/FAILED; bozuk digest FAILED; `AsicExtendedBindingNotEvaluated` ile durulamaz.
- **TST-024:** CAdES ve XAdES B-LTA preservation yenilemesi; PAdES DocTimeStamp yolu gerilemez; bir nesne hatası diğer due öğeleri durdurmaz.
- **TST-025:** Host zamanlayıcı due öğeleri yapılandırılmış aralıkla çalıştırır; lead time öncesi tetiklenmez.
- **TST-026:** Unix `HostReady` false iken PIN/onay fail-closed; `HostReady` true yolunda Keychain/secret-service; Windows `HostReady` değişmez.

## 3. Kabul kriterleri

### MVP kapısı

MVP geliştirmesine giriş için ADR-001–007 kabul edilmiş, OpenAPI doğrulanmış ve PDF/AKİS/Agent Faz 0 kapıları ölçülebilir olmalıdır.

- Windows üzerinde referans AKİS kartı ile gerçek PAdES B-B üretimi başarılıdır.
- Üretilen dosya İmzaKit Verify ve seçilen iki bağımsız doğrulayıcıda beklenen sonuç verir.
- Değiştirilmiş belge `FAILED`; Faz 1’de çevrimiçi kontrol yapılmadığı ve gömülü/yerel revocation kanıtı bulunmadığı durumda Türkiye NES sonucu `INDETERMINATE`, alt neden `REVOCATION_DATA_UNAVAILABLE` olur.
- Agent dış arayüzde dinlemez; replay/origin/digest saldırı testleri başarısız kılınır.
- State machine/idempotency testlerinde duplicate imza artefaktı oluşmaz.

### Sürüm 1.0 kapısı

- PAdES B-B/B-T/B-LT/B-LTA ve CAdES hedef matrisi tamamdır.
- Trust Store update/rollback ve policy version raporlaması test edilmiştir.
- Kritik/yüksek güvenlik bulgusu açık değildir.
- Paket/installer kod imzası, SBOM, bağımlılık taraması ve geri alma prosedürü mevcuttur.
- API sözleşme, SDK örnek, hata kataloğu ve operasyon runbook dokümanları yayımlanmıştır.

## 4. Test verisi yönetimi

Gerçek kişilere ait sertifika/PIN/belgeler test deposuna konmaz. Test sertifika otoritesi ve sentetik belgeler varsayılandır. Gerçek ESHS/kart testleri kontrollü laboratuvarda, erişimi sınırlı audit ile yapılır. Golden dosyaların SHA-256 hash’leri ve üretim aracı sürümleri kaydedilir.
