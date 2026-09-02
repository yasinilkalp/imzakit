# MVP ve Fazlandırma

## Faz 0 — Teknik risk azaltma

- PDF kütüphanesi ve lisans seçimi için PAdES incremental update/DocMDP/DSS prototipi
- AKİS PKCS#11 keşif ve imza spike’ı
- Agent loopback güvenlik/installer prototipi
- Trust Store kaynak ve güncelleme sahipliği kararı
- Harici doğrulayıcılarla ilk golden vector

### Ölçülebilir çıkış kapıları

- **PDF:** [ADR-005](../kararlar/ADR-005-pdf-motoru-secim-kapisi.md) içindeki sekiz kriterin tamamı ölçülür; iki bağımsız doğrulayıcı aynı golden PAdES B-B çıktısını kabul eder.
- **AKİS:** Gerçek kartta token keşfi, `CKA_ID` eşleme ve RSA/SHA-256 imza başarılı; yanlış PIN, kart çıkarma ve mekanizma uyumsuzluğu ayrı sonuçlanır.
- **Agent:** Yalnız loopback bind; replay, origin mismatch, süresi geçmiş bilet ve değiştirilmiş digest reddedilir; native onay olmadan imza oluşmaz.
- **Trust:** Trust Maintainer rolü, release key saklama ve rollback/acil removal prosedürü kayıtlıdır.
- **Sözleşme:** MVP OpenAPI 3.1 doğrulanır ve bütün MVP gereksinimleri teste bağlıdır.

Çıkış: kritik lisans/interoperabilite/güvenlik belirsizlikleri ölçüm kanıtı ve ADR’lerle kapanmış olmalıdır.

## Faz 1 — MVP: PAdES B-B

- Core, Cryptography, CMS, Certificate, Pkcs11, PAdES ve temel Validation
- Windows Agent + AKİS + eToken profili + native onay/PIN
- API state machine, Redis metadata ve belge deposu
- PAdES B-B, görünür/görünmez imza ve temel çoklu revision
- Türkiye NES politika iskeleti, temel trust chain
- Gömülü/yerel iptal kanıtını değerlendirme; kanıt yokluğunda `INDETERMINATE/REVOCATION_DATA_UNAVAILABLE` (çevrimiçi OCSP/CRL yok)
- SDK örneği, installer ve minimum operasyon dokümantasyonu

Çıkış: KamuSM/AKİS kart → sertifika seçimi → PAdES B-B → Verify raporu uçtan uca çalışır.

### MVP geliştirme giriş kapısı

- ADR-001–ADR-007 kabul edilmiştir.
- ADR-008 WinUI Desktop host’u [ADR-009](../kararlar/ADR-009-winui-masaustu-imza-istemcisi-geri-cekildi.md) ile geçersizdir.
- MVP OpenAPI 3.1 sözleşmesi doğrulanmıştır.
- PDF, AKİS ve Agent Faz 0 çalışma planları ile ölçüm girdileri hazırdır.
- Tüm MVP engelleyici gereksinimler tekil test ve kabul kanıtına bağlıdır.

### MVP kabul çıkış kapısı

- Gerçek AKİS kartıyla PAdES B-B üretimi ve Verify sonucu başarılıdır.
- Çıktı seçilen iki bağımsız doğrulayıcıda beklenen sonucu verir.
- Duplicate complete/callback yeni artefakt üretmez.
- Replay, origin, digest ve dış arayüz bind saldırı testleri başarısız kılınır.
- Değiştirilmiş belge `FAILED`; iptal kanıtı yokluğu `INDETERMINATE/REVOCATION_DATA_UNAVAILABLE` üretir.

## Faz 2 — Güvenilir zaman ve uzun dönem PAdES

- RFC 3161, çoklu TSA ve failover
- OCSP/CRL, SSRF korumalı fetcher ve cache
- PAdES B-T/B-LT/B-LTA, DSS/VRI, document timestamp
- DocMDP/FieldMDP ve ayrıntılı revision validation
- PASSED/FAILED/INDETERMINATE karar motorunun tam profili

## Faz 3 — CAdES, iş akışı ve kurumsallaştırma

- CAdES B-B/B-T/B-LT/B-LTA
- Çoklu SignerInfo, seri/paralel workflow ve rol/sıra politikaları
- Trust Store imzalı update, algorithm policy, gelişmiş audit/observability
- Yüksek erişilebilirlik ve performans sertleştirmesi

## Faz 4 — XAdES ve ASiC

- Güvenli XMLDSig/XAdES baseline profilleri
- ASiC-S/ASiC-E, paket güvenliği ve interoperabilite
- Formatlar arası ortak validation report olgunlaştırması

## Faz 5 — Sağlayıcı ve platform genişlemesi

- HSM, remote/cloud signing adaptörleri
- eToken dışında ek PKCS#11 vendor profilleri
- macOS/Linux Agent fizibilitesi
- Preservation scheduler ve periyodik B-LTA yenileme
- İhtiyaca göre eIDAS doğrulama profili

## Faz 6 — Format ve platform olgunlaştırma

- CAdES B-LTA `archive-time-stamp-v3` ve `ATSHashIndex-v3` (FR-066)
- Ortak doğrulama raporunda ASiC-E ASiCManifest imza-veri bağı (VAL-008)
- CAdES/XAdES archive timestamp preservation yenilemesi (FR-116)
- Host periyodik preservation tetikleyicisi (FR-117)
- Unix Agent `HostReady` ve native PIN/onay (FR-118); üretim Windows Agent [ADR-002](../kararlar/ADR-002-dotnet-platform-tabani.md) ile değişmez
- EU TSL/EUTL içe aktarma ve hukuki QES kararı bu fazın da dışındadır (FR-100)

## Önceliklendirme

| Öncelik | Kapsam |
|---|---|
| Zorunlu | Özel anahtar/PIN izolasyonu, PAdES B-B, AKİS, validation, state/idempotency, audit |
| Yüksek | RFC 3161, OCSP/CRL, B-T/B-LT/B-LTA, Trust Store güncelleme, DocMDP/FieldMDP |
| Orta | CAdES, seri/paralel akış, görünür imza şablonları |
| Sonraki | XAdES, ASiC, HSM/remote signing, çoklu platform Agent, preservation scheduler, ATSHashIndex-v3, ASiC-E ortak rapor, host cron |

## Başlıca riskler

| Risk | Azaltma |
|---|---|
| PDF kütüphanesi lisansı/yetersiz incremental API | Faz 0 prototipi ve ADR |
| Vendor PKCS#11 davranış farkları | Adaptör/quirk profili ve gerçek cihaz matrisi |
| Türkiye Trust Store kaynağı ve güncelliği | Sorumlu ekip, imzalı paket, provenance ve rollback |
| Tarayıcı-Agent güven modeli | Origin-bound ticket, native onay, penetration test |
| ETSI yorum/interoperabilite farkları | Golden vectors ve bağımsız doğrulayıcı matrisi |
| ESHS/TSA ağ kesintisi | Cache, failover, INDETERMINATE ve operasyonel metrik |
