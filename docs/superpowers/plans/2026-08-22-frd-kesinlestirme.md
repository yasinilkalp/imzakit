# İmzaKit FRD Kesinleştirme Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** İmzaKit FRD setini onaylanan ürün, güvenlik, API, fazlandırma ve kabul kararlarıyla tutarlı ve makine tarafından doğrulanabilir bir MVP geliştirme tabanına dönüştürmek.

**Architecture:** Ana FRD ürün kararlarının özeti, ADR’ler kararların değişmez kaydı, OpenAPI 3.1 MVP HTTP sözleşmesinin kaynak tanımı ve tekil izlenebilirlik matrisi gereksinim-kabul ilişkisinin kaynak kaydı olacaktır. Diğer FRD belgeleri bu üç kaynağa referans verecek; tekrar edilen TTL, faz, algoritma ve durum değerleri otomatik tutarlılık kontrolünden geçirilecektir.

**Tech Stack:** Markdown, OpenAPI 3.1 YAML, Mermaid, PowerShell 7 doğrulama betiği

**Spec:** `docs/superpowers/specs/2026-08-22-frd-kesinlestirme-design.md`

## Global Constraints

- Ürünün tamamı Apache License 2.0 altında açık kaynak olacaktır.
- Birincil geliştirme tabanı .NET 10 LTS; MVP Agent platformları Windows x64 ve Windows arm64 olacaktır.
- MVP kapsamı PAdES B-B, PAdES için CMS alt kümesi, AKİS/PKCS#11, Windows Agent, operasyon API’si ve temel Verify ile sınırlıdır.
- Agent bileti Ed25519 imzalı, en fazla 120 saniye geçerli ve tek kullanımlık olacaktır.
- Agent callback kimliği, Agent içinde üretilen private key’e bağlı en fazla 30 günlük mTLS istemci sertifikası olacaktır.
- Tamamlanmamış operasyon metadata’sı 24 saat; tamamlanan çıktı ve doğrulama raporu 7 gün saklanacaktır.
- Çevrimiçi OCSP/CRL Faz 2’dedir; Faz 1’de gerekli kanıt yokluğu `INDETERMINATE/REVOCATION_DATA_UNAVAILABLE` üretir.
- PDF motoru Faz 0 test kapısını geçmeden seçilmiş sayılmayacaktır.

---

### Task 1: Karar kayıtlarını oluştur

**Files:**
- Create: `frd/kararlar/README.md`
- Create: `frd/kararlar/ADR-001-acik-kaynak-ve-lisans.md`
- Create: `frd/kararlar/ADR-002-dotnet-platform-tabani.md`
- Create: `frd/kararlar/ADR-003-agent-loopback-guven-modeli.md`
- Create: `frd/kararlar/ADR-004-turkiye-trust-store.md`
- Create: `frd/kararlar/ADR-005-pdf-motoru-secim-kapisi.md`
- Create: `frd/kararlar/ADR-006-mvp-kapsami-ve-revocation.md`
- Create: `frd/kararlar/ADR-007-saklama-ve-audit.md`

**Interfaces:**
- Consumes: Onaylanan tasarımın 3–12. bölümleri
- Produces: Diğer FRD belgelerinin referans vereceği `ADR-001`–`ADR-007` karar kimlikleri

- [ ] **Step 1: ADR indeksini ve ortak şablonu yaz**

Her ADR’de `Durum`, `Tarih`, `Bağlam`, `Karar`, `Sonuçlar` ve `Doğrulama` başlıklarını kullan. İndekste yedi ADR’yi `Kabul edildi` durumuyla listele.

- [ ] **Step 2: Lisans ve platform ADR’lerini yaz**

ADR-001’e Apache-2.0, izin verici bağımlılık allowlist’i, reddedilen lisans sınıfları, NOTICE/SBOM kapısını; ADR-002’ye .NET 10 LTS, Windows x64/arm64 ve semantic versioning kararlarını birebir geçir.

- [ ] **Step 3: Agent ve Trust Store ADR’lerini yaz**

ADR-003’e loopback HTTP, Ed25519 bilet claim’leri, 120 saniye TTL, native onay, CORS ve mTLS enrollment/rotation/revocation yaşam döngüsünü; ADR-004’e ayrı Türkiye profili, imzalı paket, Trust Maintainer, provenance, rollback ve acil removal kurallarını geçir.

- [ ] **Step 4: PDF, MVP ve saklama ADR’lerini yaz**

ADR-005’e sekiz maddelik PDF seçim kapısını ve fallback incremental writer sınırını; ADR-006’ya Faz 1/Faz 2 ayrımını ve revocation sonucunu; ADR-007’ye 24 saat/7 gün/120 saniye varsayımlarını ve hash-chain audit modelini geçir.

- [ ] **Step 5: ADR çapraz kontrolü yap**

Run: `rg -n "TBD|TODO|sonra belirlenecek|kararlaştırılacak" frd/kararlar`

Expected: Eşleşme yok.

Run: `rg -l "^## Durum$|^## Karar$|^## Doğrulama$" frd/kararlar/ADR-*.md`

Expected: Yedi ADR dosyasının tamamı listelenir.

- [ ] **Step 6: Değişikliği kaydet**

Git etkinse: `git add frd/kararlar && git commit -m "docs: record foundational FRD decisions"`. Git etkin değilse commit adımını atla ve teslim notuna ekle.

---

### Task 2: Ana FRD, mimari ve güvenlik belgelerini kesinleştir

**Files:**
- Modify: `frd/README.md`
- Modify: `frd/ana-dokuman/imzakit-fonksiyonel-gereksinimler-dokumani.md`
- Modify: `frd/mimari/sistem-mimarisi.md`
- Modify: `frd/guvenlik/guvenlik-ve-guven-modeli.md`
- Modify: `frd/ekler/terimler-sozlugu.md`

**Interfaces:**
- Consumes: `ADR-001`–`ADR-007`
- Produces: Ürün ve mimari kararlarının okunabilir normatif özeti; ortak terimler

- [ ] **Step 1: README durumunu ve okuma sırasını güncelle**

Doküman durumunu `MVP tabanı — kabul edilmiş kararlar` olarak değiştir. Okuma sırasına ADR indeksini ve `openapi.yaml` dosyasını ekle. `API-*` kimlik ailesinin OpenAPI gereksinimlerini ifade ettiğini açıkla.

- [ ] **Step 2: Ana FRD ürün kararlarını güncelle**

Apache-2.0, .NET 10 LTS, Windows x64/arm64, kesin MVP kapsamı ve ileri faz sınırlarını ekle. “Varsayımlar ve açık kararlar” bölümünü “Kabul edilmiş kararlar ve Faz 0 kapıları” olarak değiştir; ADR bağlantıları ver.

- [ ] **Step 3: Mimariyi kesin kararlarla hizala**

Agent callback mTLS akışını, enrollment sertifika yaşam döngüsünü, Trust Store dağıtımını, Redis/belge saklama TTL’lerini ve audit hash-chain modelini ekle. PAdES modülünün PDF motoruna adaptör üzerinden bağımlı olduğunu belirt.

- [ ] **Step 4: Güvenlik gereksinimlerini somutlaştır**

SEC-002’ye bilet claim’leri ve Ed25519; SEC-007’ye mTLS callback; SEC-008’e SBOM/provenance; SEC-025’e append-only hash-chain kabul kriteri ekle. Yeni normatif maddeler gerekirse `SEC-010`–`SEC-013` ve `SEC-026`–`SEC-028` aralıklarını kullan; mevcut kimlikleri yeniden numaralandırma.

- [ ] **Step 5: Sözlüğü tamamla**

`Idempotency-Key`, `Operation Ticket`, `Provenance`, `SBOM`, `Enrollment`, `mTLS` ve `Canonical Request Hash` terimlerini ekle.

- [ ] **Step 6: Karar değerlerini doğrula**

Run: `rg -n "Apache|\.NET 10|120 saniye|30 gün|24 saat|7 gün|Ed25519|mTLS" frd/README.md frd/ana-dokuman frd/mimari frd/guvenlik`

Expected: Her değer ilgili normatif belgede bulunur ve çelişen alternatif değer yoktur.

- [ ] **Step 7: Değişikliği kaydet**

Git etkinse: `git add frd/README.md frd/ana-dokuman frd/mimari frd/guvenlik frd/ekler/terimler-sozlugu.md && git commit -m "docs: finalize product architecture and security baseline"`.

---

### Task 3: Gereksinimleri ve fazlandırmayı uygulanabilir hale getir

**Files:**
- Modify: `frd/gereksinimler/fonksiyonel-gereksinimler.md`
- Modify: `frd/planlama/mvp-ve-fazlandirma.md`

**Interfaces:**
- Consumes: Kesin MVP kapsamı, ADR-005 ve ADR-006
- Produces: Tekil gereksinimlerin bağlayıcı faz/öncelik sınıfları; ölçülebilir Faz 0 ve MVP kapıları

- [ ] **Step 1: Gereksinim metadata biçimini tanımla**

Dosya başına normatif tablo ekle: `Kimlik | Öncelik | Faz | MVP engelleyici`. Mevcut gereksinim cümlelerini değiştirmeden bütün kimlikleri tabloya al.

- [ ] **Step 2: MVP gereksinimlerini sınıflandır**

FR-003–006, FR-021–029, FR-040–042, FR-046–051, FR-060–063, FR-090–094, VAL-001–007, FR-110, NFR-002–010 gereksinimlerini gerçek Faz 1 kapsamına göre işaretle. Faz 2–5 gereksinimlerini MVP engelleyici yapma.

- [ ] **Step 3: Revocation ayrımını normatif hale getir**

FR-096–099’u Faz 2 olarak işaretle. VAL-005 ve VAL-006 altına Faz 1’de çevrimiçi kontrol yapılmadığını ve `REVOCATION_DATA_UNAVAILABLE` sonucunu ekle.

- [ ] **Step 4: Faz 0 kapılarını ölçülebilir yaz**

PDF kapısına sekiz ADR-005 kriterini; AKİS kapısına token keşfi, CKA_ID eşleme, gerçek RSA/SHA-256 imza ve hata senaryolarını; Agent kapısına bind, replay, origin, digest ve native onay testlerini; golden vector kapısına iki bağımsız doğrulayıcıyı ekle.

- [ ] **Step 5: MVP giriş/çıkış kurallarını ayır**

Giriş: ADR’ler kabul edilmiş, OpenAPI doğrulanmış, PDF/AKİS/Agent spike planları hazır. Çıkış: gerçek AKİS PAdES B-B, Verify sonucu, iki harici doğrulayıcı, idempotency ve saldırı testleri başarılı.

- [ ] **Step 6: Faz çelişkisi taraması yap**

Run: `rg -n "OCSP|CRL|B-T|B-LT|B-LTA|CAdES|XAdES|ASiC" frd/gereksinimler frd/planlama`

Expected: Çevrimiçi OCSP/CRL ve uzun dönem PAdES yalnız Faz 2; bağımsız CAdES Faz 3; XAdES/ASiC Faz 4 olarak işaretlenir.

- [ ] **Step 7: Değişikliği kaydet**

Git etkinse: `git add frd/gereksinimler frd/planlama && git commit -m "docs: align requirements with MVP phases"`.

---

### Task 4: MVP OpenAPI 3.1 sözleşmesini oluştur

**Files:**
- Create: `frd/api-ve-akislar/openapi.yaml`
- Modify: `frd/api-ve-akislar/api-ve-is-akislari.md`

**Interfaces:**
- Consumes: Mevcut API uçları, ADR-003, kesin kimlik ve idempotency modeli
- Produces: MVP istemci ve sunucu uygulamalarının kaynak HTTP sözleşmesi

- [ ] **Step 1: OpenAPI iskeletini ve güvenlik şemalarını yaz**

`openapi: 3.1.0`, `/v1` server, OAuth authorization-code/PKCE açıklaması, client-credentials şeması ve Agent callback için mutual TLS şeması ekle. Ortak `ProblemDetails`, `OperationStatus`, `ValidationOutcome` ve `Idempotency-Key` bileşenlerini tanımla.

- [ ] **Step 2: Operasyon uçlarını tanımla**

Şu uçların request/response, güvenlik, header, `400/401/403/404/409/413/422/429/5xx` yanıtlarını yaz:

```text
POST /v1/signature-operations
GET  /v1/signature-operations/{operationId}
POST /v1/signature-operations/{operationId}/agent-ticket
POST /v1/signature-operations/{operationId}/certificate
POST /v1/signature-operations/{operationId}/prepare
POST /v1/signature-operations/{operationId}/complete
POST /v1/signature-operations/{operationId}/cancel
```

- [ ] **Step 3: Validation ve Agent callback uçlarını tanımla**

`POST/GET /v1/validations` uçlarını ve `POST /v1/agent-callbacks/signature-results` mTLS ucunu ekle. `/v1/signatures/extend` Faz 2 olarak dokümante edilsin fakat MVP OpenAPI paths bölümüne alınmasın.

- [ ] **Step 4: Şemaları kesinleştir**

Operation, document reference, certificate summary, prepare result, completion request, Agent ticket, validation report ve revision result şemalarında zorunlu alanları, enum’ları, SHA-256 formatlarını, byte limitlerini ve tarih biçimlerini tanımla. Tenant/application alanlarını request gövdelerine ekleme.

- [ ] **Step 5: Durum geçişi ve idempotency tablolarını güncelle**

Markdown dokümanına her uç için izin verilen başlangıç/bitiş durumunu ve aynı/farklı canonical request hash davranışını ekle. OpenAPI’nin kaynak sözleşme olduğunu belirt.

- [ ] **Step 6: OpenAPI’yi doğrula**

Önce sistemde bulunan OpenAPI doğrulayıcısını kullan. Yoksa YAML parse ve yerel `$ref` kontrolü yapan `scripts/validate-frd.ps1` Task 6’da sağlanana kadar yapısal inceleme uygula.

Expected: YAML parse edilir; yinelenen operationId, çözülemeyen yerel `$ref` veya tanımsız schema bulunmaz.

- [ ] **Step 7: Değişikliği kaydet**

Git etkinse: `git add frd/api-ve-akislar && git commit -m "docs: define MVP OpenAPI contract"`.

---

### Task 5: Test stratejisini ve tekil izlenebilirliği tamamla

**Files:**
- Modify: `frd/test-ve-kabul/test-ve-kabul-stratejisi.md`
- Rewrite: `frd/ekler/gereksinim-izlenebilirlik-matrisi.md`

**Interfaces:**
- Consumes: Kesin gereksinim metadata’sı ve OpenAPI operationId’leri
- Produces: Her bağlayıcı gereksinimin faz, bileşen, test ve kabul kanıtına tekil bağlantısı

- [ ] **Step 1: Test kimliklerini genişlet**

Mevcut TST-001–014 kimliklerini koru. API sözleşmesi, idempotency hash çakışması, mTLS enrollment/rotation/revocation, lisans allowlist, SBOM/provenance ve saklama/audit testleri için TST-015–020 ekle.

- [ ] **Step 2: MVP kabul kapısını hizala**

Faz 1’de online revocation yapılmadığını ve kanıt yokluğunun `INDETERMINATE/REVOCATION_DATA_UNAVAILABLE` ürettiğini açıkça yaz. PDF ve Agent Faz 0 kapılarının tamamlanmasını MVP geliştirme giriş koşulu yap.

- [ ] **Step 3: İzlenebilirlik matrisini tekil satırlara dönüştür**

Her FR, NFR, SEC, VAL ve API kimliği için şu sütunları doldur:

```text
Kimlik | Kısa tanım | Öncelik | Faz | Bileşen | ADR/API | Test | Kabul kanıtı | MVP engelleyici
```

Bir aralık veya “tümü” ifadesini tekil kimlik yerine kullanma. Birden çok gereksinim aynı testi paylaşabilir fakat test hücresi boş bırakılamaz.

- [ ] **Step 4: API gereksinim kimliklerini ekle**

API-001–API-010 aralığını OpenAPI kaynak sözleşmesi, auth/tenant, idempotency, Problem Details, state guard, callback mTLS, upload/download referansı, correlation, limitler ve backward compatibility için kullan. Bunları API belgesinde normatif liste ve matriste tekil satır olarak kaydet.

- [ ] **Step 5: Matris kapsamasını doğrula**

Tüm kaynak dokümanlardan kimlikleri çıkar ve matriste aynı kimliklerin bulunduğunu karşılaştır. Yinelenen tanım veya eksik kimlik varsa matrisi düzelt.

Expected: Kaynak gereksinim kimlikleri kümesi ile matris kimlikleri kümesi aynıdır; her satırda test ve faz vardır.

- [ ] **Step 6: Değişikliği kaydet**

Git etkinse: `git add frd/test-ve-kabul frd/ekler/gereksinim-izlenebilirlik-matrisi.md && git commit -m "docs: complete acceptance traceability"`.

---

### Task 6: FRD doğrulama betiğini ekle ve tüm seti doğrula

**Files:**
- Create: `scripts/validate-frd.ps1`
- Modify: `frd/README.md`

**Interfaces:**
- Consumes: Tüm FRD Markdown ve OpenAPI dosyaları
- Produces: Yerel/CI kullanımına uygun, başarısızlıkta non-zero exit code döndüren FRD kalite kapısı

- [ ] **Step 1: Kimlik benzersizliği ve kapsam kontrolünü yaz**

Betiğin kaynak tanım satırlarındaki `FR|NFR|SEC|VAL|API|TST-[0-9]{3}` kimliklerini toplamasını, duplicate tanımları reddetmesini ve matris satırlarıyla küme karşılaştırması yapmasını sağla.

- [ ] **Step 2: Placeholder ve karar tutarlılığı kontrolünü yaz**

Normatif FRD dosyalarında `TBD`, `TODO`, `sonra belirlenecek` ve `kararlaştırılacak` ifadelerini reddet. `120 saniye`, `30 gün`, `24 saat`, `7 gün`, `.NET 10`, `Ed25519` ve Faz 1 revocation sonucunun beklenen belgelerde bulunduğunu kontrol et.

- [ ] **Step 3: Bağlantı ve OpenAPI kontrolünü yaz**

Yerel Markdown bağlantılarının hedeflerini doğrula. Kurulu YAML modülü varsa parse et; yoksa Python veya Node çalışma zamanı mevcutsa bundled YAML parser kullan. Hiçbiri yoksa açık hata ile doğrulayıcı bağımlılığını bildir; YAML kontrolünü sessizce atlama. Tüm yerel OpenAPI `$ref` hedeflerini doğrula.

- [ ] **Step 4: README’ye çalıştırma talimatını ekle**

```powershell
pwsh -NoProfile -File scripts/validate-frd.ps1
```

Başarılı çıkışın `FRD validation passed` ve exit code 0; başarısızlığın maddeli hata listesi ve exit code 1 ürettiğini belgeye yaz.

- [ ] **Step 5: Tam doğrulamayı çalıştır**

Run: `pwsh -NoProfile -File scripts/validate-frd.ps1`

Expected: `FRD validation passed` ve exit code 0.

- [ ] **Step 6: Değişiklik listesini incele**

Run: `rg --files frd docs/superpowers scripts`

Expected: Tasarımda ve planda listelenen bütün dosyalar bulunur; geçici çıktı bulunmaz.

- [ ] **Step 7: Son değişikliği kaydet**

Git etkinse: `git add frd scripts docs/superpowers && git commit -m "docs: finalize development-ready FRD baseline"`.

