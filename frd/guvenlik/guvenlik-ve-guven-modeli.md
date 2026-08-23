# Güvenlik ve Güven Modeli

## 1. Güven sınırları

Tarayıcı, müşteri uygulaması, Agent, API, belge deposu, Redis, PKCS#11 sürücüsü, TSA ve ESHS uçları ayrı güven sınırlarıdır. Kullanıcı tarafından sağlanan PDF/XML/ASiC, sertifika içindeki AIA/OCSP/CRL URL’leri ve önceki imzalar düşmanca girdi kabul edilir.

## 2. Agent güvenliği

- **SEC-001:** Agent yalnız `127.0.0.1`/`::1` üzerinde dinlemeli; dış ağ arayüzüne bind etmemelidir.
- **SEC-002:** Her işlem; sunucu tarafından Ed25519 ile imzalanmış, en fazla 120 saniye geçerli, tek kullanımlık ve `issuer`, `audience`, `origin`, `operationId`, `tenantId`, `applicationId`, `documentSha256`, `allowedAction`, `nonce`, `issuedAt`, `expiresAt` alanlarına bağlı bilet gerektirir.
- **SEC-003:** Nonce atomik olarak tüketilmeli; tekrar kullanım reddedilmelidir.
- **SEC-004:** CORS geniş wildcard kullanmamalı; müşteri origin allowlist veya origin-bound ticket uygulanmalıdır.
- **SEC-005:** Browser çağrısı tek başına imza başlatamaz; Agent belge adı, hash/özet, çağıran uygulama, sertifika ve algoritmayı native ekranda göstermelidir.
- **SEC-006:** PIN kontrollü native alanda alınmalı; process içinde gerekenden uzun tutulmamalı ve managed string kullanımından kaçınılmalıdır.
- **SEC-007:** Agent callback’i operation ticket, imza sonucu ve idempotency anahtarıyla sunucuya doğrudan ve mTLS üzerinden yapmalıdır.
- **SEC-008:** Installer, binary ve update manifest’i kod imzalı; update paketi bütünlük/yayıncı kontrolünden geçmeli, release SBOM ve provenance yayımlamalıdır.
- **SEC-009:** Local privilege escalation, DLL search-order hijacking ve yetkisiz PKCS#11 modül yolu için allowlist/ACL kontrolleri uygulanmalıdır.
- **SEC-010:** Agent cihaz private key’ini yerel güvenli depoda üretmeli ve dışa aktarmamalıdır.
- **SEC-011:** Enrollment yalnız yetkili yöneticinin tek kullanımlık token’ıyla yapılmalı; mTLS sertifikası en fazla 30 gün geçerli olmalı, ömrünün üçte ikisinde yenilenmeli ve anında iptal edilebilmelidir.
- **SEC-012:** Loopback HTTP gizli taşıma kanalı sayılmamalı; PIN, credential ve ham özel veri bu kanal üzerinden taşınmamalıdır.

## 3. Sunucu ve veri güvenliği

- **SEC-020:** Kimlik doğrulama OAuth2/OIDC veya mTLS profiliyle; yetkilendirme tenant, uygulama ve operasyon kapsamıyla yapılmalıdır.
- **SEC-021:** Belge erişimi tahmin edilemez kimlik ve süreli URL ile sınırlandırılmalı; cross-tenant erişim reddedilmelidir.
- **SEC-022:** Redis anahtarlarında ham PII kullanılmamalı; TTL’siz operasyon kaydı oluşturulmamalıdır.
- **SEC-023:** Secret’lar kaynak kodu/appsettings içine açık yazılmamalı; secret manager kullanılmalıdır.
- **SEC-024:** Loglarda PIN, private key, credential, ham belge, tam sertifika kişisel alanları ve raw token bulunmamalıdır.
- **SEC-025:** Audit; operasyon oluşturma, kullanıcı onayı, sertifika seçimi, hazırlama, imzalama, timestamp, doğrulama, indirme ve iptal olaylarını append-only tutmalı; her olay önceki olay hash’ini bağlamalıdır.
- **SEC-026:** Tamamlanmamış operasyon metadata’sı varsayılan 24 saat, tamamlanan çıktı ve doğrulama raporu 7 gün tutulmalı; süresiz saklama varsayılan olmamalıdır.
- **SEC-027:** Release süreci NuGet, installer, container, SBOM ve Trust Store artefaktlarını imzalamalı; kaynak commit ile artefakt digest ilişkisini provenance olarak yayımlamalıdır.

## 4. Dış kaynak erişimi ve SSRF

`IExternalResourceFetcher` yalnız HTTP/HTTPS kabul eder; DNS çözümünden önce ve sonra loopback, link-local, private, multicast ve cloud metadata ağlarını engeller. Redirect sayısı, timeout, maksimum cevap boyutu, content type ve sıkıştırılmış içerik sınırları uygulanır. DNS rebinding’e karşı her bağlantı hedefi yeniden doğrulanır. `file`, `ftp`, UNC ve özel şemalar reddedilir.

## 5. Belge işleme güvenliği

- PDF parser; aşırı nesne, stream, revision, xref ve dekompresyon limitlerine sahip olmalıdır.
- XML; DTD ve external entity kapalı, depth/node/attribute limitli olmalıdır.
- ASiC; zip-slip, absolute path, duplicate/case-conflicting entry, symlink ve zip-bomb kontrolleri yapmalıdır.
- İmzalı verinin canonical/ByteRange byte’ları doğrulama sırasında yeniden yazılmamalıdır.
- Format hatası ile kriptografik hata ayrılmalıdır.

## 6. Algoritma politikası

Algoritma kararı kod içine dağılmamalı; sürümlü politika `allowedForSigning`, `allowedForValidation`, başlangıç/bitiş zamanı ve anahtar boyutu koşullarını taşımalıdır. Zayıflayan algoritma eski imzayı otomatik FAILED yapmaz; validation time ve proof-of-existence ile değerlendirilir. Yeni imza üretiminde politika dışı algoritma reddedilir.

## 7. Trust Store

Trust Store, işletim sistemi köklerinden ayrı ve profil bazlıdır. Paket; sürüm, sağlayıcı, kök/ara sertifikalar, politika OID’leri, geçerlilik tarihleri, kaynak/provenance ve paket imzası içerir. Güncelleme atomik yapılır; doğrulama raporu kullanılan sürümü kaydeder. Geri alma ve acil trust removal süreci bulunur.

## 8. Tehdit ve kontrol özeti

| Tehdit | Kontrol |
|---|---|
| Kötü niyetli web sayfası Agent’a imza attırır | Origin-bound tek kullanımlık bilet + native onay |
| Bilet tekrar oynatılır | Nonce, TTL, atomik consume, operation state |
| PIN sızar | Native giriş, server/browser/log izolasyonu |
| Sahte TSA/OCSP cevabı | CMS/response imzası, zincir, EKU/yetki, freshness |
| Sertifika URL’si iç ağa erişir | SSRF korumalı fetcher |
| Belge parser kaynak tüketir | Boyut, derinlik, obje, süre ve dekompresyon limitleri |
| Trust Store manipüle edilir | İmzalı/sürümlü paket, release-key doğrulama |
| Tamamlama iki kez çağrılır | Idempotency ve state transition guard |
