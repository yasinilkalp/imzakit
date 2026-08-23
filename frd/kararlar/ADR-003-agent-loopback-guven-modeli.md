# ADR-003 — Agent Loopback Güven Modeli

## Durum

Kabul edildi — 22 Ağustos 2026

## Tarih

22 Ağustos 2026

## Bağlam

Tarayıcıdan yerel karta erişim, kötü niyetli web sayfası ve replay saldırılarına karşı korunmalı; yerel TLS sertifikası kurulumu ürünün zorunlu önkoşulu olmamalıdır.

## Karar

Agent yalnız `127.0.0.1` ve `::1` üzerinde loopback HTTP dinler. Her eylem, sunucunun Ed25519 ile imzaladığı, en fazla 120 saniye geçerli ve tek kullanımlık bir bilet gerektirir. Bilet `issuer`, `audience`, `origin`, `operationId`, `tenantId`, `applicationId`, `documentSha256`, `allowedAction`, `nonce`, `issuedAt` ve `expiresAt` alanlarını bağlar. Nonce atomik tüketilir; wildcard CORS kullanılmaz. Geçerli bilet native kullanıcı onayının yerine geçmez.

Agent callback’i mTLS ile API’ye gider. Cihaz private key’i Agent içinde üretilir ve dışarı çıkmaz. Yetkili yöneticinin tek kullanımlık enrollment token’ıyla verilen istemci sertifikası en fazla 30 gün geçerlidir, ömrünün üçte ikisinde yenilenir ve yönetici tarafından anında iptal edilebilir.

## Sonuçlar

PIN yalnız native güvenli alanda alınır. Browser ve API PIN’i veya private key’i görmez. Yerel HTTP içeriği gizli taşıma kanalı olarak kabul edilmez; yetki imzalı bilet ve native onaydan gelir.

## Doğrulama

Bind, origin mismatch, replay, TTL, digest değiştirme, native onay, enrollment, rotation ve revocation testleri zorunludur.

