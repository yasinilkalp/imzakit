# ADR-004 — Türkiye Trust Store

## Durum

Kabul edildi — 22 Ağustos 2026

## Tarih

22 Ağustos 2026

## Bağlam

Türkiye NES değerlendirmesi işletim sistemi kök deposuna veya tek bir OID’e indirgenemez; kaynağı ve sürümü açıklanabilir bir güven politikası gerekir.

## Karar

`TurkiyeNes` profili işletim sistemi deposundan ayrı bir Trust Store kullanır. Paket açık Git deposunda yayımlanır ve release anahtarıyla imzalanır. Sürüm, sağlayıcı, sertifika DER/hash, rol, geçerlilik aralığı, politika OID’leri, kaynak/provenance ve ekleme-kaldırma gerekçesi zorunludur. Yalnız doğrulanmış paket atomik etkinleşir.

İçerik onayı proje yönetişimindeki Trust Maintainer rolüne aittir. Rollback ve acil trust removal prosedürü zorunludur.

## Sonuçlar

Her doğrulama raporu Trust Store ve algoritma politikası sürümünü kaydeder. Teknik sonuç hukuki geçerlilik hükmü değildir.

## Doğrulama

Geçersiz imza, eski sürüm, atomik update, rollback ve acil removal senaryoları test edilir.

