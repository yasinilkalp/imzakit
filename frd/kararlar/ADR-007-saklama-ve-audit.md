# ADR-007 — Saklama ve Audit

## Durum

Kabul edildi — 22 Ağustos 2026

## Tarih

22 Ağustos 2026

## Bağlam

Operasyon, belge ve audit verileri için güvenli varsayılanlar tanımlanmadan tenant izolasyonu ve veri minimizasyonu doğrulanamaz.

## Karar

Agent bileti 120 saniye, tamamlanmamış operasyon metadata’sı 24 saat, tamamlanan çıktı ve doğrulama raporu 7 gün saklanır. Kurulum sahibi süreleri kısaltabilir veya açık politika ile uzatabilir; süresiz saklama varsayılan değildir. Redis belge içeriği tutmaz.

Audit append-only olaylardan oluşur; her olay önceki olay hash’ini bağlar. PIN, private key, credential, ham belge, raw token ve tam sertifika kişisel alanları audit veya log içine girmez.

## Sonuçlar

Silme işleri gözlemlenebilir ve tenant bazında izole olur. Saklama politikası değişikliği audit olayı üretir.

## Doğrulama

TTL silme, tenant izolasyonu, hash-chain bozulması ve hassas veri taraması test edilir.

