# ADR-006 — MVP Kapsamı ve İptal Kontrolü

## Durum

Kabul edildi — 22 Ağustos 2026

## Tarih

22 Ağustos 2026

## Bağlam

Mevcut FRD, Faz 1 MVP kabulünde revocation sonucu isterken çevrimiçi OCSP/CRL motorunu Faz 2’ye bırakmaktadır.

## Karar

MVP; PAdES B-B, gereken CMS alt kümesi, RSA/SHA-256, AKİS/PKCS#11, Windows Agent, operasyon API’si, temel Verify ve çoklu PDF revision kapsamındadır. Faz 1 gömülü veya yerel iptal kanıtını değerlendirebilir; çevrimiçi OCSP/CRL, cache, freshness ve SSRF korumalı fetcher Faz 2’dedir.

Gerekli iptal kanıtı yoksa `TurkiyeNes` sonucu `INDETERMINATE`, alt neden `REVOCATION_DATA_UNAVAILABLE` olur. Güvenilir gömülü kanıt revoked/suspended gösterirse sonuç `FAILED` olur.

## Sonuçlar

PAdES B-T/B-LT/B-LTA Faz 2, bağımsız CAdES Faz 3, XAdES/ASiC Faz 4’tedir. API raporu çevrimiçi kontrol yapılmadığını açıklar.

## Doğrulama

Kanıt yok, gömülü good, revoked/suspended ve değiştirilmiş belge senaryoları ayrı test edilir.

