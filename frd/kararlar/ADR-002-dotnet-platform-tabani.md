# ADR-002 — .NET Platform Tabanı

## Durum

Kabul edildi — 22 Ağustos 2026

## Tarih

22 Ağustos 2026

## Bağlam

SDK, servis ve Agent için destek süresi belirli, güncel bir platform tabanı gerekir.

## Karar

SDK, API, Verify ve testlerin birincil tabanı .NET 10 LTS’tir. MVP Agent hedefleri Windows x64 ve Windows arm64’tür. Public API semantic versioning uygular; geriye uyumsuz değişiklik yalnız ana sürümde yapılır.

## Sonuçlar

Windows dışı Agent Faz 5’tedir. Ortak Agent protokolü platform bağımsız kalır.

## Doğrulama

Build matrisi .NET 10 LTS ile Windows x64/arm64 Agent artefaktlarını ve public API uyumluluk kontrolünü çalıştırır.

