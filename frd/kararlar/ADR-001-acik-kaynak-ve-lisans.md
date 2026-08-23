# ADR-001 — Açık Kaynak ve Lisans

## Durum

Kabul edildi — 22 Ağustos 2026

## Tarih

22 Ağustos 2026

## Bağlam

İmzaKit’in SDK, Agent, API ve Verify bileşenlerinin ticari ve açık kaynak ürünler tarafından sürtünmesiz kullanılabilmesi gerekir.

## Karar

Ürünün tamamı Apache License 2.0 altında yayımlanacaktır. Zorunlu çalışma zamanı bağımlılıklarında Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause ve ISC lisansları doğrudan kabul edilir. GPL, AGPL, SSPL, yalnız araştırma amaçlı, source-available veya ticari lisanslı bileşenler zorunlu bağımlılık olamaz. LGPL, MPL ve özel istisnalı lisanslar yazılı inceleme gerektirir.

## Sonuçlar

Her sürüm NOTICE dosyası, lisans envanteri ve SBOM içerir. Lisans allowlist ihlali sürümü durdurur.

## Doğrulama

CI bağımlılık lisanslarını tarar; bilinmeyen veya izin verilmeyen lisansla stabil artefakt üretmez.

