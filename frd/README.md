# İmzaKit FRD Doküman Seti

**Ürün:** İmzaKit — Türkiye Elektronik İmza Entegrasyon Kiti  
**Sürüm:** 1.0 MVP tabanı — kabul edilmiş kararlar  
**Tarih:** 22 Ağustos 2026

Bu dizin, İmzaKit ürün ailesinin fonksiyonel gereksinimlerini, mimarisini, güvenlik modelini, API sözleşmelerini, test yaklaşımını ve teslimat fazlarını birlikte tanımlar.

## Okuma sırası

1. [Ana FRD](ana-dokuman/imzakit-fonksiyonel-gereksinimler-dokumani.md)
2. [Sistem mimarisi](mimari/sistem-mimarisi.md)
3. [Fonksiyonel gereksinimler](gereksinimler/fonksiyonel-gereksinimler.md)
4. [Güvenlik ve güven modeli](guvenlik/guvenlik-ve-guven-modeli.md)
5. [API ve iş akışları](api-ve-akislar/api-ve-is-akislari.md)
6. [MVP OpenAPI 3.1 sözleşmesi](api-ve-akislar/openapi.yaml)
7. [Test ve kabul stratejisi](test-ve-kabul/test-ve-kabul-stratejisi.md)
8. [MVP ve fazlandırma](planlama/mvp-ve-fazlandirma.md)
9. [Mimari karar kayıtları](kararlar/README.md)
10. [İzlenebilirlik matrisi](ekler/gereksinim-izlenebilirlik-matrisi.md)
11. [Terimler sözlüğü](ekler/terimler-sozlugu.md)

## Doküman kuralları

- `FR-*`: fonksiyonel gereksinim
- `NFR-*`: fonksiyonel olmayan gereksinim
- `SEC-*`: güvenlik gereksinimi
- `API-*`: API gereksinimi
- `VAL-*`: doğrulama gereksinimi
- `TST-*`: test/kabul gereksinimi
- “Zorunlu”, MVP veya belirtilen faz için bağlayıcıdır.
- “Önerilen”, varsayılan uygulama kararıdır; değiştirilirse mimari karar kaydı gerekir.
- “Sonraki faz”, MVP kabulünü engellemez.
- `openapi.yaml`, MVP HTTP sözleşmesinin kaynak tanımıdır; `API-*` gereksinimleri bu sözleşmenin kalite ve davranış kurallarını ifade eder.
- Kabul edilmiş bir karar yalnız yeni bir ADR ile değiştirilir.

## Doğrulama

FRD kalite kapısı depo kökünden aşağıdaki komutla çalıştırılır:

```powershell
pwsh -NoProfile -File scripts/validate-frd.ps1
```

Başarı `FRD validation passed` ve exit code `0`; hata maddeli bulgu listesi ve exit code `1` üretir.
