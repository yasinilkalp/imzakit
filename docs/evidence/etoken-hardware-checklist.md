# eToken Donanım Kabul Kontrol Listesi

**Durum:** PIN’siz keşif ve CredUI PIN laboratuvarı (28 Ağustos 2026) operatör teyidiyle geçti. CI sahte native API ile yeşil kalır. Faz 1 yazılım kapısı (28 Ağustos 2026) testlerle kapatıldı; fiziksel AKİS üretim kabulüne ertelendi.

**PIN adımı:** `scripts/run-etoken-pin-lab.ps1` — CredUI penceresi açılır. PIN’i terminale yazmayın.

- [x] Vendor modülü laboratuvarda yüklendi (`eTPKCS11.dll` 10.9.4482.0, SHA-256 `7ADA03F73A29EBC4D120FBBB9E513CE8F3614E715B32CDEBABB521E7FD4ADB1C`; yol `%WINDIR%\System32`, Agent varsayılan kökü değil).
- [x] `%WINDIR%\System32` varsayılan allowlist kökü değildir; bu oturumda host bilinçle laboratuvar kökü olarak kullanıldı (SEC-009).
- [x] Takılı token keşfedildi (PIN’siz; `scripts/run-etoken-hardware-lab.ps1`, 28 Ağustos 2026, win-x64). Etiket/üretici/model dolu, seri maskeli.
- [x] X.509 sertifikası PIN olmadan okundu (`CKO_CERTIFICATE` / `CKC_X_509`, `CKA_VALUE` DER `0x30`, `CKA_ID` ve `CKA_LABEL` dolu). DER/label git’e yazılmadı.
- [x] Private key sertifikayla aynı `CKA_ID` üzerinden bulundu (CredUI PIN, `scripts/run-etoken-pin-lab.ps1`).
- [x] `CKM_SHA256_RSA_PKCS` token içinde üretildi ve PAdES Verify çalıştı (CredUI PIN lab). İmzalı PDF git’e konmadı.
- [ ] Yanlış PIN, kilitli PIN, token çıkarma, desteklenmeyen mekanizma ve driver restart ayrı sonuçlanıyor.
- [ ] PIN, private key, credential, ham belge ve tam sertifika kişisel alanları log/audit/crash dump içinde bulunmuyor.
- [x] Test tarihi, Windows mimarisi, driver sürümü, token modeli ve anonimleştirilmiş çıktı hash’leri kaydedildi (28 Ağustos 2026, win-x64, eTPKCS11 10.9.4482.0).

Gerçek PIN, özel anahtar veya kişiye ait sertifika bu depoya eklenmez.
