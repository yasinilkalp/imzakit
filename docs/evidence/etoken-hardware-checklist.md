# eToken Donanım Kabul Kontrol Listesi

**Durum:** Profil kodu hazır; fiziksel eToken, izinli `eTPKCS11.dll` ve kontrollü Windows laboratuvarı olmadan çalıştırılmadı. CI sahte native API ile yeşil kalır; bu liste işaretlenmeden eToken donanım kabulü iddia edilmez. MVP çıkış kapısı AKİS kartına bağlı kalır.

- [ ] Vendor modülü allowlist içindeki mutlak yoldan ve güvenilir ACL ile yükleniyor (`Pkcs11NativeLibraryLoader` + `eTPKCS11.dll`; SafeNet/Thales `Program Files` kökü).
- [ ] `%WINDIR%\System32` varsayılan allowlist kökü değildir; host bilinçle eklemediyse kullanılmaz.
- [ ] Takılı token; etiket, üretici, model ve maskeli seri numarasıyla keşfediliyor.
- [ ] X.509 sertifikası `CKO_CERTIFICATE`, `CKC_X_509`, `CKA_VALUE`, `CKA_ID` ve `CKA_LABEL` üzerinden okunuyor.
- [ ] Private key sertifikayla aynı `CKA_ID` üzerinden bulunuyor.
- [ ] `CKM_SHA256_RSA_PKCS` imzası token içinde üretilip PAdES Verify ile doğrulanıyor.
- [ ] Yanlış PIN, kilitli PIN, token çıkarma, desteklenmeyen mekanizma ve driver restart ayrı sonuçlanıyor.
- [ ] PIN, private key, credential, ham belge ve tam sertifika kişisel alanları log/audit/crash dump içinde bulunmuyor.
- [ ] Test tarihi, Windows mimarisi, driver sürümü, token modeli ve anonimleştirilmiş çıktı hash'leri kaydediliyor.

Gerçek PIN, özel anahtar veya kişiye ait sertifika bu depoya eklenmez.
