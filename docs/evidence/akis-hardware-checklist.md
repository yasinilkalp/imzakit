# AKİS Donanım Kabul Kontrol Listesi

**Durum:** Çalıştırılmadı — fiziksel referans kart, izinli vendor driver'ı ve kontrollü Windows laboratuvarı gerekir.

- [ ] Vendor modülü allowlist içindeki mutlak yoldan ve güvenilir ACL ile yükleniyor.
- [ ] Takılı token; etiket, üretici, model ve maskeli seri numarasıyla keşfediliyor.
- [ ] X.509 sertifikası `CKO_CERTIFICATE`, `CKC_X_509`, `CKA_VALUE`, `CKA_ID` ve `CKA_LABEL` üzerinden okunuyor.
- [ ] Private key sertifikayla aynı `CKA_ID` üzerinden bulunuyor.
- [ ] `CKM_SHA256_RSA_PKCS` imzası kart içinde üretilip PAdES Verify ile doğrulanıyor.
- [ ] Yanlış PIN, kilitli PIN, kart çıkarma, desteklenmeyen mekanizma ve driver restart ayrı sonuçlanıyor.
- [ ] PIN, private key, credential, ham belge ve tam sertifika kişisel alanları log/audit/crash dump içinde bulunmuyor.
- [ ] Test tarihi, Windows mimarisi, driver sürümü, kart modeli ve anonimleştirilmiş çıktı hash'leri kaydediliyor.

Gerçek PIN, özel anahtar veya kişiye ait sertifika bu depoya eklenmez. Önceki ayrıntılı hazırlık listesi: [akis-gercek-kart-kontrol-listesi.md](./akis-gercek-kart-kontrol-listesi.md).
