# AKİS Gerçek Kart Kanıt Kontrol Listesi

Bu liste otomatik test sonucu değildir. Yalnız fiziksel referans AKİS kartı ve kontrollü laboratuvar çalışmasıyla doldurulur.

- [ ] İzinli vendor modülü güvenilir kurulum yolundan yükleniyor.
- [ ] Takılı token; etiket, üretici, model ve maskeli seri numarasıyla keşfediliyor.
- [ ] X.509 sertifikası `CKA_VALUE`, `CKA_ID` ve `CKA_LABEL` üzerinden okunuyor.
- [ ] Private key sertifikayla aynı `CKA_ID` üzerinden bulunuyor.
- [ ] RSA/SHA-256 PKCS#1 imzası kart içinde üretiliyor ve Verify ile doğrulanıyor.
- [ ] Yanlış PIN, kilitli PIN, kart çıkarma ve mekanizma uyumsuzluğu ayrı kodlanıyor.
- [ ] PIN, private key, ham belge ve tam sertifika kişisel alanları loglarda bulunmuyor.

Kanıt kaydı; tarih, işletim sistemi/mimari, driver sürümü, kart modeli, anonimleştirilmiş test kimliği ve çıktı hash'lerini içermelidir. PIN veya gerçek kişiye ait sertifika depoya eklenmez.
