# MVP Süreç İçi İmzalama Kanıtı — 23 Ağustos 2026

`InProcessSigningFlowTests`, gerçek üretim modüllerini DI üzerinden birleştirerek aşağıdaki akışı doğrular:

1. İmzalama operasyonu oluşturulur ve izinli durum geçişleri uygulanır.
2. PDF ByteRange ve CMS signed attributes hazırlanır.
3. Yalnız PKCS#11 donanım sınırı bellek içi RSA test adaptörüyle karşılanır.
4. İmza CMS `SignedData` içine, ardından PDF `/Contents` alanına yerleştirilir.
5. Nihai PDF'nin özgün PDF byte'larını aynen koruduğu doğrulanır.
6. Verify sonucu ByteRange ve kriptografik imza için `Passed`, dış sertifika güveni için `Indeterminate` döner.
7. Operasyon `Completed` terminal durumuna ulaşır.

Bu kanıt gerçek AKİS kartı, native kullanıcı onayı, mTLS callback, çevrimiçi güven zinciri veya iptal kontrolü kanıtı değildir. Bu sınırlar harici/fiziksel doğrulama listesinde açık bırakılır.
