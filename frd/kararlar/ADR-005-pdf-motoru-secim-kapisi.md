# ADR-005 — PDF Motoru Seçim Kapısı

## Durum

Kabul edildi — 22 Ağustos 2026

## Tarih

22 Ağustos 2026

## Bağlam

İzin verici lisans, doğru incremental update ve PAdES interoperabilitesi birlikte doğrulanmadan bir PDF kütüphanesini mimariye kilitlemek yüksek risktir.

## Karar

PDF motoru Faz 0 test kapısını geçmeden seçilmez. Aday şu koşulların tamamını sağlamalıdır:

1. Mevcut byte’ları yeniden yazmadan incremental update
2. Doğru `/ByteRange` ve güvenli `/Contents` kapasitesi
3. Mevcut imza ve revision zincirini koruma
4. DocMDP ve FieldMDP okuma
5. DSS/VRI ve document timestamp genişleme noktası
6. Obje, xref, stream ve dekompresyon limitleri
7. İki bağımsız doğrulayıcıyla uyumlu golden PAdES B-B
8. Apache-2.0 dağıtımıyla uyumlu lisans ve NOTICE yükümlülüğü

## Sonuçlar

`ImzaKit.PAdES` PDF motoruna adaptör üzerinden bağlanır. Hiçbir aday geçmezse yalnız incremental signing kapsamlı izole bir yazma katmanı geliştirilir; genel amaçlı PDF kütüphanesi oluşturulmaz.

## Doğrulama

Karar kaydı, sekiz kriterin ölçüm sonuçlarını ve golden dosya hash’lerini içeren ardıl ADR ile güncellenir.

## Faz 0 Ara Kanıtı — 23 Ağustos 2026

Hazır bir PDF motoru seçilmedi. PDFsharp belgenin tamamını yeniden yazdığı, PdfPig ise incremental signing writer sağlamadığı için üretim yazıcısı olarak elendi. Dar kapsamlı İmzaKit incremental writer yaklaşımı sürdürüldü.

Tamamlanan kanıtlar:

1. Özgün PDF byte’ları korunarak yeni revision ekleniyor.
2. Yeni trailer `/Prev` ile önceki xref’e bağlanıyor.
3. `/ByteRange` yalnız sabit genişlikli `/Contents` rezervini dışarıda bırakıyor.
4. Katalog sözlüğünün mevcut girdileri ve `/Pages` ağacı korunarak `/AcroForm` ekleniyor.
5. CMS kapasite aşımı çıktı üretilmeden reddediliyor.
6. PdfPig `0.1.15` strict parser çıktıyı açıyor.
7. .NET `SignedCms` ve Bouncy Castle `2.7.0` detached CMS imzasını gerçek PDF byte aralıkları üzerinde ayrı ayrı doğruluyor.
8. PDFsharp `6.2.4` golden çıktıyı bağımsız PDF okuyucu olarak açıyor.

Golden PAdES B-B fixture SHA-256:

`8206460B35BBFF225605A2679BE003A917567D960FF2EEE0192B50CDAC3EBC83`

İkinci doğrulama yığını yalnız test kapsamındadır: PDFsharp 6.2.4 (MIT) + Bouncy Castle 2.7.0 (MIT). Üretim paketlerine bağımlılık eklenmedi.

Kapı henüz bütünüyle kapanmadı. DocMDP/FieldMDP okuma ve uygulama, DSS/VRI genişleme noktaları, xref/stream/dekompresyon kaynak limitleri ve desteklenmeyen PDF türlerinin açık reddi sonraki Faz 0 dilimleridir.

Preflight güncellemesi: üretim writer'ı varsayılan olarak 32 MiB belge, 100.000 obje ve 32 revision sınırı uygular. PDF 1.4–1.7 klasik xref desteklenir; şifreli, xref stream, object stream, hibrit referans ve mevcut AcroForm içeren belgeler kararlı makine-okunur kodlarla imza başlamadan reddedilir.

Politika güncellemesi: DocMDP `/P 1–3` ve FieldMDP `All`, `Include`, `Exclude` eylemleri ile alan adları salt-okunur çıkarılır. `NoChanges` ve `Signature1` hedef alanını kilitleyen politika, genel mevcut-AcroForm reddinden önce özel hata koduyla durdurulur.
