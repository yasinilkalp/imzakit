# PDF Motoru Seçim Spike'ı

## Sonuç

ADR-005 kapısını bütünüyle geçen hazır bir .NET PDF motoru bulunamadı. İmzaKit, mevcut PDF byte'larını değiştirmeden yalnız yeni revision ekleyen dar kapsamlı bir incremental signing writer geliştirecek. Genel amaçlı PDF düzenleyici geliştirilmeyecek.

PDFsharp imza oluşturma kabiliyetine rağmen incremental update gereksinimini karşılamadığı için seçilmedi. PdfPig, Apache-2.0 lisanslı okuyucu adayı olarak değerlendirmede kalacak; ancak yazma veya imzalama motoru olarak seçilmedi. Okuyucu adaptörüne alınması ayrıca güvenlik limitleri ve DocMDP/FieldMDP erişimiyle kanıtlanacak.

## Değerlendirilen adaylar

| ADR-005 kapısı | PDFsharp 6.2/7 önizleme | PdfPig 0.1.15 | İmzaKit incremental writer |
|---|---|---|---|
| 1. Append-only incremental update | Başarısız: kaydetme akışı `FileMode.Create` ile belgeyi yeniden yazar | Başarısız: mevcut belgelerde değişiklik desteği çok sınırlı; incremental signing API'si yok | Tasarım hedefi |
| 2. `/ByteRange` ve `/Contents` | İmza desteğinde mevcut, fakat yeniden yazılan belge üzerinde | Yok | Tasarım hedefi |
| 3. Önceki imza/revision koruması | Başarısız: özgün byte'lar korunmuyor | Yazma desteği yok | Tasarım hedefi |
| 4. DocMDP/FieldMDP okuma | Kapı için doğrulanmadı | Kapı için doğrulanmadı | Okuyucu adaptörü sorumluluğu |
| 5. DSS/VRI/timestamp genişleme noktası | Timestamp desteği var; DSS/VRI kapısı doğrulanmadı | Doğrulanmadı | Revision türleriyle genişletilecek |
| 6. Kaynak limitleri | Kapı için doğrulanmadı | Yalnız stack-depth limiti açıkça mevcut; xref, stream ve dekompresyon limitlerinin tamamı doğrulanmadı | İmza öncesi politika ve limit katmanı |
| 7. İki bağımsız doğrulayıcı | Golden test yapılmadı | Uygulanamaz | Uygulama diliminde zorunlu kapı |
| 8. Lisans/NOTICE | MIT, uyumlu | Apache-2.0, uyumlu | Apache-2.0 |

## Kanıt

- PDFsharp'ın resmi imza dokümanı yeni veya mevcut belgelerin imzalanabildiğini ve `/Contents` rezervasyonunu açıklar: <https://docs.pdfsharp.net/PDFsharp/Topics/PDF-Features/Signatures.html>
- PDFsharp resmi kaynak kodunda hedef dosya `FileMode.Create` ile açılır, dosya başlığı ve tüm objeler yeniden yazılır: <https://github.com/empira/PDFsharp/blob/master/src/foundation/src/PDFsharp/src/PdfSharp/Pdf/PdfDocument.cs>
- PDFsharp MIT lisanslıdır: <https://docs.pdfsharp.net/General/License/License-FAQ.html>
- PdfPig resmi README'si yalnız temel belge oluşturmayı ve mevcut belgelerde çok sınırlı değişikliği belirtir: <https://github.com/UglyToad/PdfPig/blob/master/README.md?plain=1>
- PdfPig Apache-2.0 lisanslıdır: <https://github.com/UglyToad/PdfPig>
- PdfPig `ParsingOptions`, recursive/nested işlemler için `MaxStackDepth` sunar; ADR-005'in diğer kaynak limitlerini tek başına karşılamaz: <https://github.com/UglyToad/PdfPig/blob/master/src/UglyToad.PdfPig/ParsingOptions.cs>

## Mimari karar

`ImzaKit.PAdES` içinde iki ayrı sınır kullanılacak:

1. `IPdfSignatureInspector`: trailer/xref zincirini, katalog ve AcroForm imza alanlarını, DocMDP/FieldMDP politikalarını güvenli limitlerle okur.
2. `IPdfIncrementalWriter`: özgün belgeyi aynen kopyalar; yeni veya güncellenen objeleri, xref/trailer zincirini ve sabit genişlikli `/ByteRange` ile `/Contents` alanlarını yalnız sona ekler.

İlk uygulama yalnız klasik xref tablo kullanan, şifrelenmemiş PDF 1.4–1.7 belgelerini ve görünmez tek imzayı kapsayacak. Xref stream, object stream, hibrit referans, şifreli PDF, bozuk xref onarımı, görünür imza ve lineerleştirme MVP dışıdır; desteklenmeyen belge açık hata ile reddedilir.

## Sonraki kanıt dilimi

İlk TDD dilimi, minimal bir PDF üzerinde placeholder revision üretip şu koşulları kanıtlayacak:

1. Çıktının ilk `N` byte'ı girdinin byte-for-byte aynısıdır.
2. Yeni trailer `/Prev` ile önceki xref'e bağlanır.
3. `/ByteRange` aralıkları yalnız `/Contents` hex alanını dışarıda bırakır.
4. Ayrılan CMS kapasitesi aşılırsa çıktı üretmeden belirgin hata döner.
5. Golden PAdES B-B, iki bağımsız doğrulayıcı kapısı tamamlanana kadar özellik “deneysel” kalır.
