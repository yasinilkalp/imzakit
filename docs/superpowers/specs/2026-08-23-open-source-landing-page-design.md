# ImzaKit Açık Kaynak Landing Page Tasarımı

**Tarih:** 23 Ağustos 2026  
**Durum:** Onaylandı  
**Hedef canlı adres:** `https://yasinilkalp.github.io/imzakit/`

## Amaç

ImzaKit'i açık kaynak bir .NET elektronik imza araç takımı olarak tanıtan, teknik kullanıcıyı NuGet kurulumuna yönlendiren ve katkıcılar için proje giriş noktası oluşturan iki dilli bir landing page yayımlamak.

Başarı ölçütleri:

- Ziyaretçi ürünün ne yaptığını, kapsamını ve ön sürüm sınırlarını ilk ekranda anlayabilmeli.
- Birincil eylem `NuGet ile Başla`, ikincil eylem `GitHub'da İncele` olmalı.
- Türkçe ve İngilizce içerik aynı statik dağıtım içinde eksiksiz bulunmalı.
- Sayfa GitHub Pages üzerinde `main` dalından otomatik yayımlanmalı.
- Proje, katkı ve güvenlik politikalarıyla açık kaynak katılımına hazır olmalı.

## Mimari

Landing page `site/` klasöründe bağımsız, statik bir web yüzeyi olarak tutulur. Teknik belgeler `docs/` altında kalır; pazarlama sayfası ile ürün dokümantasyonu birbirine karışmaz.

Sayfa saf HTML, CSS ve JavaScript kullanır. Derleme aracı, paket yöneticisi, haricî font, CSS kütüphanesi, uzaktaki script veya görsel bağımlılığı bulunmaz. Bu yaklaşım saldırı yüzeyini, Pages yapı süresini ve bakım yükünü düşük tutar.

GitHub Actions içindeki `.github/workflows/pages.yml`, yalnız `main` dalına gönderilen değişikliklerde `site/` klasörünü GitHub Pages artefaktı olarak yükler ve yayımlar. İş akışı minimum `contents: read`, `pages: write` ve `id-token: write` izinlerini kullanır; eşzamanlı yayınlar kontrollü biçimde gruplanır.

## Görsel yön

Seçilen yön **Dost canlısı açık kaynak** yaklaşımıdır:

- Sıcak kırık beyaz ana zemin
- Yumuşak, erişilebilir yeşil vurgu rengi
- Koyu yeşil metin ve yeterli kontrast
- Sınırlı yuvarlatılmış yüzeyler
- Geniş beyaz alan ve okunaklı teknik içerik
- Hafif, amaçlı hareket; `prefers-reduced-motion` desteği
- Mobil öncelikli responsive düzen

ImzaKit logosu ilk sürümde tipografik kelime işareti olarak kullanılır. Yeni bir resim veya maskot üretilmez. Görsel kimlik ürünün teknik ciddiyetini korurken açık kaynak topluluğuna davetkâr görünmelidir.

## Sayfa yapısı

### Üst menü

Yapışkan menüde ImzaKit kelime işareti, Özellikler, Nasıl Çalışır, Modüller, Dokümantasyon, Topluluk bağlantıları ve TR/EN dil anahtarı yer alır. Mobil görünümde erişilebilir açılır menü kullanılır.

### Hero

Ana mesaj: **İmzalama altyapınızı birlikte geliştirelim.**

Alt metin ImzaKit'i sağlayıcıdan bağımsız, Apache-2.0 lisanslı bir .NET 10 elektronik imza araç takımı olarak konumlandırır. Birincil buton NuGet kurulum bölümüne, ikincil buton GitHub deposuna gider.

### Güven şeridi

Apache-2.0, .NET 10, tek NuGet paketi, dokuz modül ve açık kaynak nitelikleri kısa doğrulanabilir ifadelerle sunulur.

### Nasıl çalışır

Üç adımlı akış gösterilir:

1. PDF ve CMS imza verisini hazırla.
2. Veriyi kart veya HSM sınırında imzala.
3. İmzayı tamamla ve PAdES raporuyla doğrula.

### Özellikler

PAdES, CMS, PKCS#11, doğrulama, Agent güvenliği ve API işlem modeli ayrı sorumluluklar olarak anlatılır. Ürün, üreticiye özel sürücü veya PIN arayüzü sağlıyormuş gibi sunulmaz.

### Modüller

Dokuz modül kısa açıklamalarıyla listelenir: Core, Cryptography, CMS, PAdES, PKCS#11, Verify, Agent, API ve DependencyInjection. İstemci tarafı filtreleme, kullanıcıya imzalama, sınır ve platform alanlarına göre görünümü daraltma olanağı verir.

### Kurulum ve kod

`ImzaKit 1.0.0-alpha.3` için NuGet komutu ve temel DI örneği gösterilir. Kod bloklarında kopyalama düğmesi bulunur. Kod örnekleri yayımlanmış API sözleşmesine karşı otomatik kontrol edilir.

### Açık kaynak ve topluluk

Katkı rehberi, issue oluşturma, güvenlik bildirimi, Apache-2.0 lisansı ve davranış kuralları görünür bağlantılarla sunulur.

### Ön sürüm uyarısı

Landing page şu sınırları açıkça belirtir:

- API yüzeyi `1.0.0` öncesinde değişebilir.
- Güven zinciri ve OCSP/CRL kararı entegratör sorumluluğundadır.
- Fiziksel kart/HSM, native kullanıcı onayı ve hedef PDF okuyucuları gerçek ortamda doğrulanmalıdır.
- ImzaKit üreticiye özel PKCS#11 sürücüsü veya PIN arayüzü paketlemez.

### Footer

GitHub, NuGet, teknik kullanım rehberi, canlı durum raporu, LICENSE, NOTICE, SECURITY ve katkı rehberi bağlantıları bulunur. `site/` dışındaki belgeler Pages artefaktına kopyalanmadığı için bu bağlantılar `https://github.com/yasinilkalp/imzakit/blob/main/...` biçimindeki mutlak GitHub adreslerini kullanır.

## Dil modeli

Türkçe varsayılan dildir. İngilizce, aynı HTML belgesi içindeki eşdeğer içerik üzerinden dil anahtarıyla açılır. Seçim `localStorage` içinde tutulur. JavaScript kapalıyken Türkçe içerik ve bütün temel bağlantılar kullanılabilir kalır.

Her iki dilde bölüm kapsamı aynıdır; yalnızca başlık çevirisi yapılıp teknik uyarılar eksiltilmez. `lang` niteliği dil değişiminde güncellenir.

## Açık kaynak hazırlığı

Depoya aşağıdaki topluluk dosyaları eklenir:

- `CONTRIBUTING.md`: geliştirme ortamı, testler, değişiklik kapsamı ve pull request beklentileri
- `CODE_OF_CONDUCT.md`: Contributor Covenant tabanlı davranış kuralları
- `SECURITY.md`: desteklenen sürüm ve özel güvenlik bildirimi süreci
- `.github/ISSUE_TEMPLATE/bug_report.yml`: yeniden üretim ve ortam bilgisi isteyen hata şablonu
- `.github/ISSUE_TEMPLATE/feature_request.yml`: kullanım amacı ve kapsam isteyen özellik şablonu
- `.github/ISSUE_TEMPLATE/config.yml`: güvenlik sorunlarını herkese açık issue dışında yönlendiren ayar

Mevcut `LICENSE`, `NOTICE`, iki dilli `README.md` ve teknik kullanım rehberi korunur. README içine canlı landing page bağlantısı eklenir.

## Etkileşim ve hata davranışı

- Dil anahtarı, mobil menü, modül filtresi ve kopyalama işlevleri framework olmadan çalışır.
- Clipboard API kullanılamazsa düğme kullanıcıya metni seçerek kopyalamasını söyler.
- JavaScript hatası temel içeriği veya navigasyon bağlantılarını erişilemez kılmaz.
- Haricî ağ isteği yapılmaz; sayfa çevrimdışı açıldığında da içerik görüntülenir.
- GitHub, NuGet ve doküman bağlantıları açıkça adlandırılır; anlamsız `buraya tıklayın` metni kullanılmaz.

## Erişilebilirlik ve performans

- Semantik başlık sırası, skip link, klavye erişimi ve görünür odak stili zorunludur.
- Renk kontrastı WCAG AA düzeyini hedefler.
- Mobil menü uygun `aria-expanded` ve `aria-controls` niteliklerini kullanır.
- Hareket azaltma tercihi uygulanır.
- Haricî bağımlılık ve ağır medya olmadığı için ilk yüklemede ağ isteği yalnız HTML belgesidir.
- Sayfa 360 px genişlikte yatay taşma üretmez.

## Doğrulama

Yeni bir PowerShell sözleşme denetimi aşağıdakileri doğrular:

- Türkçe ve İngilizce içerik blokları
- NuGet sürümü ve kurulum komutu
- Dokuz modül ve zorunlu açık kaynak bağlantıları
- Alpha/güvenlik uyarıları
- Erişilebilirlik işaretleri
- GitHub Pages iş akışı ve minimum izinleri
- Haricî script, stylesheet, font veya görsel bağımlılığı bulunmaması

Tarayıcı doğrulaması masaüstü ve 390 px mobil görünümde yapılır. Dil değişimi, mobil menü, filtreleme, kod kopyalama, bölüm bağlantıları ve yatay taşma kontrol edilir. Tarayıcı konsolunda hata bulunmamalıdır.

Mevcut FRD denetimi ayrıca çalıştırılır. Dokümantasyon ve statik site değişikliği üretim kütüphanelerini etkilemediğinden tam .NET test paketi zorunlu değildir; Pages iş akışı kendi sözleşme kontrolünü yayın öncesi çalıştırır.

## Yayın ve kabul

Uygulama tek commit grubu halinde `main` dalına gönderilir. Pages iş akışının başarılı tamamlanması ve `https://yasinilkalp.github.io/imzakit/` adresinin HTTP 200 dönmesi yayın kanıtıdır.

GitHub Pages depo ayarı henüz Actions kaynağına geçirilmemişse, bu ayar kullanıcı onayıyla etkinleştirilir. Özel alan adı ilk sürüm kapsamında değildir.

Canlı geliştirme durum raporu landing page, topluluk dosyaları, doğrulama sonucu ve Pages yayın adresiyle güncellenir.

## Kapsam dışı

- Özel alan adı ve DNS yönetimi
- Telemetri, analitik veya çerezler
- Blog, CMS veya sunucu tarafı işlevler
- Yeni logo/mascot üretimi
- Paket API'sinde değişiklik
- NuGet için yeni sürüm yayımlama
