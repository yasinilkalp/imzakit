# Tek ImzaKit NuGet Paketi Tasarımı

## Amaç

İmzaKit’in dokuz modüler üretim projesini kaynak ve test sınırları olarak koruyup NuGet.org’da yalnız `ImzaKit` kimliğiyle tek paket yayımlamak. İlk sürüm `1.0.0-alpha.1`, hedef framework `.NET 10` ve lisans `Apache-2.0` olacaktır.

Kullanıcı kurulumu:

```shell
dotnet add package ImzaKit --version 1.0.0-alpha.1
```

## Karar

Tek fiziksel NuGet paketi dokuz mevcut modül assembly’sini ve bunların taşınabilir PDB dosyalarını taşıyacaktır. Kaynak projeler bir assembly’de birleştirilmeyecek, namespace’ler ve proje referansları değiştirilmeyecektir.

NuGet.org’a şu sürümde yalnız bir kimlik gönderilecektir:

- `ImzaKit` — `1.0.0-alpha.1`

Şu kimlikler paketlenmeyecek ve yayımlanmayacaktır:

- `ImzaKit.Agent`
- `ImzaKit.Api`
- `ImzaKit.Cms`
- `ImzaKit.Core`
- `ImzaKit.Cryptography`
- `ImzaKit.DependencyInjection`
- `ImzaKit.PAdES`
- `ImzaKit.Pkcs11`
- `ImzaKit.Verify`

## Değerlendirilen Yaklaşımlar

### 1. Tek paket, dokuz assembly — seçilen

Paketleme projesi dokuz proje çıktısını `lib/net10.0` altında toplar. Kullanıcı tek paket kurar; geliştirme ekibi modüler derleme ve test sınırlarını korur. Bütün modüller birlikte sürümlenir ve indirilir.

### 2. Şemsiye/meta paket — reddedilen

`ImzaKit` paketi dokuz `ImzaKit.*` paketine bağımlı olurdu. Kurulum komutu tek görünse de NuGet.org’da on paket yayımlanması gerektiğinden kullanıcının “tek paket” şartını karşılamaz.

### 3. Tek assembly — reddedilen

Dokuz projenin kaynaklarını tek projede derlemek dağıtım yüzeyini küçültür ancak mevcut sınırları, proje referanslarını ve test mimarisini gereksiz yere değiştirir. Sağladığı fayda seçilen yaklaşımdan daha düşük, geçiş riski daha yüksektir.

## Paketleme Mimarisi

`packaging/ImzaKit/ImzaKit.csproj` yalnız paket üretme sorumluluğuna sahip olacaktır. Proje dokuz kaynak projeye `PrivateAssets="all"` proje referansı verecek; böylece derleme sırası ve çıktılar belirlenirken nuspec içinde yayımlanmayan `ImzaKit.*` paket bağımlılıkları oluşmayacaktır.

NuGet’in desteklenen `TargetsForTfmSpecificBuildOutput` ve `TargetsForTfmSpecificDebugSymbolsInPackage` genişletme noktaları kullanılacaktır:

- Dokuz modül DLL’i `lib/net10.0` içine eklenir.
- Dokuz taşınabilir PDB sembol paketine eklenir.
- Paketleme projesinin boş assembly’si nihai pakete eklenmez.
- `README.md` paket köküne eklenir.

Dokuz kaynak projenin her biri `IsPackable=false` olacaktır. Paketleme projesi bunu `IsPackable=true` olarak geçersiz kılacaktır. Solution seviyesindeki `dotnet pack` böylece yalnız `ImzaKit` paketini üretir.

## Dış Bağımlılıklar

Tek paket nuspec’i yalnız çalışma zamanında gereken dış NuGet bağımlılıklarını bildirecektir:

- `BouncyCastle.Cryptography` `2.7.0`
- `Microsoft.Extensions.DependencyInjection.Abstractions` `10.0.11`
- `System.Security.Cryptography.Pkcs` `10.0.11`

`ImzaKit.*` biçiminde iç paket bağımlılığı bulunmayacaktır. Dış bağımlılık DLL’leri ImzaKit paketinin içine kopyalanmayacak; NuGet tarafından normal bağımlılık olarak çözülecektir.

## Metadata ve Lisans

Paket metadata’sı merkezi MSBuild ayarlarından gelecektir:

- Package ID: `ImzaKit`
- Version: `1.0.0-alpha.1`
- License: `Apache-2.0`
- Repository: `https://github.com/yasinilkalp/imzakit`
- Target framework: `net10.0`
- README: `README.md`
- Symbol format: `.snupkg`

API anahtarı hiçbir dosyaya, loga veya Git geçmişine yazılmayacaktır. Yayın komutu anahtarı yalnız `NUGET_API_KEY` ortam değişkeninden alacaktır.

## Paketleme Akışı

1. Solution Release modunda derlenir.
2. Solution pack komutu yalnız `ImzaKit.1.0.0-alpha.1.nupkg` ve `ImzaKit.1.0.0-alpha.1.snupkg` üretir.
3. Doğrulama betiği paket arşivlerini açmadan okuyarak kimlik, sürüm, lisans, repository, README, dokuz DLL, dokuz PDB ve dış bağımlılıkları doğrular.
4. Geçici tüketici projesi yalnız yerel `ImzaKit` paketini referans alır; birden fazla modülden public türleri derler ve çalıştırır.
5. Tüm 90 test yeniden çalıştırılır.
6. Durum raporu tek paket sonucuyla güncellenir.
7. Kaynak değişiklikleri Git’e gönderilir.
8. `NUGET_API_KEY` varsa paket NuGet.org’a gönderilir; görünürlük resmi NuGet API’sinden doğrulanır.

## Hata Kapıları

Paket üretimi veya yayın şu koşullarda duracaktır:

- Birden fazla ana `.nupkg` üretilirse.
- Paket kimliği veya sürümü beklenen değer değilse.
- Dokuz modül DLL’inden ya da PDB’sinden biri eksikse veya yinelenirse.
- Nuspec içinde `ImzaKit.*` iç paket bağımlılığı varsa.
- Üç dış bağımlılıktan biri eksik veya sürümü farklıysa.
- README, Apache-2.0 lisansı ya da repository URL’si eksikse.
- Release build uyarı/hata üretirse veya herhangi bir test başarısız olursa.
- NuGet.org’da `ImzaKit` `1.0.0-alpha.1` zaten varsa.
- `NUGET_API_KEY` yoksa; bu durumda paket hazırlanır fakat yayın yapılmaz.

## Doğrulama Ölçütleri

Değişiklik aşağıdaki kanıtların tümü sağlandığında uygulama açısından tamamlanmış sayılır:

- Release build: `0` hata, `0` uyarı.
- Test: `90/90` başarılı.
- Paket çıktısı: `1` `.nupkg`, `1` `.snupkg`.
- Ana paket: tam olarak dokuz `ImzaKit.*.dll`; paketleme assembly’si yok.
- Sembol paketi: tam olarak dokuz eşleşen `ImzaKit.*.pdb`.
- Nuspec: üç dış bağımlılık, sıfır iç `ImzaKit.*` paket bağımlılığı.
- Tüketici smoke testi: tek `PackageReference Include="ImzaKit"` ile derleme ve çalışma başarılı.
- Git çalışma ağacı: yalnız amaçlanan kaynak, doküman ve rapor değişiklikleri.

NuGet yayını ancak API anahtarı sağlanıp resmi API görünürlüğü doğrulandığında ayrıca tamamlanmış sayılır.

## Dokümantasyon ve Durum Raporu

Kök README kurulum örneğini tek `ImzaKit` paketine göre gösterecektir. Paket tablosu yayımlanan paketler yerine paket içindeki modülleri açıklayacaktır.

`reports/imzakit-gelistirme-durum.html` şu gerçek durumu gösterecektir:

- Yayın öncesi: tek paket ve tek sembol paketi doğrulandı; NuGet anahtarı bekleniyor.
- Yayın sonrası: `ImzaKit 1.0.0-alpha.1` NuGet.org’da doğrulandı.

Harici AKİS kartı, native kullanıcı onayı, mTLS, trust/revocation ve installer kabul çalışmaları bu paketleme değişikliğinin kapsamı dışındadır ve raporda açık harici kapılar olarak kalır.
