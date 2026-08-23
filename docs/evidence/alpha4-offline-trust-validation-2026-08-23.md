# Alpha.4 çevrimdışı güven doğrulama kanıtı

- Ölçüm zamanı (UTC): `2026-08-23T19:54:12Z`
- Dal: `main`
- Paket: `ImzaKit.1.0.0-alpha.4.nupkg`
- SHA-256: `CF271F64CD3918E0246212034F933BCDA1BC82E0277C9608156DC4EEDE6FEEE2`
- Yayın durumu: **NuGet yayını yapılmadı.** Yayın, ayrı onay ve Trusted Publishing çalıştırması gerektirir.

## Temiz derleme ve test

```powershell
dotnet clean ImzaKit.slnx -c Release -m:1 -nodeReuse:false -p:UseSharedCompilation=false
dotnet restore ImzaKit.slnx -m:1 -p:RestoreIgnoreFailedSources=true
dotnet build ImzaKit.slnx -c Release --no-restore -m:1 -nodeReuse:false -p:UseSharedCompilation=false
dotnet test ImzaKit.slnx -c Release --no-restore --no-build -m:1 -nodeReuse:false --logger "console;verbosity=normal"
```

Sonuçlar:

- Clean: geçti, `0` uyarı, `0` hata.
- Restore: geçti.
- Release build: geçti, `0` uyarı, `0` hata.
- Test: `159` geçti, `0` başarısız, `0` atlandı.

Test dağılımı: Agent 9, API 17, Certificate 15, CMS 12, Core 4, Cryptography 3, PAdES 35, PKCS#11 5, Revocation 20, Trust 16, Verify 23.

## Paket doğrulaması

```powershell
dotnet pack packaging\ImzaKit\ImzaKit.csproj -c Release --no-build --no-restore -o artifacts\packages -m:1 -nodeReuse:false
.\scripts\verify-nuget-package.ps1 -PackageDirectory .\artifacts\packages
```

Sonuç: geçti. Paket tam 12 üretim DLL’i ve sembol paketi tam 12 PDB içeriyor; `ImzaKit.*` iç paket bağımlılığı bulunmuyor.

DLL envanteri:

1. `ImzaKit.Agent.dll`
2. `ImzaKit.Api.dll`
3. `ImzaKit.Certificate.dll`
4. `ImzaKit.Cms.dll`
5. `ImzaKit.Core.dll`
6. `ImzaKit.Cryptography.dll`
7. `ImzaKit.DependencyInjection.dll`
8. `ImzaKit.PAdES.dll`
9. `ImzaKit.Pkcs11.dll`
10. `ImzaKit.Revocation.dll`
11. `ImzaKit.Trust.dll`
12. `ImzaKit.Verify.dll`

## Dokümantasyon, FRD ve workflow kapıları

```powershell
.\scripts\validate-frd.ps1
.\scripts\verify-technical-guide.ps1
.\scripts\verify-landing-page.ps1
.\scripts\verify-open-source-readiness.ps1
.\scripts\verify-pages-workflow.ps1
.\scripts\verify-publish-workflow.ps1
```

Altı betiğin tamamı geçti. Paket doğrulamasıyla birlikte final doğrulama kümesi yedi kapıdan oluşur.

## Çalışma ağacı kaydı

`git status --short` ölçümünde 430 kayıt vardı: 424 kayıt, depoda izlenen `bin/obj` çıktılarının temiz build ile yeniden üretilmesinden kaynaklandı. Üretim dışı kalan altı kayıt, bu çalışma başlamadan önce mevcut olan ve korunmuş landing-page redesign çalışmasıdır:

```text
 M site/index.html
?? site/logo-light.png
?? site/logo-mark.png
?? site/logo.png
?? site/redesign-a-editorial.html
?? site/redesign-b-console.html
```

Alpha.4 kaynak, test, paketleme, FRD ve rehber değişiklikleri commit edilmiştir. `site/index.html` içindeki Alpha.4 içerik eklemeleri, önceden var olan kullanıcı redesign değişiklikleriyle aynı dosyada bulunduğundan kullanıcı çalışmasını istemeden commit etmemek için çalışma ağacında korunmuştur.
