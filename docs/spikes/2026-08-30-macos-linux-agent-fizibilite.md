# macOS/Linux Agent Fizibilite Spike'ı

## Sonuç

Ortak Agent protokolü (loopback bind, imzalı bilet, replay/origin/digest) .NET 10 üzerinde platform bağımsızdır ve Windows dışı derlemede çalışır. Native PIN (CredUI) ve onay (MessageBox) yalnız Windows’tadır. Unix Agent host’u **hazır değildir**: PIN tarayıcıya veya API’ye düşmeden imza üretilemez; fail-closed `UnsupportedNativePinPrompt` / `UnsupportedNativeConsentPrompt` oturum açmaz ve onayı reddeder.

macOS Keychain, Linux secret-service, GTK/Cocoa diyalog ve fiziksel AKİS/eToken Unix sürücüsü bu dilimde yoktur. Üretim Agent artefaktı ADR-002’ye göre Windows x64/arm64 kalır.

## Değerlendirilen sınırlar

| Yetenek | Windows | macOS/Linux | Karar |
|---|---|---|---|
| Loopback `127.0.0.1` / `::1` | Desteklenir | Desteklenir (protokol) | Ortak kod; dış arayüz bind yok |
| Bilet, nonce, origin | Desteklenir | Desteklenir | Platform bağımsız |
| Native PIN | CredUI | Yok | Fail-closed; HTTP PIN yok |
| Native onay | MessageBox | Yok | Fail-closed Deny |
| PKCS#11 DLL | `akisp11.dll`, `eTPKCS11.dll`, SoftHSM2 | `libakisp11.so`, `libsofthsm2.so` adları listeli | Unix kök allowlist: `/usr/lib/softhsm`, `/usr/lib64/softhsm`; vendor `.so` paketlenmez |
| Host hazır | Evet | Hayır | `AgentPlatformCapabilities.HostReady` yalnız Windows |

## Kanıt

- `AgentLoopbackEndpoint` yalnız loopback kabul eder; OS ayrımı yoktur.
- `CredUiSecurePinDialog` / `MessageBoxConsentDialog` `OperatingSystem.IsWindows()` değilse PIN/onay üretmez.
- `AddImzaKitAgent` Windows’ta mevcut native diyalogları, diğerlerinde fail-closed prompt’ları kaydeder.
- `AgentPlatformCapabilitiesTests` HostReady’yi `OperatingSystem.IsWindows()` ile hizalar.
- Fiziksel Unix kart/HSM laboratuvarı yoktur; donanım kabulü iddia edilmez.

## Mimari karar

1. Public Agent protokolü Windows dışı derlemede kırılmaz.
2. Native UI eksikken imza host’u “hazır” sayılmaz.
3. PKCS#11 Unix paylaşımlı nesne adları profilde kalır; yol operatör allowlist’i ile verilir.
4. macOS/Linux native PIN/onay ayrı uygulama dilimidir; bu spike host’u teslim etmez.

## Sonraki kanıt dilimi

Unix native PIN/onay (secret-service / güvenlik diyalogu) ve gerçek `libakisp11.so` laboratuvarı olmadan Agent host kabul edilmez. Sıradaki Faz 5 yazılım: eIDAS doğrulama profili veya ek PKCS#11 vendor.
