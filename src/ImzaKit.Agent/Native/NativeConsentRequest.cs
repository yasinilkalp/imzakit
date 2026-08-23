namespace ImzaKit.Agent.Native;

public sealed record NativeConsentRequest(
    string DocumentName,
    string DocumentSha256,
    string CallingOrigin,
    string CertificateLabel,
    string Algorithm);
