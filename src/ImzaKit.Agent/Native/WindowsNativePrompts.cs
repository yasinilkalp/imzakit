namespace ImzaKit.Agent.Native;

public sealed record PinDialogRequest(string Caption, string Message);

public interface ISecurePinDialog
{
    bool TryReadPin(PinDialogRequest request, out char[] pinChars);
}

public interface IConsentDialog
{
    NativeConsentDecision Prompt(string caption, string message);
}

public sealed class WindowsNativePinPrompt(ISecurePinDialog dialog) : INativePinPrompt
{
    public NativePinSession? Acquire()
    {
        ArgumentNullException.ThrowIfNull(dialog);
        PinDialogRequest request = new(
            "İmzaKit kart PIN",
            "Kullanıcı adı: imza (hesap adı değil).\r\nŞifre: kart/token PIN.\r\nPIN tarayıcıya veya API'ye gönderilmez.");
        if (!dialog.TryReadPin(request, out char[] pinChars))
        {
            Clear(pinChars);
            return null;
        }

        try
        {
            return pinChars.Length == 0 ? null : new NativePinSession(pinChars);
        }
        finally
        {
            Clear(pinChars);
        }
    }

    private static void Clear(char[] buffer)
    {
        if (buffer.Length > 0)
        {
            Array.Clear(buffer);
        }
    }
}

public sealed class WindowsNativeConsentPrompt(IConsentDialog dialog) : INativeConsentPrompt
{
    public NativeConsentDecision Prompt(NativeConsentRequest request)
    {
        ArgumentNullException.ThrowIfNull(dialog);
        ArgumentNullException.ThrowIfNull(request);
        string message =
            $"Belge: {request.DocumentName}{Environment.NewLine}" +
            $"Özet: {request.DocumentSha256}{Environment.NewLine}" +
            $"Kaynak: {request.CallingOrigin}{Environment.NewLine}" +
            $"Sertifika: {request.CertificateLabel}{Environment.NewLine}" +
            $"Algoritma: {request.Algorithm}{Environment.NewLine}{Environment.NewLine}" +
            "Bu belgeyi imzalamayı onaylıyor musunuz?";
        return dialog.Prompt("İmzaKit imza onayı", message);
    }
}
