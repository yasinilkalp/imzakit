using System.Runtime.InteropServices;

namespace ImzaKit.Agent.Native;

public sealed class CredUiSecurePinDialog : ISecurePinDialog
{
    public bool TryReadPin(PinDialogRequest request, out char[] pinChars)
    {
        ArgumentNullException.ThrowIfNull(request);
        pinChars = [];
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        CREDUI_INFO info = new()
        {
            cbSize = Marshal.SizeOf<CREDUI_INFO>(),
            pszCaptionText = request.Caption,
            pszMessageText = request.Message
        };

        uint authPackage = 0;
        nint outAuthBuffer = 0;
        uint outAuthBufferSize = 0;
        bool save = false;
        uint result = CredUIPromptForWindowsCredentialsW(
            ref info,
            0,
            ref authPackage,
            0,
            0,
            out outAuthBuffer,
            out outAuthBufferSize,
            ref save,
            0x1); // CREDUIWIN_GENERIC

        if (result != 0 || outAuthBuffer == 0 || outAuthBufferSize == 0)
        {
            if (outAuthBuffer != 0)
            {
                Marshal.ZeroFreeCoTaskMemUnicode(outAuthBuffer);
            }

            return false;
        }

        try
        {
            int userLength = 256;
            int domainLength = 256;
            int passwordLength = 256;
            Span<char> user = stackalloc char[userLength];
            Span<char> domain = stackalloc char[domainLength];
            Span<char> password = stackalloc char[passwordLength];
            if (!CredUnPackAuthenticationBufferW(
                    0x1, // CRED_PACK_PROTECTED_CREDENTIALS
                    outAuthBuffer,
                    outAuthBufferSize,
                    user,
                    ref userLength,
                    domain,
                    ref domainLength,
                    password,
                    ref passwordLength))
            {
                return false;
            }

            int pinLength = passwordLength > 0 && password[passwordLength - 1] == '\0'
                ? passwordLength - 1
                : passwordLength;
            pinChars = password[..Math.Max(pinLength, 0)].ToArray();
            password.Clear();
            return pinChars.Length > 0;
        }
        finally
        {
            Marshal.ZeroFreeCoTaskMemUnicode(outAuthBuffer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public nint hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public nint hbmBanner;
    }

    [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint CredUIPromptForWindowsCredentialsW(
        ref CREDUI_INFO pUiInfo,
        uint dwAuthError,
        ref uint pulAuthPackage,
        nint pvInAuthBuffer,
        uint ulInAuthBufferSize,
        out nint ppvOutAuthBuffer,
        out uint pulOutAuthBufferSize,
        ref bool pfSave,
        uint dwFlags);

    [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredUnPackAuthenticationBufferW(
        uint dwFlags,
        nint pAuth,
        uint cbAuth,
        Span<char> pszUserName,
        ref int pcchMaxUserName,
        Span<char> pszDomainName,
        ref int pcchMaxDomainName,
        Span<char> pszPassword,
        ref int pcchMaxPassword);
}

public sealed class MessageBoxConsentDialog : IConsentDialog
{
    public NativeConsentDecision Prompt(string caption, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(caption);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        if (!OperatingSystem.IsWindows())
        {
            return NativeConsentDecision.Denied;
        }

        int result = MessageBoxW(0, message, caption, 0x00000004 | 0x00000020); // MB_YESNO | MB_ICONQUESTION
        return result == 6 ? NativeConsentDecision.Approved : NativeConsentDecision.Denied;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int MessageBoxW(nint hWnd, string lpText, string lpCaption, uint uType);
}
