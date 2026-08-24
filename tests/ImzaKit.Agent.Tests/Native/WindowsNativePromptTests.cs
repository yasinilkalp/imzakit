using ImzaKit.Agent.Native;

namespace ImzaKit.Agent.Tests.Native;

public sealed class WindowsNativePromptTests
{
    [Fact]
    public void CancelledPinDialogDoesNotCreateASession()
    {
        ScriptedPinDialog dialog = new(success: false, pin: "1234");
        WindowsNativePinPrompt prompt = new(dialog);

        using NativePinSession? session = prompt.Acquire();

        Assert.Null(session);
        Assert.Equal(1, dialog.Calls);
        Assert.True(dialog.PinWasCleared);
    }

    [Fact]
    public void SuccessfulPinDialogCopiesCharsAndClearsTheDialogBuffer()
    {
        ScriptedPinDialog dialog = new(success: true, pin: "2468");
        WindowsNativePinPrompt prompt = new(dialog);
        char[] seen = [];

        using (NativePinSession? session = prompt.Acquire())
        {
            Assert.NotNull(session);
            session!.Use(pin => seen = pin.ToArray());
        }

        Assert.Equal("2468".ToCharArray(), seen);
        Assert.True(dialog.PinWasCleared);
        Assert.DoesNotContain("2468", dialog.LastCaption, StringComparison.Ordinal);
    }

    [Fact]
    public void DisposedPinSessionCannotBeReused()
    {
        NativePinSession session = new("9999");
        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() => session.Use(_ => { }));
    }

    [Fact]
    public void ConsentDialogShowsDocumentSummaryAndNeverAsksForPin()
    {
        ScriptedConsentDialog dialog = new(NativeConsentDecision.Approved);
        WindowsNativeConsentPrompt prompt = new(dialog);
        NativeConsentRequest request = new(
            "sozlesme.pdf",
            "AABBCCDDEEFF",
            "https://app.example",
            "Test NES",
            "SHA256withRSA");

        NativeConsentDecision decision = prompt.Prompt(request);

        Assert.Equal(NativeConsentDecision.Approved, decision);
        Assert.Contains("sozlesme.pdf", dialog.LastMessage, StringComparison.Ordinal);
        Assert.Contains("AABBCCDDEEFF", dialog.LastMessage, StringComparison.Ordinal);
        Assert.Contains("https://app.example", dialog.LastMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("PIN", dialog.LastMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", dialog.LastMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DeniedConsentIsReturnedWithoutOpeningPinDialog()
    {
        ScriptedConsentDialog dialog = new(NativeConsentDecision.Denied);
        WindowsNativeConsentPrompt prompt = new(dialog);

        Assert.Equal(
            NativeConsentDecision.Denied,
            prompt.Prompt(new NativeConsentRequest("a.pdf", "00", "https://app.example", "cert", "SHA256withRSA")));
    }

    private sealed class ScriptedPinDialog(bool success, string pin) : ISecurePinDialog
    {
        private char[]? _buffer;
        public int Calls { get; private set; }
        public string LastCaption { get; private set; } = "";
        public bool PinWasCleared => _buffer is null || _buffer.All(ch => ch == '\0');

        public bool TryReadPin(PinDialogRequest request, out char[] pinChars)
        {
            Calls++;
            LastCaption = request.Caption;
            if (!success)
            {
                pinChars = [];
                _buffer = pinChars;
                return false;
            }

            pinChars = pin.ToCharArray();
            _buffer = pinChars;
            return true;
        }
    }

    private sealed class ScriptedConsentDialog(NativeConsentDecision decision) : IConsentDialog
    {
        public string LastMessage { get; private set; } = "";

        public NativeConsentDecision Prompt(string caption, string message)
        {
            LastMessage = message;
            _ = caption;
            return decision;
        }
    }
}
