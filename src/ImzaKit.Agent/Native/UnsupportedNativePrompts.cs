namespace ImzaKit.Agent.Native;

public sealed class UnsupportedNativePinPrompt : INativePinPrompt
{
    public NativePinSession? Acquire() => null;
}

public sealed class UnsupportedNativeConsentPrompt : INativeConsentPrompt
{
    public NativeConsentDecision Prompt(NativeConsentRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return NativeConsentDecision.Denied;
    }
}
