namespace ImzaKit.Agent.Native;

public interface INativeConsentPrompt
{
    NativeConsentDecision Prompt(NativeConsentRequest request);
}
