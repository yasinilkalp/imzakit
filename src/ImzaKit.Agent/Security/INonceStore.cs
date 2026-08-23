namespace ImzaKit.Agent.Security;

public interface INonceStore
{
    bool TryConsume(string nonce, DateTimeOffset expiresAt);
}
