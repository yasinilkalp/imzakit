using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.Timestamp.Tests;

public sealed class TsaCredentialStoreTests
{
    [Fact]
    public void CredentialStringDoesNotContainSecret()
    {
        TsaCredential basic = TsaCredential.Basic("tsa-user", "super-secret-password");
        TsaCredential bearer = TsaCredential.Bearer("live-token-value");

        Assert.DoesNotContain("super-secret-password", basic.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("live-token-value", bearer.ToString(), StringComparison.Ordinal);
        Assert.StartsWith("Basic ", basic.AuthorizationHeader, StringComparison.Ordinal);
        Assert.Equal("Bearer live-token-value", bearer.AuthorizationHeader);
    }

    [Fact]
    public async Task EnvironmentStoreReadsBasicAndBearerFromSecretVariables()
    {
        Dictionary<string, string> variables = new(StringComparer.OrdinalIgnoreCase)
        {
            ["IMZAKIT_TSA_PRIMARY_USER"] = "tsa-user",
            ["IMZAKIT_TSA_PRIMARY_PASSWORD"] = "tsa-secret",
            ["IMZAKIT_TSA_BACKUP_BEARER"] = "vault-token"
        };
        EnvironmentTsaCredentialStore store = new(name =>
            variables.TryGetValue(name, out string? value) ? value : null);

        TsaCredential? basic = await store.GetAsync("primary", CancellationToken.None);
        TsaCredential? bearer = await store.GetAsync("backup", CancellationToken.None);
        TsaCredential? missing = await store.GetAsync("public", CancellationToken.None);

        Assert.Equal("Basic " + Convert.ToBase64String("tsa-user:tsa-secret"u8), basic!.AuthorizationHeader);
        Assert.Equal("Bearer vault-token", bearer!.AuthorizationHeader);
        Assert.Null(missing);
    }

    [Fact]
    public async Task EnvironmentStoreRejectsIncompleteBasicCredential()
    {
        EnvironmentTsaCredentialStore store = new(name =>
            string.Equals(name, "IMZAKIT_TSA_PRIMARY_USER", StringComparison.OrdinalIgnoreCase)
                ? "tsa-user"
                : null);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.GetAsync("primary", CancellationToken.None).AsTask());

        Assert.Equal("IMZAKIT.TS.CREDENTIAL_INVALID", error.Message);
    }
}
