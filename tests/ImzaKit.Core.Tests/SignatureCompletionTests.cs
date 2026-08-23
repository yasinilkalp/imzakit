using ImzaKit.Core.Signing;

namespace ImzaKit.Core.Tests;

public sealed class SignatureCompletionTests
{
    [Fact]
    public void CreatePreservesPrepareBindingAndCopiesSignatureValue()
    {
        Guid operationId = Guid.Parse("2af90dd8-4cb7-4fe3-a71a-cc15aec81bdb");
        byte[] signatureValue = [0x10, 0x20, 0x30];

        SignatureCompletion completion = SignatureCompletion.Create(
            operationId,
            prepareVersion: 4,
            new string('B', 64),
            signatureValue);

        signatureValue[0] = 0xFF;

        Assert.Equal(operationId, completion.OperationId);
        Assert.Equal(4, completion.PrepareVersion);
        Assert.Equal(new string('B', 64), completion.CertificateFingerprintSha256);
        Assert.Equal(new byte[] { 0x10, 0x20, 0x30 }, completion.SignatureValue.ToArray());
    }
}
