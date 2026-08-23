using ImzaKit.Core.Cryptography;
using ImzaKit.Core.Signing;

namespace ImzaKit.Core.Tests;

public sealed class SignaturePreparationTests
{
    [Fact]
    public void CreateCopiesDataToBeSignedBytes()
    {
        byte[] source = [0x30, 0x31, 0x32];

        SignaturePreparation preparation = SignaturePreparation.Create(
            Guid.Parse("2af90dd8-4cb7-4fe3-a71a-cc15aec81bdb"),
            new string('A', 64),
            source,
            SignatureAlgorithmProfile.RsaSha256,
            new string('B', 64),
            prepareVersion: 1);

        source[0] = 0xFF;

        Assert.Equal(new byte[] { 0x30, 0x31, 0x32 }, preparation.DataToBeSigned.ToArray());
    }

    [Fact]
    public void CreatePreservesSigningContext()
    {
        Guid operationId = Guid.Parse("2af90dd8-4cb7-4fe3-a71a-cc15aec81bdb");

        SignaturePreparation preparation = SignaturePreparation.Create(
            operationId,
            new string('A', 64),
            [0x01],
            SignatureAlgorithmProfile.RsaSha256,
            new string('B', 64),
            prepareVersion: 3);

        Assert.Equal(operationId, preparation.OperationId);
        Assert.Equal(new string('A', 64), preparation.DocumentSha256);
        Assert.Equal(SignatureAlgorithmProfile.RsaSha256, preparation.Algorithm);
        Assert.Equal(new string('B', 64), preparation.CertificateFingerprintSha256);
        Assert.Equal(3, preparation.PrepareVersion);
    }

    [Fact]
    public void CreateRejectsEmptyDataToBeSigned()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            SignaturePreparation.Create(
                Guid.NewGuid(),
                new string('A', 64),
                [],
                SignatureAlgorithmProfile.RsaSha256,
                new string('B', 64),
                prepareVersion: 1));

        Assert.Equal("dataToBeSigned", exception.ParamName);
    }
}
