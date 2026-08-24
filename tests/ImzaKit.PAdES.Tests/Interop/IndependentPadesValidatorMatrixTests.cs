namespace ImzaKit.PAdES.Tests.Interop;

public sealed class IndependentPadesValidatorMatrixTests
{
    [Fact]
    public void GoldenPadesIsAcceptedByTwoIndependentValidators()
    {
        GoldenPadesFixture fixture = GoldenPadesFixture.Create();
        IIndependentPadesValidator[] validators =
        [
            new PdfPigSignedCmsValidator(),
            new PdfSharpBouncyCastleValidator()
        ];

        Assert.Equal(2, validators.Length);
        Assert.NotEqual(validators[0].Name, validators[1].Name);
        foreach (IIndependentPadesValidator validator in validators)
        {
            IndependentPadesVerdict verdict = validator.Validate(fixture);
            Assert.True(verdict.PdfOpens, validator.Name);
            Assert.True(verdict.CmsSignatureValid, validator.Name);
        }
    }
}
