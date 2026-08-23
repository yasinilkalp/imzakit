using System.Text;
using ImzaKit.PAdES.Policy;

namespace ImzaKit.PAdES.Tests.Policy;

public sealed class PdfModificationPolicyInspectorTests
{
    [Theory]
    [InlineData("", PdfCertificationChangeLevel.None)]
    [InlineData("/TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 1 >>", PdfCertificationChangeLevel.NoChanges)]
    [InlineData("/TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 2 >>", PdfCertificationChangeLevel.FormFillAndSign)]
    [InlineData("/TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 3 >>", PdfCertificationChangeLevel.FormFillSignAndAnnotate)]
    public void InspectReadsDocMdpPermission(string policy, PdfCertificationChangeLevel expected)
    {
        PdfModificationPolicy result = PdfModificationPolicyInspector.Inspect(Pdf(policy));

        Assert.Equal(expected, result.CertificationPermission);
    }

    [Theory]
    [InlineData("All", PdfFieldLockAction.All)]
    [InlineData("Include", PdfFieldLockAction.Include)]
    [InlineData("Exclude", PdfFieldLockAction.Exclude)]
    public void InspectReadsFieldMdpActionAndFieldNames(string action, PdfFieldLockAction expected)
    {
        byte[] pdf = Pdf($"/TransformMethod /FieldMDP /TransformParams << /Action /{action} /Fields [(Amount) (Approval)] >>");

        PdfModificationPolicy result = PdfModificationPolicyInspector.Inspect(pdf);

        Assert.Equal(expected, result.FieldLockAction);
        Assert.Equal(["Amount", "Approval"], result.FieldNames);
    }

    private static byte[] Pdf(string policy) => Encoding.ASCII.GetBytes($"%PDF-1.7\n{policy}\n%%EOF");
}
