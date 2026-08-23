using ImzaKit.Core.Signing;
using ImzaKit.PAdES.Incremental;

namespace ImzaKit.PAdES.Preparation;

public sealed class PadesSignaturePreparation
{
    public PadesSignaturePreparation(
        PdfSignaturePlaceholder placeholder,
        SignaturePreparation signaturePreparation)
    {
        ArgumentNullException.ThrowIfNull(placeholder);
        ArgumentNullException.ThrowIfNull(signaturePreparation);
        Placeholder = placeholder;
        SignaturePreparation = signaturePreparation;
    }

    public PdfSignaturePlaceholder Placeholder { get; }

    public SignaturePreparation SignaturePreparation { get; }
}
