namespace ImzaKit.Verify.Validation;

public interface IPadesValidationService
{
    PadesValidationReport Validate(ReadOnlySpan<byte> pdf);

    PadesValidationReport Validate(ReadOnlySpan<byte> pdf, ValidationContext context);
}
