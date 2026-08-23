namespace ImzaKit.PAdES.Appearance;

public sealed class PadesSignatureAppearance
{
    private PadesSignatureAppearance(
        bool isVisible,
        int pageNumber,
        double lowerLeftX,
        double lowerLeftY,
        double upperRightX,
        double upperRightY,
        string text,
        DateTimeOffset? displayedAt,
        byte[]? imageBytes)
    {
        IsVisible = isVisible;
        PageNumber = pageNumber;
        LowerLeftX = lowerLeftX;
        LowerLeftY = lowerLeftY;
        UpperRightX = upperRightX;
        UpperRightY = upperRightY;
        Text = text;
        DisplayedAt = displayedAt;
        ImageBytes = imageBytes;
    }

    public static PadesSignatureAppearance Invisible { get; } = new(
        false, 0, 0, 0, 0, 0, string.Empty, null, null);

    public static PadesSignatureAppearance Visible(
        int pageNumber,
        double lowerLeftX,
        double lowerLeftY,
        double upperRightX,
        double upperRightY,
        string text,
        DateTimeOffset? displayedAt = null,
        byte[]? imageBytes = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(pageNumber, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(lowerLeftX, upperRightX);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(lowerLeftY, upperRightY);
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        if (text.AsSpan().ContainsAny("()\\"))
        {
            throw new ArgumentException("Appearance text cannot contain PDF string delimiters.", nameof(text));
        }

        byte[]? copiedImage = imageBytes is null ? null : imageBytes.ToArray();
        if (copiedImage is { Length: > 0 } && !IsJpeg(copiedImage))
        {
            throw new ArgumentException("Optional appearance image must be JPEG.", nameof(imageBytes));
        }

        return new(
            true,
            pageNumber,
            lowerLeftX,
            lowerLeftY,
            upperRightX,
            upperRightY,
            text,
            displayedAt,
            copiedImage is { Length: > 0 } ? copiedImage : null);
    }

    public bool IsVisible { get; }
    public int PageNumber { get; }
    public double LowerLeftX { get; }
    public double LowerLeftY { get; }
    public double UpperRightX { get; }
    public double UpperRightY { get; }
    public string Text { get; }
    public DateTimeOffset? DisplayedAt { get; }
    public byte[]? ImageBytes { get; }

    public double Width => UpperRightX - LowerLeftX;
    public double Height => UpperRightY - LowerLeftY;

    private static bool IsJpeg(ReadOnlySpan<byte> image) =>
        image.Length >= 3 && image[0] == 0xFF && image[1] == 0xD8 && image[^2] == 0xFF && image[^1] == 0xD9;
}
