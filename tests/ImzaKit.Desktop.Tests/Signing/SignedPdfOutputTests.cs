using ImzaKit.Hosts.Desktop.Signing;

namespace ImzaKit.Desktop.Tests.Signing;

public sealed class SignedPdfOutputTests
{
    [Fact]
    public void WriteUsesImzaliSuffixNextToOriginal()
    {
        string directory = CreateTempDirectory();
        string original = Path.Combine(directory, "sozlesme.pdf");
        File.WriteAllBytes(original, [1, 2, 3]);

        string written = SignedPdfOutput.Write(original, [9, 9]);

        Assert.Equal(Path.Combine(directory, "sozlesme-imzali.pdf"), written);
        Assert.Equal([9, 9], File.ReadAllBytes(written));
        Assert.Equal([1, 2, 3], File.ReadAllBytes(original));
    }

    [Fact]
    public void WriteIncrementsSuffixWhenTargetExists()
    {
        string directory = CreateTempDirectory();
        string original = Path.Combine(directory, "belge.pdf");
        File.WriteAllBytes(original, [1]);
        File.WriteAllBytes(Path.Combine(directory, "belge-imzali.pdf"), [2]);

        string written = SignedPdfOutput.Write(original, [3]);

        Assert.Equal(Path.Combine(directory, "belge-imzali-2.pdf"), written);
        Assert.Equal([3], File.ReadAllBytes(written));
        Assert.Equal([2], File.ReadAllBytes(Path.Combine(directory, "belge-imzali.pdf")));
    }

    [Fact]
    public void WriteDoesNotLeavePartialFileWhenDirectoryIsMissing()
    {
        string missingDirectory = Path.Combine(Path.GetTempPath(), "imzakit-missing-" + Guid.NewGuid().ToString("N"));
        string original = Path.Combine(missingDirectory, "yok.pdf");

        Assert.ThrowsAny<IOException>(() => SignedPdfOutput.Write(original, [1, 2, 3]));
        Assert.False(Directory.Exists(missingDirectory));
    }

    private static string CreateTempDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(), "imzakit-desktop-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
