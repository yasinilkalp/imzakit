using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace ImzaKit.Release.Installer;

public static class AuthenticodePeSignature
{
    public static bool HasEmbeddedSignature(ReadOnlySpan<byte> peImage)
    {
        if (peImage.Length < 0x40 || peImage[0] != (byte)'M' || peImage[1] != (byte)'Z')
        {
            return false;
        }

        int lfanew = BinaryPrimitives.ReadInt32LittleEndian(peImage[0x3C..]);
        if (lfanew < 0 || peImage.Length < lfanew + 24 + 2)
        {
            return false;
        }

        if (peImage[lfanew] != (byte)'P' || peImage[lfanew + 1] != (byte)'E')
        {
            return false;
        }

        int optionalHeader = lfanew + 24;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(peImage[optionalHeader..]);
        int directoryOffset = magic switch
        {
            0x10B => optionalHeader + 96,
            0x20B => optionalHeader + 112,
            _ => -1
        };
        int security = directoryOffset + (4 * 8);
        if (directoryOffset < 0 || peImage.Length < security + 8)
        {
            return false;
        }

        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(peImage[security..]);
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(peImage[(security + 4)..]);
        return rva != 0 && size != 0;
    }
}

public static class AuthenticodeGate
{
    public static void Require(ReadOnlySpan<byte> peImage, bool required)
    {
        if (required && !AuthenticodePeSignature.HasEmbeddedSignature(peImage))
        {
            throw new InvalidOperationException("IMZAKIT.RELEASE.AUTHENTICODE_REQUIRED");
        }
    }

    public static void RequireFile(string path, bool required) =>
        Require(File.ReadAllBytes(path), required);
}

public static class AgentMsiDocument
{
    public static string CreateWixSource(AgentInstallerPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        StringBuilder xml = new();
        xml.AppendLine(CultureInfo.InvariantCulture, $"""<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">""");
        xml.AppendLine(CultureInfo.InvariantCulture, $"""  <Package Name="ImzaKit Agent {payload.Version}" Manufacturer="ImzaKit" Version="{payload.Version.Replace("-", ".", StringComparison.Ordinal)}" Scope="perMachine">""");
        xml.AppendLine("""    <StandardDirectory Id="ProgramFiles64Folder">""");
        xml.AppendLine("""      <Directory Name="ImzaKit"><Directory Name="Agent" Id="INSTALLFOLDER">""");
        foreach (string file in payload.Files)
        {
            xml.AppendLine(CultureInfo.InvariantCulture, $"""        <File Source="{file}" />""");
        }

        xml.AppendLine("""      </Directory></Directory>""");
        xml.AppendLine("""    </StandardDirectory>""");
        xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="AuthenticodeRequired" Value="{payload.AuthenticodeRequired}" />""");
        xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="LoopbackBind" Value="{string.Join(';', payload.LoopbackBindAddresses)}" />""");
        xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="RuntimeIdentifiers" Value="{string.Join(';', payload.RuntimeIdentifiers)}" />""");
        xml.AppendLine("""  </Package>""");
        xml.AppendLine("</Wix>");
        return xml.ToString();
    }
}
