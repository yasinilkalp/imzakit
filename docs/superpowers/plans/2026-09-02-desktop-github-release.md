# Desktop GitHub Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `1.0.0-alpha.14` etiketinde Authenticode imzalı Desktop `setup.exe` ve NuGet’i aynı yayın hattında, imza yoksa hiçbirini basmadan üretmek.

**Architecture:** Ubuntu `verify-pack` yalnız test+nupkg artifact üretir. Windows `desktop` WinUI publish → WiX MSI + Burn `setup.exe` → signtool + `AuthenticodeGate`. `publish` her iki artifact yeşilse nuget.org, GitHub Packages ve `gh release create` çalıştırır.

**Tech Stack:** .NET 10, xUnit, WiX v4 (Windows job), signtool, GitHub Actions, mevcut `ImzaKit.Release` politikası.

**Spec:** `docs/superpowers/specs/2026-09-02-desktop-github-release-design.md`

## Global Constraints

- NuGet 16 DLL; Desktop `IsPackable=false`.
- Authenticode yoksa Desktop installer ve `publish` işi yok.
- Vendor `akisp11.dll` / `eTPKCS11.dll` harvest yok.
- `site/` içinde `.exe` yok; indirme `releases/latest`.
- Agent installer/host bu dilimde yok.
- İlk RID `win-x64`.
- Komutlar `--tl:off -m:1`.
- MSI `ProductVersion`: `1.0.0-alpha.N` → `1.0.N`.

---

### Task 1: WindowsInstallerVersion

**Files:**
- Create: `packaging/ImzaKit.Release/Installer/WindowsInstallerVersion.cs`
- Create: `tests/ImzaKit.Release.Tests/Installer/WindowsInstallerVersionTests.cs`

**Interfaces:**
- Produces: `WindowsInstallerVersion.FromSemVer(string version) -> string`

- [ ] **Step 1: Write the failing test**

```csharp
using ImzaKit.Release.Installer;

namespace ImzaKit.Release.Tests.Installer;

public sealed class WindowsInstallerVersionTests
{
    [Theory]
    [InlineData("1.0.0-alpha.14", "1.0.14")]
    [InlineData("1.0.0-alpha.13", "1.0.13")]
    [InlineData("1.0.0", "1.0.0")]
    [InlineData("2.0.0-beta.1", "2.0.1")]
    public void MapsSemVerToMajorMinorBuild(string semver, string expected)
    {
        Assert.Equal(expected, WindowsInstallerVersion.FromSemVer(version: semver));
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.0")]
    [InlineData("1.0.0-alpha")]
    [InlineData("1.0.0.1")]
    public void RejectsUnsupportedVersions(string version)
    {
        Assert.Throws<ArgumentException>(() => WindowsInstallerVersion.FromSemVer(version));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test tests/ImzaKit.Release.Tests/ImzaKit.Release.Tests.csproj -c Release --tl:off -m:1 --filter FullyQualifiedName~WindowsInstallerVersionTests`

Expected: FAIL (type not found)

- [ ] **Step 3: Write minimal implementation**

```csharp
using System.Globalization;
using System.Text.RegularExpressions;

namespace ImzaKit.Release.Installer;

public static class WindowsInstallerVersion
{
    private static readonly Regex SemVer = new(
        @"^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-(?<label>[A-Za-z]+)\.(?<prerelease>\d+))?$",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture);

    public static string FromSemVer(string version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        Match match = SemVer.Match(version);
        if (!match.Success)
        {
            throw new ArgumentException("Unsupported installer version.", nameof(version));
        }

        string major = match.Groups["major"].Value;
        string minor = match.Groups["minor"].Value;
        string build = match.Groups["prerelease"].Success
            ? match.Groups["prerelease"].Value
            : match.Groups["patch"].Value;
        return string.Create(CultureInfo.InvariantCulture, $"{major}.{minor}.{build}");
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: same filter. Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packaging/ImzaKit.Release/Installer/WindowsInstallerVersion.cs tests/ImzaKit.Release.Tests/Installer/WindowsInstallerVersionTests.cs
git commit -m "feat: map ImzaKit semver to Windows Installer ProductVersion."
```

---

### Task 2: Desktop MSI harvest and ProductVersion

**Files:**
- Modify: `packaging/ImzaKit.Release/Installer/AuthenticodeAndMsi.cs` (`DesktopMsiDocument.CreateWixSource`)
- Modify: `tests/ImzaKit.Release.Tests/Installer/DesktopInstallerAndUpdateTests.cs`

**Interfaces:**
- Consumes: `WindowsInstallerVersion.FromSemVer`
- Produces: `DesktopMsiDocument.CreateWixSource(DesktopInstallerPayload payload, string harvestDirectory) -> string`

- [ ] **Step 1: Write the failing test**

Replace `WixSourceExcludesVendorDllAndRequiresAuthenticode` body with:

```csharp
[Fact]
public void WixSourceExcludesVendorDllAndRequiresAuthenticode()
{
    DesktopInstallerPayload payload = DesktopInstallerLayout.Create("1.0.0-alpha.14", ["win-x64"]);
    string harvest = Path.Combine("artifacts", "desktop-publish");
    string wxs = DesktopMsiDocument.CreateWixSource(payload, harvest);

    Assert.Contains(@"ProgramFiles64Folder", wxs, StringComparison.Ordinal);
    Assert.Contains("Desktop", wxs, StringComparison.Ordinal);
    Assert.Contains("win-x64", wxs, StringComparison.Ordinal);
    Assert.Contains(@"Version=""1.0.14""", wxs, StringComparison.Ordinal);
    Assert.DoesNotContain("1.0.0.alpha", wxs, StringComparison.OrdinalIgnoreCase);
    Assert.DoesNotContain("akisp11", wxs, StringComparison.OrdinalIgnoreCase);
    Assert.DoesNotContain("etpkcs11.dll", wxs, StringComparison.OrdinalIgnoreCase);
    Assert.Contains("AuthenticodeRequired", wxs, StringComparison.Ordinal);
    Assert.Contains(@"SafeNet\Authentication\SAC\x64", wxs, StringComparison.Ordinal);
    Assert.Contains(Path.Combine(harvest, "ImzaKit.Hosts.Desktop.App.exe"), wxs, StringComparison.Ordinal);
}
```

Add:

```csharp
[Fact]
public void WixSourceRejectsEmptyHarvestDirectory()
{
    DesktopInstallerPayload payload = DesktopInstallerLayout.Create("1.0.0-alpha.14", ["win-x64"]);
    Assert.Throws<ArgumentException>(() => DesktopMsiDocument.CreateWixSource(payload, " "));
}
```

- [ ] **Step 2: Run focused tests**

Run: `dotnet test tests/ImzaKit.Release.Tests/ImzaKit.Release.Tests.csproj -c Release --tl:off -m:1 --filter FullyQualifiedName~DesktopInstallerAndUpdateTests`

Expected: FAIL (missing harvest parameter / still `1.0.0.alpha.14`)

- [ ] **Step 3: Implement**

Change `DesktopMsiDocument.CreateWixSource` to:

```csharp
public static string CreateWixSource(DesktopInstallerPayload payload, string harvestDirectory)
{
    ArgumentNullException.ThrowIfNull(payload);
    ArgumentException.ThrowIfNullOrWhiteSpace(harvestDirectory);
    string productVersion = WindowsInstallerVersion.FromSemVer(payload.Version);
    StringBuilder xml = new();
    xml.AppendLine(CultureInfo.InvariantCulture, $"""<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">""");
    xml.AppendLine(CultureInfo.InvariantCulture, $"""  <Package Name="ImzaKit Desktop {payload.Version}" Manufacturer="ImzaKit" Version="{productVersion}" Scope="perMachine">""");
    xml.AppendLine("""    <StandardDirectory Id="ProgramFiles64Folder">""");
    xml.AppendLine("""      <Directory Name="ImzaKit"><Directory Name="Desktop" Id="INSTALLFOLDER">""");
    foreach (string file in payload.Files)
    {
        string source = Path.Combine(harvestDirectory, file);
        xml.AppendLine(CultureInfo.InvariantCulture, $"""        <File Source="{source}" />""");
    }

    xml.AppendLine("""      </Directory></Directory>""");
    xml.AppendLine("""    </StandardDirectory>""");
    xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="AuthenticodeRequired" Value="{payload.AuthenticodeRequired}" />""");
    xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="RuntimeIdentifiers" Value="{string.Join(';', payload.RuntimeIdentifiers)}" />""");
    xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="Pkcs11AllowlistRoots" Value="{string.Join(';', payload.Pkcs11AllowlistRoots)}" />""");
    xml.AppendLine(CultureInfo.InvariantCulture, $"""    <Property Id="EtokenPkcs11AllowlistRoots" Value="{string.Join(';', payload.EtokenPkcs11AllowlistRoots)}" />""");
    xml.AppendLine("""  </Package>""");
    xml.AppendLine("</Wix>");
    return xml.ToString();
}
```

Keep `using System.Globalization;` and `using System.Text;` already in the file. Add nothing that harvests `akisp11`.

- [ ] **Step 4: Re-run tests**

Expected: PASS (also full `ImzaKit.Release.Tests`)

- [ ] **Step 5: Commit**

```bash
git add packaging/ImzaKit.Release/Installer/AuthenticodeAndMsi.cs tests/ImzaKit.Release.Tests/Installer/DesktopInstallerAndUpdateTests.cs
git commit -m "feat: harvest Desktop MSI files and emit numeric ProductVersion."
```

---

### Task 3: Desktop Burn setup.exe source

**Files:**
- Create: `packaging/ImzaKit.Release/Installer/DesktopBurnDocument.cs`
- Modify: `tests/ImzaKit.Release.Tests/Installer/DesktopInstallerAndUpdateTests.cs`

**Interfaces:**
- Produces: `DesktopBurnDocument.CreateWixSource(string version, string msiFileName) -> string`
- Produces: `DesktopBurnDocument.SetupExeFileName = "ImzaKit.Desktop-win-x64.setup.exe"`
- UpgradeCode (sabit): `{B7E4C1A2-8F93-4D6E-9B10-2C5A7E8D4F31}`

- [ ] **Step 1: Write the failing test**

```csharp
[Fact]
public void BurnBundleWrapsMsiAsWinX64SetupExe()
{
    string wxs = DesktopBurnDocument.CreateWixSource("1.0.0-alpha.14", "ImzaKit.Desktop.msi");
    Assert.Equal("ImzaKit.Desktop-win-x64.setup.exe", DesktopBurnDocument.SetupExeFileName);
    Assert.Contains(@"Version=""1.0.14""", wxs, StringComparison.Ordinal);
    Assert.Contains("ImzaKit Desktop 1.0.0-alpha.14", wxs, StringComparison.Ordinal);
    Assert.Contains("ImzaKit.Desktop.msi", wxs, StringComparison.Ordinal);
    Assert.Contains("B7E4C1A2-8F93-4D6E-9B10-2C5A7E8D4F31", wxs, StringComparison.Ordinal);
    Assert.DoesNotContain("akisp11", wxs, StringComparison.OrdinalIgnoreCase);
}
```

- [ ] **Step 2: Run test**

Expected: FAIL (type not found)

- [ ] **Step 3: Implement**

```csharp
using System.Globalization;

namespace ImzaKit.Release.Installer;

public static class DesktopBurnDocument
{
    public const string SetupExeFileName = "ImzaKit.Desktop-win-x64.setup.exe";
    public const string UpgradeCode = "B7E4C1A2-8F93-4D6E-9B10-2C5A7E8D4F31";

    public static string CreateWixSource(string version, string msiFileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(msiFileName);
        string productVersion = WindowsInstallerVersion.FromSemVer(version);
        return string.Create(
            CultureInfo.InvariantCulture,
            $"""
            <Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
              <Bundle Name="ImzaKit Desktop {version}" Manufacturer="ImzaKit" Version="{productVersion}" UpgradeCode="{UpgradeCode}">
                <BootstrapperApplication>
                  <bal:WixStandardBootstrapperApplication Theme="hyperlinkLicense" />
                </BootstrapperApplication>
                <Chain>
                  <MsiPackage SourceFile="{msiFileName}" />
                </Chain>
              </Bundle>
            </Wix>
            """);
    }
}
```

- [ ] **Step 4: Run DesktopInstallerAndUpdateTests**

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packaging/ImzaKit.Release/Installer/DesktopBurnDocument.cs tests/ImzaKit.Release.Tests/Installer/DesktopInstallerAndUpdateTests.cs
git commit -m "feat: emit WiX Burn source for Desktop setup.exe."
```

---

### Task 4: emit-release-bundle `--kind desktop`

**Files:**
- Modify: `scripts/emit-release-bundle.cs` (`ParseKind`)
- Modify: `tests/ImzaKit.Release.Tests/Signing/ReleaseSigningPolicyTests.cs` only if a new assertion is needed (existing Desktop test already covers policy). Add a script-level check via a tiny helper test file is optional; prefer running the file.

**Interfaces:**
- Produces: `ParseKind("desktop") -> ReleaseArtifactKind.DesktopPeOrInstaller`

- [ ] **Step 1: Write a failing kind parser test**

Create `packaging/ImzaKit.Release/Signing/ReleaseArtifactKindParser.cs` so the script and tests share the map (do not duplicate switch in the script).

Test `tests/ImzaKit.Release.Tests/Signing/ReleaseArtifactKindParserTests.cs`:

```csharp
using ImzaKit.Release.Signing;

namespace ImzaKit.Release.Tests.Signing;

public sealed class ReleaseArtifactKindParserTests
{
    [Theory]
    [InlineData(null, ReleaseArtifactKind.NugetPackage)]
    [InlineData("nuget", ReleaseArtifactKind.NugetPackage)]
    [InlineData("agent", ReleaseArtifactKind.AgentPeOrInstaller)]
    [InlineData("desktop", ReleaseArtifactKind.DesktopPeOrInstaller)]
    [InlineData("manifest", ReleaseArtifactKind.UpdateManifest)]
    public void ParsesKnownKinds(string? value, ReleaseArtifactKind expected)
    {
        Assert.Equal(expected, ReleaseArtifactKindParser.Parse(value));
    }

    [Fact]
    public void RejectsUnknownKind()
    {
        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => ReleaseArtifactKindParser.Parse("msi"));
        Assert.Contains("Unknown --kind", ex.Message, StringComparison.Ordinal);
    }
}
```

- [ ] **Step 2: Run parser tests**

Expected: FAIL

- [ ] **Step 3: Implement parser and switch the script**

```csharp
namespace ImzaKit.Release.Signing;

public static class ReleaseArtifactKindParser
{
    public static ReleaseArtifactKind Parse(string? value) => value switch
    {
        null or "nuget" => ReleaseArtifactKind.NugetPackage,
        "agent" => ReleaseArtifactKind.AgentPeOrInstaller,
        "desktop" => ReleaseArtifactKind.DesktopPeOrInstaller,
        "manifest" => ReleaseArtifactKind.UpdateManifest,
        _ => throw new InvalidOperationException("Unknown --kind: " + value)
    };
}
```

In `scripts/emit-release-bundle.cs` replace `ParseKind` with `ReleaseArtifactKindParser.Parse`.

- [ ] **Step 4: Run Release tests + `--compile-check`**

Run: `dotnet test tests/ImzaKit.Release.Tests/ImzaKit.Release.Tests.csproj -c Release --tl:off -m:1`

Run: `dotnet run --file scripts/emit-release-bundle.cs -- --compile-check`

Expected: PASS / `RELEASE_BUNDLE_COMPILE_OK`

- [ ] **Step 5: Commit**

```bash
git add packaging/ImzaKit.Release/Signing/ReleaseArtifactKindParser.cs tests/ImzaKit.Release.Tests/Signing/ReleaseArtifactKindParserTests.cs scripts/emit-release-bundle.cs
git commit -m "feat: accept desktop artifact kind in the release bundle emitter."
```

---

### Task 5: emit-desktop-installer script

**Files:**
- Create: `scripts/emit-desktop-installer.cs`
- Create: `tests/ImzaKit.Release.Tests/Installer/DesktopInstallerEmitterContractTests.cs` — assert the script file contains required flags if a C# host is too heavy; prefer invoking `--compile-check`.

**Interfaces:**
- CLI: `--version` `--publish-dir` `--output-dir`
- Writes `{output}/desktop.wxs` and `{output}/desktop-bundle.wxs`
- `--compile-check` prints `DESKTOP_INSTALLER_COMPILE_OK`

- [ ] **Step 1: Add a contract test that the script exists and compile-check is documented** — implement the script with `--compile-check` first via failing `dotnet run`.

Run (before file exists): `dotnet run --file scripts/emit-desktop-installer.cs -- --compile-check`

Expected: FAIL (file missing)

- [ ] **Step 2: Implement `scripts/emit-desktop-installer.cs`**

```csharp
#:project ../packaging/ImzaKit.Release/ImzaKit.Release.csproj

using ImzaKit.Release.Installer;

if (args.Contains("--compile-check", StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine("DESKTOP_INSTALLER_COMPILE_OK");
    return 0;
}

string? version = ReadOption(args, "--version");
string? publishDir = ReadOption(args, "--publish-dir");
string? outputDir = ReadOption(args, "--output-dir");
if (string.IsNullOrWhiteSpace(version) ||
    string.IsNullOrWhiteSpace(publishDir) ||
    string.IsNullOrWhiteSpace(outputDir))
{
    Console.Error.WriteLine("Usage: --version <semver> --publish-dir <dir> --output-dir <dir>");
    return 2;
}

DesktopInstallerPayload payload = DesktopInstallerLayout.Create(version, ["win-x64"]);
foreach (string file in payload.Files)
{
    if (file.Contains("akisp11", StringComparison.OrdinalIgnoreCase) ||
        file.Contains("etpkcs11", StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine("IMZAKIT.RELEASE.VENDOR_PKCS11_FORBIDDEN");
        return 1;
    }
}

Directory.CreateDirectory(outputDir);
string msiWxs = DesktopMsiDocument.CreateWixSource(payload, publishDir);
string bundleWxs = DesktopBurnDocument.CreateWixSource(version, "ImzaKit.Desktop.msi");
File.WriteAllText(Path.Combine(outputDir, "desktop.wxs"), msiWxs);
File.WriteAllText(Path.Combine(outputDir, "desktop-bundle.wxs"), bundleWxs);
Console.WriteLine("DESKTOP_INSTALLER_WXS_OK " + DesktopBurnDocument.SetupExeFileName);
return 0;

static string? ReadOption(string[] arguments, string name)
{
    int index = Array.FindIndex(arguments, argument => string.Equals(argument, name, StringComparison.Ordinal));
    return index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}
```

- [ ] **Step 3: Run compile-check and a temp-dir emit**

```powershell
dotnet run --file scripts/emit-desktop-installer.cs -- --compile-check
New-Item -ItemType Directory -Force artifacts/desktop-wxs, artifacts/desktop-publish | Out-Null
dotnet run --file scripts/emit-desktop-installer.cs -- --version 1.0.0-alpha.14 --publish-dir artifacts/desktop-publish --output-dir artifacts/desktop-wxs
```

Expected: `DESKTOP_INSTALLER_COMPILE_OK`; `desktop.wxs` contains `Version="1.0.14"`; `desktop-bundle.wxs` contains setup name via later workflow `-o`.

- [ ] **Step 4: Commit**

```bash
git add scripts/emit-desktop-installer.cs
git commit -m "feat: emit Desktop WiX sources from the installer layout."
```

---

### Task 6: Three-job publish workflow

**Files:**
- Modify: `.github/workflows/publish.yml`
- Modify: `scripts/verify-publish-workflow.ps1`
- Modify: `scripts/verify-nuget-package.ps1` default `$Version` after Task 7 or here to `1.0.0-alpha.14` only if props already bumped; otherwise keep version as workflow env and pass `-Version`.

**Interfaces:**
- Jobs: `verify-pack` (ubuntu-latest), `desktop` (windows-latest, needs verify-pack), `publish` (ubuntu-latest, needs [verify-pack, desktop])
- Env `IMZAKIT_VERSION` from tag (`v` stripped) or fail
- `contents: write` only on `publish`
- Desktop job uses `IMZAKIT_AUTHENTICODE_PFX` and `IMZAKIT_AUTHENTICODE_PFX_PASSWORD`
- `gh release create` attaches `ImzaKit.Desktop-win-x64.setup.exe`

- [ ] **Step 1: Expand `verify-publish-workflow.ps1` first (RED)**

Replace hardcoded `alpha.13` requirement with:

```powershell
$requiredPatterns = [ordered]@{
    'tag trigger' = '(?m)^\s+tags:\s*\r?$'
    'manual trigger' = '(?m)^\s+workflow_dispatch:\s*\r?$'
    'version from tag' = 'IMZAKIT_VERSION'
    'Release build' = 'dotnet build ImzaKit\.slnx -c Release'
    'test suite' = 'dotnet test ImzaKit\.slnx -c Release --no-build'
    'single package build' = 'dotnet pack packaging/ImzaKit/ImzaKit\.csproj -c Release --no-build --output artifacts/packages'
    'release bundle emit' = 'scripts/emit-release-bundle\.cs'
    'desktop installer emit' = 'scripts/emit-desktop-installer\.cs'
    'desktop kind' = '--kind desktop'
    'sbom artifact' = 'artifacts/packages/sbom\.cdx\.json'
    'provenance key env' = 'IMZAKIT_RELEASE_ECDSA_KEY'
    'authenticode pfx secret' = 'secrets\.IMZAKIT_AUTHENTICODE_PFX'
    'authenticode password secret' = 'secrets\.IMZAKIT_AUTHENTICODE_PFX_PASSWORD'
    'windows desktop job' = 'windows-latest'
    'setup exe name' = 'ImzaKit\.Desktop-win-x64\.setup\.exe'
    'gh release' = 'gh release create'
    'package contract' = 'scripts/verify-nuget-package\.ps1'
    'OIDC permission' = '(?m)^\s+id-token:\s*write\s*$'
    'packages write permission' = '(?m)^\s+packages:\s+write\s*$'
    'contents write on publish' = '(?m)^\s+contents:\s+write\s*$'
    'NuGet OIDC login' = 'uses:\s*NuGet/login@v1'
    'NuGet profile' = '(?m)^\s+user:\s*Kodekibi\s*$'
    'temporary API key output' = 'steps\.login\.outputs\.NUGET_API_KEY'
    'GitHub Packages token' = 'secrets\.GITHUB_TOKEN'
    'GitHub Packages source' = 'nuget\.pkg\.github\.com'
    'package path from version' = 'ImzaKit\.\$\{\{ env\.IMZAKIT_VERSION \}\}\.nupkg'
    'NuGet.org source' = 'https://api\.nuget\.org/v3/index\.json'
    'needs desktop' = 'needs:\s*\[verify-pack, desktop\]'
}
```

Keep forbidden: `secrets.NUGET_API_KEY`, `--skip-duplicate`, literal API keys.

Add:

```powershell
if ($workflow -match 'ImzaKit\.1\.0\.0-alpha\.13\.nupkg') {
    throw 'Publish workflow must not hardcode 1.0.0-alpha.13 package paths.'
}
```

Run: `pwsh -NoProfile -File scripts/verify-publish-workflow.ps1`

Expected: FAIL (missing jobs/secrets)

- [ ] **Step 2: Rewrite `.github/workflows/publish.yml`**

```yaml
name: Publish NuGet package

on:
  push:
    tags:
      - "v*"
  workflow_dispatch:
    inputs:
      publish_nuget_org:
        description: Publish to NuGet.org
        type: boolean
        default: true

concurrency:
  group: nuget-publish
  cancel-in-progress: false

jobs:
  verify-pack:
    name: Verify and pack
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    outputs:
      version: ${{ steps.version.outputs.version }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          global-json-file: global.json
      - id: version
        shell: bash
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          PROPS=$(python -c "import pathlib,re; t=pathlib.Path('Directory.Build.props').read_text(); print(re.search(r'<Version>([^<]+)</Version>', t).group(1))")
          if [ "$VERSION" != "$PROPS" ]; then
            echo "Version mismatch tag=$VERSION props=$PROPS" >&2
            exit 1
          fi
          echo "version=$VERSION" >> "$GITHUB_OUTPUT"
          echo "IMZAKIT_VERSION=$VERSION" >> "$GITHUB_ENV"
      - run: dotnet build ImzaKit.slnx -c Release
      - run: dotnet test ImzaKit.slnx -c Release --no-build
      - run: dotnet pack packaging/ImzaKit/ImzaKit.csproj -c Release --no-build --output artifacts/packages
      - env:
          IMZAKIT_RELEASE_ECDSA_KEY: ${{ secrets.IMZAKIT_RELEASE_ECDSA_KEY }}
        run: >
          dotnet run --file scripts/emit-release-bundle.cs --
          --package artifacts/packages/ImzaKit.${{ steps.version.outputs.version }}.nupkg
          --output artifacts/packages
          --version ${{ steps.version.outputs.version }}
          --commit "${{ github.sha }}"
          --kind nuget
      - shell: pwsh
        run: ./scripts/verify-nuget-package.ps1 -Version ${{ steps.version.outputs.version }}
      - uses: actions/upload-artifact@v4
        with:
          name: packages
          path: artifacts/packages

  desktop:
    name: Sign Desktop installer
    needs: verify-pack
    runs-on: windows-latest
    timeout-minutes: 40
    permissions:
      contents: read
    env:
      IMZAKIT_VERSION: ${{ needs.verify-pack.outputs.version }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          global-json-file: global.json
      - name: Publish Desktop host
        run: >
          dotnet publish src/ImzaKit.Hosts.Desktop.App/ImzaKit.Hosts.Desktop.App.csproj
          -c Release -r win-x64 --self-contained true
          -o artifacts/desktop-publish
      - name: Copy license files into harvest
        shell: pwsh
        run: |
          Copy-Item LICENSE,NOTICE artifacts/desktop-publish
          if (-not (Test-Path artifacts/desktop-publish/sbom.cdx.json)) {
            Set-Content artifacts/desktop-publish/sbom.cdx.json '{}'
          }
          if (-not (Test-Path artifacts/desktop-publish/provenance.json)) {
            Set-Content artifacts/desktop-publish/provenance.json '{}'
          }
      - name: Emit WiX sources
        run: >
          dotnet run --file scripts/emit-desktop-installer.cs --
          --version ${{ env.IMZAKIT_VERSION }}
          --publish-dir artifacts/desktop-publish
          --output-dir artifacts/desktop-wxs
      - name: Install WiX
        run: dotnet tool install --global wix --version 5.0.2
      - name: Build MSI and setup.exe
        shell: pwsh
        run: |
          wix build artifacts/desktop-wxs/desktop.wxs -o artifacts/desktop/ImzaKit.Desktop.msi
          wix build artifacts/desktop-wxs/desktop-bundle.wxs -o artifacts/desktop/ImzaKit.Desktop-win-x64.setup.exe
      - name: Import certificate and sign
        shell: pwsh
        env:
          IMZAKIT_AUTHENTICODE_PFX: ${{ secrets.IMZAKIT_AUTHENTICODE_PFX }}
          IMZAKIT_AUTHENTICODE_PFX_PASSWORD: ${{ secrets.IMZAKIT_AUTHENTICODE_PFX_PASSWORD }}
        run: |
          if ([string]::IsNullOrWhiteSpace($env:IMZAKIT_AUTHENTICODE_PFX) -or [string]::IsNullOrWhiteSpace($env:IMZAKIT_AUTHENTICODE_PFX_PASSWORD)) {
            throw 'IMZAKIT.RELEASE.AUTHENTICODE_CERTIFICATE_MISSING'
          }
          $pfx = Join-Path $env:RUNNER_TEMP 'imzakit.pfx'
          [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:IMZAKIT_AUTHENTICODE_PFX))
          try {
            $files = @(
              'artifacts/desktop-publish/ImzaKit.Hosts.Desktop.App.exe',
              'artifacts/desktop/ImzaKit.Desktop-win-x64.setup.exe'
            )
            foreach ($file in $files) {
              & signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f $pfx /p $env:IMZAKIT_AUTHENTICODE_PFX_PASSWORD $file
              if ($LASTEXITCODE -ne 0) { throw "signtool failed for $file" }
            }
          }
          finally {
            if (Test-Path $pfx) { Remove-Item $pfx -Force }
          }
      - name: Authenticode gate
        env:
          IMZAKIT_AUTHENTICODE_PFX: ${{ secrets.IMZAKIT_AUTHENTICODE_PFX }}
        run: >
          dotnet run --file scripts/emit-release-bundle.cs --
          --package artifacts/desktop/ImzaKit.Desktop-win-x64.setup.exe
          --output artifacts/desktop
          --version ${{ env.IMZAKIT_VERSION }}
          --commit "${{ github.sha }}"
          --kind desktop
          --product ImzaKit.Desktop
      - uses: actions/upload-artifact@v4
        with:
          name: desktop-installer
          path: |
            artifacts/desktop/ImzaKit.Desktop-win-x64.setup.exe
            artifacts/desktop/sbom.cdx.json

  publish:
    name: Publish NuGet and GitHub Release
    needs: [verify-pack, desktop]
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: write
      id-token: write
      packages: write
    env:
      IMZAKIT_VERSION: ${{ needs.verify-pack.outputs.version }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          global-json-file: global.json
      - uses: actions/download-artifact@v4
        with:
          name: packages
          path: artifacts/packages
      - uses: actions/download-artifact@v4
        with:
          name: desktop-installer
          path: artifacts/desktop
      - name: Publish to GitHub Packages
        shell: bash
        run: |
          dotnet nuget push artifacts/packages/ImzaKit.${{ env.IMZAKIT_VERSION }}.nupkg \
            --api-key "${{ secrets.GITHUB_TOKEN }}" \
            --source "https://nuget.pkg.github.com/${{ github.repository_owner }}/index.json"
      - name: Sign in to NuGet.org with OIDC
        if: github.event_name == 'push' || inputs.publish_nuget_org
        uses: NuGet/login@v1
        id: login
        with:
          user: Kodekibi
      - name: Publish to NuGet.org
        if: github.event_name == 'push' || inputs.publish_nuget_org
        shell: bash
        run: |
          dotnet nuget push artifacts/packages/ImzaKit.${{ env.IMZAKIT_VERSION }}.nupkg \
            --api-key "${{ steps.login.outputs.NUGET_API_KEY }}" \
            --source https://api.nuget.org/v3/index.json \
            --symbol-source https://api.nuget.org/v3/index.json
      - name: Create GitHub Release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release create "v${{ env.IMZAKIT_VERSION }}" \
            artifacts/desktop/ImzaKit.Desktop-win-x64.setup.exe \
            artifacts/desktop/sbom.cdx.json \
            --title "ImzaKit ${{ env.IMZAKIT_VERSION }}" \
            --notes "Ön sürüm. Authenticode imzalı Desktop setup.exe. Fiziksel AKİS kabulü iddia edilmez. NuGet paketi Desktop host içermez."
```

Fix NuGet.org step: `id: login` must be referenced from the same job; keep as in current file. Add `id: login` on the login step (already there).

`workflow_dispatch` `inputs.publish_nuget_org` on the publish job: use `github.event.inputs.publish_nuget_org`.

If `python` is too heavy on ubuntu, parse Version with `pwsh` instead of python in verify-pack:

```bash
VERSION="${GITHUB_REF_NAME#v}"
PROPS=$(grep -oP '(?<=<Version>)[^<]+' Directory.Build.props | head -1)
```

Use grep -P or pwsh for portability.

- [ ] **Step 3: Run verify-publish-workflow.ps1**

Expected: PASS. Also confirm workflow has no `1.0.0-alpha.13` path.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/publish.yml scripts/verify-publish-workflow.ps1
git commit -m "ci: publish signed Desktop setup.exe and NuGet from the same tag."
```

---

### Task 7: Bump product version to 1.0.0-alpha.14

**Files:**
- Modify: `Directory.Build.props`
- Modify: `README.md`, `SECURITY.md`, `site/index.html`
- Modify: `docs/imzakit-teknik-kullanim-rehberi.html`
- Modify: `scripts/verify-landing-page.ps1`, `scripts/verify-technical-guide.ps1`, `scripts/verify-open-source-readiness.ps1`, `scripts/verify-nuget-package.ps1` (default Version)
- Modify: `frd/ekler/gereksinim-izlenebilirlik-matrisi.md` (Desktop “henüz uygulanmadı” dipnotunu “host uygulandı; GitHub Release alpha.14” yap)
- Modify: `reports/imzakit-gelistirme-durum.html` (sürüm ve sonraki iş: Authenticode secret + tag)

Do not change installer unit tests that already pass `1.0.0-alpha.14` from Task 2.

- [ ] **Step 1: Replace `1.0.0-alpha.13` with `1.0.0-alpha.14` in the files above** where it names the current shipping version.

- [ ] **Step 2: Run**

```powershell
pwsh -NoProfile -File scripts/verify-landing-page.ps1
pwsh -NoProfile -File scripts/verify-technical-guide.ps1
pwsh -NoProfile -File scripts/verify-open-source-readiness.ps1
pwsh -NoProfile -File scripts/verify-publish-workflow.ps1
pwsh -NoProfile -File scripts/validate-frd.ps1
dotnet test tests/ImzaKit.Release.Tests/ImzaKit.Release.Tests.csproj -c Release --tl:off -m:1
```

Expected: all passed

- [ ] **Step 3: Commit**

```bash
git add Directory.Build.props README.md SECURITY.md site/index.html docs/imzakit-teknik-kullanim-rehberi.html scripts/verify-landing-page.ps1 scripts/verify-technical-guide.ps1 scripts/verify-open-source-readiness.ps1 scripts/verify-nuget-package.ps1 frd/ekler/gereksinim-izlenebilirlik-matrisi.md reports/imzakit-gelistirme-durum.html
git commit -m "chore: ship version contract 1.0.0-alpha.14."
```

---

## Self-review

- Spec: üç iş, fail-closed Authenticode, win-x64 Burn `setup.exe`, alpha.14, Agent yok — Task 1–7 karşılar.
- Placeholder yok.
- `CreateWixSource` imzası Task 2’de harvest parametresi alır; Task 5 aynı imzayı kullanır.
- `ReleaseArtifactKindParser.Parse` Task 4 üretir; script onu tüketir.

## Operatör (kod dışı)

`v1.0.0-alpha.14` basmadan önce GitHub secret: `IMZAKIT_AUTHENTICODE_PFX` (base64 PFX), `IMZAKIT_AUTHENTICODE_PFX_PASSWORD`. Secret yoksa `desktop` kırmızı kalır; bu beklenen fail-closed davranıştır.
