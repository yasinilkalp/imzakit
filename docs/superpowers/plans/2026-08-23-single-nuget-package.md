# Single NuGet Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce and publish one `ImzaKit` `1.0.0-alpha.1` NuGet package containing all nine production module assemblies and matching portable symbols.

**Architecture:** Keep the nine source projects and eight test projects unchanged as modular build boundaries, but mark the source projects non-packable. Add one packaging-only project that gathers project-reference DLL/PDB outputs through NuGet’s supported MSBuild extension points and declares only the three external runtime dependencies.

**Tech Stack:** .NET SDK 10.0.400, MSBuild/NuGet pack targets, PowerShell, NuGet.org

**Spec:** `docs/superpowers/specs/2026-08-23-single-nuget-package-design.md`

## Global Constraints

- Publish exactly one package ID: `ImzaKit`.
- Package version is exactly `1.0.0-alpha.1`.
- Target framework is exactly `net10.0`.
- License expression is exactly `Apache-2.0`.
- Repository URL is exactly `https://github.com/yasinilkalp/imzakit`.
- The main package contains exactly the nine existing `ImzaKit.*.dll` module assemblies and no packaging assembly.
- The symbol package contains exactly the nine matching portable `ImzaKit.*.pdb` files.
- Package dependencies are exactly `BouncyCastle.Cryptography` `2.7.0`, `Microsoft.Extensions.DependencyInjection.Abstractions` `10.0.11`, and `System.Security.Cryptography.Pkcs` `10.0.11`.
- No `ImzaKit.*` package dependency may appear in the nuspec.
- Never persist or print `NUGET_API_KEY`.
- Keep physical AKİS, native approval, mTLS, trust/revocation, and installer acceptance outside this change.

---

### Task 1: Add a failing single-package archive validator

**Files:**
- Create: `scripts/verify-nuget-package.ps1`

**Interfaces:**
- Consumes: `-PackageDirectory` and optional `-Version`, defaulting to `artifacts/packages` and `1.0.0-alpha.1`.
- Produces: exit code `0` plus `NuGet package verification passed: ImzaKit <version>` only when the package and symbol archives match the specification; otherwise throws and exits non-zero.

- [ ] **Step 1: Create the package validator**

Create `scripts/verify-nuget-package.ps1` with these checks:

```powershell
param(
    [string]$PackageDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\packages'),
    [string]$Version = '1.0.0-alpha.1'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$expectedModules = @(
    'ImzaKit.Agent', 'ImzaKit.Api', 'ImzaKit.Cms', 'ImzaKit.Core',
    'ImzaKit.Cryptography', 'ImzaKit.DependencyInjection', 'ImzaKit.PAdES',
    'ImzaKit.Pkcs11', 'ImzaKit.Verify'
)
$expectedDependencies = [ordered]@{
    'BouncyCastle.Cryptography' = '2.7.0'
    'Microsoft.Extensions.DependencyInjection.Abstractions' = '10.0.11'
    'System.Security.Cryptography.Pkcs' = '10.0.11'
}

$packages = @(Get-ChildItem -LiteralPath $PackageDirectory -Filter '*.nupkg' |
    Where-Object { $_.Extension -eq '.nupkg' })
$symbols = @(Get-ChildItem -LiteralPath $PackageDirectory -Filter '*.snupkg')
if ($packages.Count -ne 1) { throw "Expected one nupkg, found $($packages.Count)." }
if ($symbols.Count -ne 1) { throw "Expected one snupkg, found $($symbols.Count)." }

function Read-Nuspec([System.IO.Compression.ZipArchive]$archive) {
    $entry = $archive.Entries | Where-Object FullName -Like '*.nuspec' | Select-Object -First 1
    if (-not $entry) { throw 'Package nuspec is missing.' }
    $reader = [System.IO.StreamReader]::new($entry.Open())
    try { return [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
}

$packageArchive = [System.IO.Compression.ZipFile]::OpenRead($packages[0].FullName)
try {
    $nuspec = Read-Nuspec $packageArchive
    $metadata = $nuspec.package.metadata
    if ($metadata.id -ne 'ImzaKit') { throw "Unexpected package ID: $($metadata.id)" }
    if ($metadata.version -ne $Version) { throw "Unexpected version: $($metadata.version)" }
    if ($metadata.license.'#text' -ne 'Apache-2.0') { throw 'Apache-2.0 license is missing.' }
    if ($metadata.repository.url -ne 'https://github.com/yasinilkalp/imzakit') { throw 'Repository URL is invalid.' }
    if ($metadata.readme -ne 'README.md' -or -not ($packageArchive.Entries.FullName -contains 'README.md')) { throw 'README is missing.' }

    $actualDlls = @($packageArchive.Entries.FullName |
        Where-Object { $_ -like 'lib/net10.0/ImzaKit.*.dll' } |
        ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) } |
        Sort-Object -Unique)
    $expectedDlls = @($expectedModules | Sort-Object)
    if (Compare-Object $expectedDlls $actualDlls) { throw "Module DLL set is invalid: $($actualDlls -join ', ')" }

    $dependencies = @($metadata.dependencies.group.dependency)
    if ($dependencies | Where-Object { $_.id -like 'ImzaKit.*' }) { throw 'Internal ImzaKit package dependency found.' }
    foreach ($pair in $expectedDependencies.GetEnumerator()) {
        $dependency = $dependencies | Where-Object id -EQ $pair.Key
        if (@($dependency).Count -ne 1 -or $dependency.version -ne $pair.Value) {
            throw "Dependency mismatch: $($pair.Key) $($dependency.version)"
        }
    }
    if ($dependencies.Count -ne $expectedDependencies.Count) { throw "Unexpected dependency count: $($dependencies.Count)" }
} finally { $packageArchive.Dispose() }

$symbolArchive = [System.IO.Compression.ZipFile]::OpenRead($symbols[0].FullName)
try {
    $actualPdbs = @($symbolArchive.Entries.FullName |
        Where-Object { $_ -like 'lib/net10.0/ImzaKit.*.pdb' } |
        ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) } |
        Sort-Object -Unique)
    $expectedPdbs = @($expectedModules | Sort-Object)
    if (Compare-Object $expectedPdbs $actualPdbs) { throw "Module PDB set is invalid: $($actualPdbs -join ', ')" }
} finally { $symbolArchive.Dispose() }

Write-Output "NuGet package verification passed: ImzaKit $Version"
```

- [ ] **Step 2: Run the validator against the current nine-package output**

Run:

```powershell
pwsh -NoProfile -File scripts/verify-nuget-package.ps1
```

Expected: FAIL with `Expected one nupkg, found 9.` This establishes the red state for the requested one-package behavior.

- [ ] **Step 3: Commit the failing validator**

```powershell
git add scripts/verify-nuget-package.ps1
git commit -m "test: define single NuGet package contract"
```

### Task 2: Add the packaging-only project

**Files:**
- Create: `packaging/ImzaKit/ImzaKit.csproj`
- Modify: `Directory.Build.props`
- Modify: `ImzaKit.slnx`

**Interfaces:**
- Consumes: the nine production project outputs and the common metadata in `Directory.Build.props`.
- Produces: one packable `ImzaKit` project whose main archive has nine module DLLs and whose symbol archive has nine matching PDBs.

- [ ] **Step 1: Make projects non-packable by default**

Add this property to the common `PropertyGroup` in `Directory.Build.props`:

```xml
<IsPackable>false</IsPackable>
```

Keep common version, repository, license, README, tags, and symbol settings unchanged. The packaging project will explicitly override this default.

- [ ] **Step 2: Create the packaging project**

Create `packaging/ImzaKit/ImzaKit.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <IsPackable>true</IsPackable>
    <PackageId>ImzaKit</PackageId>
    <Description>Provider-independent electronic signature toolkit for .NET.</Description>
    <IncludeBuildOutput>false</IncludeBuildOutput>
    <TargetsForTfmSpecificBuildOutput>$(TargetsForTfmSpecificBuildOutput);IncludeProjectAssemblies</TargetsForTfmSpecificBuildOutput>
    <TargetsForTfmSpecificDebugSymbolsInPackage>$(TargetsForTfmSpecificDebugSymbolsInPackage);IncludeProjectSymbols</TargetsForTfmSpecificDebugSymbolsInPackage>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\ImzaKit.Agent\ImzaKit.Agent.csproj" PrivateAssets="all" />
    <ProjectReference Include="..\..\src\ImzaKit.Api\ImzaKit.Api.csproj" PrivateAssets="all" />
    <ProjectReference Include="..\..\src\ImzaKit.Cms\ImzaKit.Cms.csproj" PrivateAssets="all" />
    <ProjectReference Include="..\..\src\ImzaKit.Core\ImzaKit.Core.csproj" PrivateAssets="all" />
    <ProjectReference Include="..\..\src\ImzaKit.Cryptography\ImzaKit.Cryptography.csproj" PrivateAssets="all" />
    <ProjectReference Include="..\..\src\ImzaKit.DependencyInjection\ImzaKit.DependencyInjection.csproj" PrivateAssets="all" />
    <ProjectReference Include="..\..\src\ImzaKit.PAdES\ImzaKit.PAdES.csproj" PrivateAssets="all" />
    <ProjectReference Include="..\..\src\ImzaKit.Pkcs11\ImzaKit.Pkcs11.csproj" PrivateAssets="all" />
    <ProjectReference Include="..\..\src\ImzaKit.Verify\ImzaKit.Verify.csproj" PrivateAssets="all" />
    <PackageReference Include="BouncyCastle.Cryptography" />
    <PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" />
    <PackageReference Include="System.Security.Cryptography.Pkcs" />
  </ItemGroup>
  <Target Name="IncludeProjectAssemblies" DependsOnTargets="ResolveReferences">
    <ItemGroup>
      <BuildOutputInPackage Include="@(ReferenceCopyLocalPaths)"
                            Condition="'%(ReferenceCopyLocalPaths.ReferenceSourceTarget)' == 'ProjectReference' And '%(ReferenceCopyLocalPaths.Extension)' == '.dll'"
                            TargetPath="%(ReferenceCopyLocalPaths.DestinationSubPath)" />
    </ItemGroup>
  </Target>
  <Target Name="IncludeProjectSymbols" DependsOnTargets="ResolveReferences">
    <ItemGroup>
      <_ProjectSymbol Include="@(ReferenceCopyLocalPaths->'%(RootDir)%(Directory)%(Filename).pdb')"
                      Condition="'%(ReferenceCopyLocalPaths.ReferenceSourceTarget)' == 'ProjectReference' And '%(ReferenceCopyLocalPaths.Extension)' == '.dll' And Exists('%(ReferenceCopyLocalPaths.RootDir)%(ReferenceCopyLocalPaths.Directory)%(ReferenceCopyLocalPaths.Filename).pdb')" />
      <TfmSpecificDebugSymbolsFile Include="@(_ProjectSymbol)" TargetPath="%(Filename)%(Extension)" />
    </ItemGroup>
  </Target>
</Project>
```

- [ ] **Step 3: Add the packaging project to the solution**

Add this folder after `/src/` in `ImzaKit.slnx`:

```xml
<Folder Name="/packaging/">
  <Project Path="packaging/ImzaKit/ImzaKit.csproj" />
</Folder>
```

- [ ] **Step 4: Build and pack the solution**

Run:

```powershell
dotnet build ImzaKit.slnx -c Release
dotnet pack ImzaKit.slnx -c Release --no-build --output artifacts/packages
```

Before packing, remove only `artifacts/packages` after resolving and verifying its absolute path is inside the repository. Expected pack output: one `ImzaKit.1.0.0-alpha.1.nupkg` and one `ImzaKit.1.0.0-alpha.1.snupkg`.

- [ ] **Step 5: Run the package validator to reach green**

```powershell
pwsh -NoProfile -File scripts/verify-nuget-package.ps1
```

Expected: `NuGet package verification passed: ImzaKit 1.0.0-alpha.1`.

- [ ] **Step 6: Commit the packaging project**

```powershell
git add Directory.Build.props ImzaKit.slnx packaging/ImzaKit/ImzaKit.csproj
git commit -m "build: produce a single ImzaKit package"
```

### Task 3: Add a real consumer smoke test

**Files:**
- Create: `tests/ImzaKit.PackageSmoke/ImzaKit.PackageSmoke.csproj`
- Create: `tests/ImzaKit.PackageSmoke/Program.cs`
- Create: `tests/ImzaKit.PackageSmoke/NuGet.Config`

**Interfaces:**
- Consumes: `artifacts/packages/ImzaKit.1.0.0-alpha.1.nupkg` through one `PackageReference`.
- Produces: a process output listing module assembly names, proving a package consumer can compile and load public APIs from multiple bundled modules.

- [ ] **Step 1: Create the isolated consumer project**

Create `tests/ImzaKit.PackageSmoke/ImzaKit.PackageSmoke.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <OutputType>Exe</OutputType>
    <ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="ImzaKit" Version="1.0.0-alpha.1" />
  </ItemGroup>
</Project>
```

Do not add this project to `ImzaKit.slnx`; it must consume the package rather than project references.

- [ ] **Step 2: Add the local feed configuration**

Create `tests/ImzaKit.PackageSmoke/NuGet.Config`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="imzakit-local" value="..\..\artifacts\packages" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
</configuration>
```

- [ ] **Step 3: Add the multi-module smoke program**

Create `tests/ImzaKit.PackageSmoke/Program.cs`:

```csharp
using ImzaKit.Agent.Configuration;
using ImzaKit.Api.Problems;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Cryptography;
using ImzaKit.Cryptography.Digests;
using ImzaKit.DependencyInjection;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Pkcs11.Akis;
using ImzaKit.Verify.Validation;

var names = new[]
{
    typeof(AgentLoopbackOptions).Assembly.GetName().Name,
    typeof(ApiProblemCatalog).Assembly.GetName().Name,
    typeof(CmsSignaturePreparer).Assembly.GetName().Name,
    typeof(HashAlgorithmId).Assembly.GetName().Name,
    typeof(DefaultDigestCalculator).Assembly.GetName().Name,
    typeof(ImzaKitServiceCollectionExtensions).Assembly.GetName().Name,
    typeof(PadesSignaturePreparer).Assembly.GetName().Name,
    typeof(AkisProviderProfile).Assembly.GetName().Name,
    typeof(PadesValidator).Assembly.GetName().Name
};

Console.WriteLine(string.Join('|', names));
```

- [ ] **Step 4: Run the smoke test from a clean consumer output**

Delete only `tests/ImzaKit.PackageSmoke/bin` and `tests/ImzaKit.PackageSmoke/obj` after verifying both resolved paths remain inside that fixture directory, then run:

```powershell
dotnet run --project tests/ImzaKit.PackageSmoke/ImzaKit.PackageSmoke.csproj -c Release --configfile tests/ImzaKit.PackageSmoke/NuGet.Config
```

Expected output:

```text
ImzaKit.Agent|ImzaKit.Api|ImzaKit.Cms|ImzaKit.Core|ImzaKit.Cryptography|ImzaKit.DependencyInjection|ImzaKit.PAdES|ImzaKit.Pkcs11|ImzaKit.Verify
```

- [ ] **Step 5: Commit the consumer smoke test**

```powershell
git add tests/ImzaKit.PackageSmoke
git commit -m "test: verify single-package consumption"
```

### Task 4: Update release documentation and status report

**Files:**
- Modify: `README.md`
- Modify: `reports/imzakit-gelistirme-durum.html`
- Modify: `docs/superpowers/plans/2026-08-23-nuget-release.md`

**Interfaces:**
- Consumes: verified one-package build evidence from Tasks 2 and 3.
- Produces: public installation documentation and a truthful live report showing one package ready and NuGet publication blocked only by the API key.

- [ ] **Step 1: Change README package language**

Replace the `## Packages` heading with `## Modules in the package`, retain the nine-row module table, and add this sentence above it:

```markdown
NuGet.org distributes all modules together under the single package ID `ImzaKit`; the assemblies remain separate so their namespaces and architectural boundaries stay explicit.
```

Keep the install command as:

```shell
dotnet add package ImzaKit --version 1.0.0-alpha.1
```

- [ ] **Step 2: Update the live HTML report**

Make these evidence changes without changing the visual system:

- Hero: `Tek NuGet ön sürümü yayına hazır.`
- Metric: `1+1` and `NuGet + sembol paketi`.
- Quality gate: `1 nupkg + 1 snupkg`.
- NuGet artifact detail: one package containing nine DLLs and nine PDBs.
- Release work item: `ImzaKit 1.0.0-alpha.1` with evidence `1 nupkg + 1 snupkg`.
- Next operation remains NuGet.org publication and must still say `NUGET_API_KEY bekleniyor` until publication succeeds.

- [ ] **Step 3: Supersede the earlier nine-package release plan**

At the top of `docs/superpowers/plans/2026-08-23-nuget-release.md`, after its title, add:

```markdown
> **Superseded:** The approved release architecture now publishes one `ImzaKit` package. Follow `docs/superpowers/plans/2026-08-23-single-nuget-package.md` instead.
```

- [ ] **Step 4: Verify report content and FRD traceability**

```powershell
rg -n "1\+1|ImzaKit 1.0.0-alpha.1|NUGET_API_KEY bekleniyor" reports/imzakit-gelistirme-durum.html
pwsh -NoProfile -File scripts/validate-frd.ps1
```

Expected: all three report phrases are present and FRD validation reports `109/109` with no failures.

- [ ] **Step 5: Commit documentation and report changes**

```powershell
git add README.md reports/imzakit-gelistirme-durum.html docs/superpowers/plans/2026-08-23-nuget-release.md
git commit -m "docs: document the single ImzaKit package"
```

### Task 5: Run final gates, push, and publish when authorized

**Files:**
- Generated and ignored: `artifacts/packages/ImzaKit.1.0.0-alpha.1.nupkg`
- Generated and ignored: `artifacts/packages/ImzaKit.1.0.0-alpha.1.snupkg`
- Modify after successful NuGet visibility only: `reports/imzakit-gelistirme-durum.html`

**Interfaces:**
- Consumes: all committed changes from Tasks 1–4 and optional `NUGET_API_KEY` environment secret.
- Produces: fresh verification evidence, a synchronized `origin/main`, and—only when the secret exists—a visible NuGet.org prerelease.

- [ ] **Step 1: Run the complete local verification sequence**

```powershell
dotnet build ImzaKit.slnx -c Release
dotnet test ImzaKit.slnx -c Release --no-build
dotnet pack ImzaKit.slnx -c Release --no-build --output artifacts/packages
pwsh -NoProfile -File scripts/verify-nuget-package.ps1
dotnet run --project tests/ImzaKit.PackageSmoke/ImzaKit.PackageSmoke.csproj -c Release --configfile tests/ImzaKit.PackageSmoke/NuGet.Config
pwsh -NoProfile -File scripts/validate-frd.ps1
git diff --check
```

Expected: build has `0` warnings and `0` errors; all `90` tests pass; package validator and consumer smoke test pass; FRD reports `109/109`; diff check is clean.

- [ ] **Step 2: Review repository state**

```powershell
git status --short
git log -5 --oneline --decorate
```

Confirm generated `bin`, `obj`, and `artifacts` files are not included. If tracked build outputs changed because the initial repository already tracked them, restore only the verified `src/*/(bin|obj)` and `tests/*/(bin|obj)` paths produced by this run; do not touch source or user changes.

- [ ] **Step 3: Push the verified commits**

```powershell
git push origin main
```

Verify `git rev-parse HEAD` equals `git rev-parse origin/main`.

- [ ] **Step 4: Check NuGet identity and secret without exposing it**

Query `https://api.nuget.org/v3-flatcontainer/imzakit/index.json`. Continue only when `1.0.0-alpha.1` is absent. Check the secret only with:

```powershell
if ([string]::IsNullOrWhiteSpace($env:NUGET_API_KEY)) { exit 2 }
```

If exit code is `2`, stop with the package prepared and report the missing secret. Never echo its value.

- [ ] **Step 5: Publish the one package**

Run only when the secret exists:

```powershell
dotnet nuget push artifacts/packages/ImzaKit.1.0.0-alpha.1.nupkg --api-key $env:NUGET_API_KEY --source https://api.nuget.org/v3/index.json --symbol-source https://api.nuget.org/v3/index.json --skip-duplicate
```

Expected: the package and symbol package are accepted. Do not repack between final verification and push.

- [ ] **Step 6: Verify NuGet visibility and finalize the report**

Poll `https://api.nuget.org/v3-flatcontainer/imzakit/index.json` with bounded retries until `1.0.0-alpha.1` appears. Only then change the report’s release work item from `next` to `done`, replace the key-waiting evidence with the public version URL, rerun `git diff --check`, commit as `docs: record NuGet publication`, and push `main`.
