# NuGet Prerelease Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the nine production ImzaKit libraries as verified `1.0.0-alpha.1` packages on NuGet.org.

**Architecture:** Centralize shared NuGet metadata in `Directory.Build.props`, retain package-specific descriptions in each production project, and embed the root README in every package. Produce all packages from the solution into an ignored artifacts directory, inspect their manifests and contents, then publish with a user-supplied environment secret.

**Tech Stack:** .NET SDK 10.0.400, MSBuild, NuGet.org, PowerShell

**Spec:** `frd/`

## Global Constraints

- License is Apache-2.0.
- Initial public version is `1.0.0-alpha.1`.
- Repository is `https://github.com/yasinilkalp/imzakit`.
- API keys must never be committed, written into project files, or printed.
- Only the nine projects under `src/` are packable; test projects remain unpublished.

---

### Task 1: Release metadata and repository hygiene

**Files:**
- Create: `README.md`
- Create: `.gitignore`
- Modify: `Directory.Build.props`
- Modify: `src/ImzaKit.Agent/ImzaKit.Agent.csproj`
- Modify: `src/ImzaKit.Api/ImzaKit.Api.csproj`
- Modify: `src/ImzaKit.Pkcs11/ImzaKit.Pkcs11.csproj`
- Modify: `src/ImzaKit.Verify/ImzaKit.Verify.csproj`

**Interfaces:**
- Consumes: existing SDK-style projects and Apache-2.0 `LICENSE`
- Produces: complete NuGet metadata and a package-embedded README for all production projects

- [ ] **Step 1:** Add common version, repository, readme, symbols, and tags metadata to `Directory.Build.props`.
- [ ] **Step 2:** Add clear package descriptions to the four projects whose descriptions are currently implicit.
- [ ] **Step 3:** Add a concise README with package map, installation command, project status, license, and security warning.
- [ ] **Step 4:** Ignore generated build and package artifacts.
- [ ] **Step 5:** Run `dotnet build ImzaKit.slnx -c Release` and require exit code 0.

### Task 2: Package production and inspection

**Files:**
- Generate: `artifacts/packages/*.nupkg`
- Generate: `artifacts/packages/*.snupkg`

**Interfaces:**
- Consumes: the release metadata from Task 1
- Produces: nine installable packages and nine symbol packages at version `1.0.0-alpha.1`

- [ ] **Step 1:** Run `dotnet pack ImzaKit.slnx -c Release --no-build --output artifacts/packages`.
- [ ] **Step 2:** Assert that exactly nine `.nupkg` and nine `.snupkg` files exist.
- [ ] **Step 3:** Inspect every `.nuspec` and archive to confirm identity, version, Apache-2.0 license, repository URL, README, assemblies, and symbols.
- [ ] **Step 4:** Run the full test suite and require zero failures.

### Task 3: Source control and NuGet publication

**Files:**
- Modify: `reports/imzakit-gelistirme-durum.html`

**Interfaces:**
- Consumes: verified packages and `NUGET_API_KEY` supplied outside the repository
- Produces: Git-tracked release preparation and publicly downloadable NuGet packages

- [ ] **Step 1:** Update the live development report with package preparation and publication state.
- [ ] **Step 2:** Review `git diff`, commit only release-preparation files, and push `main`.
- [ ] **Step 3:** Confirm all nine package IDs and version `1.0.0-alpha.1` are not already published.
- [ ] **Step 4:** Publish `.nupkg` files with `dotnet nuget push`, the `NUGET_API_KEY` environment variable, NuGet.org source, symbol source, and `--skip-duplicate`.
- [ ] **Step 5:** Query NuGet.org and confirm every package/version is visible before reporting completion.
