# ImzaKit Open Source Landing Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a bilingual, light-theme ImzaKit landing page through GitHub Pages and make the repository ready for open-source contributors.

**Architecture:** Keep the marketing surface as a dependency-free static document in `site/`, separate from technical documentation in `docs/`. Validate landing-page content, community files, and the Pages workflow with PowerShell contract scripts before a minimal-permission GitHub Actions deployment from `main`.

**Tech Stack:** HTML5, CSS, vanilla JavaScript, PowerShell 7, GitHub Actions, GitHub Pages

**Spec:** `docs/superpowers/specs/2026-08-23-open-source-landing-page-design.md`

## Global Constraints

- Target URL is `https://yasinilkalp.github.io/imzakit/`.
- Turkish is the default language; English must provide equivalent section coverage.
- Package examples must use `ImzaKit 1.0.0-alpha.3` and .NET 10.
- The site must not use external fonts, stylesheets, scripts, images, analytics, cookies, frameworks, or build tools.
- The primary CTA is `NuGet ile Başla`; the secondary CTA is `GitHub'da İncele`.
- The visual direction is warm off-white, soft green, community-friendly, responsive, and WCAG AA-oriented.
- JavaScript-disabled users must retain Turkish content and all essential links.
- GitHub Pages deployment must originate from `main` and use only `contents: read`, `pages: write`, and `id-token: write` permissions.
- Work directly on `main`, matching the user's explicit repository workflow preference.

---

## File Map

- `site/index.html` — complete bilingual landing page, styles, and interactions in one deployable file.
- `scripts/verify-landing-page.ps1` — static site content, accessibility, dependency, and API-example contract.
- `scripts/verify-open-source-readiness.ps1` — community-file and issue-template contract.
- `scripts/verify-pages-workflow.ps1` — GitHub Pages trigger, permission, validation, and artifact contract.
- `CONTRIBUTING.md` — local setup, tests, contribution scope, and pull-request expectations.
- `CODE_OF_CONDUCT.md` — Contributor Covenant-based participation rules and enforcement contact route.
- `SECURITY.md` — supported version and private vulnerability-reporting process.
- `.github/ISSUE_TEMPLATE/bug_report.yml` — structured bug intake.
- `.github/ISSUE_TEMPLATE/feature_request.yml` — structured feature proposal intake.
- `.github/ISSUE_TEMPLATE/config.yml` — disables blank issues and routes security reports privately.
- `.github/workflows/pages.yml` — validation and GitHub Pages deployment.
- `README.md` — public website and contributor entry points.
- `reports/imzakit-gelistirme-durum.html` — landing-page and Pages delivery evidence.

---

### Task 1: Open-Source Community Contract

**Files:**
- Create: `scripts/verify-open-source-readiness.ps1`
- Create: `CONTRIBUTING.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `SECURITY.md`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`
- Create: `.github/ISSUE_TEMPLATE/feature_request.yml`
- Create: `.github/ISSUE_TEMPLATE/config.yml`

**Interfaces:**
- Consumes: existing `LICENSE`, `NOTICE`, `README.md`, `ImzaKit.slnx`, and repository commands.
- Produces: `verify-open-source-readiness.ps1` returning exit code `0` and the message `Open-source readiness verification passed.` when every community contract is present.

- [ ] **Step 1: Write the failing readiness verifier**

Create `scripts/verify-open-source-readiness.ps1` with a repository-root lookup from `$PSScriptRoot`, a required-file list, and content assertions:

```powershell
[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))
$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($RepositoryRoot)
$required = @(
    'LICENSE', 'NOTICE', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'SECURITY.md',
    '.github/ISSUE_TEMPLATE/bug_report.yml',
    '.github/ISSUE_TEMPLATE/feature_request.yml',
    '.github/ISSUE_TEMPLATE/config.yml'
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $path) -PathType Leaf)) {
        throw "Required open-source file is missing: $path"
    }
}
$checks = [ordered]@{
    'CONTRIBUTING.md' = @('dotnet restore', 'dotnet test', 'pull request')
    'CODE_OF_CONDUCT.md' = @('Contributor Covenant', 'enforcement')
    'SECURITY.md' = @('1.0.0-alpha.3', 'Security advisory', 'public issue')
    '.github/ISSUE_TEMPLATE/bug_report.yml' = @('name:', 'description:', 'reproduction', 'environment')
    '.github/ISSUE_TEMPLATE/feature_request.yml' = @('name:', 'description:', 'use case', 'scope')
    '.github/ISSUE_TEMPLATE/config.yml' = @('blank_issues_enabled: false', 'Security advisory')
}
foreach ($entry in $checks.GetEnumerator()) {
    $text = Get-Content -LiteralPath (Join-Path $root $entry.Key) -Raw
    foreach ($pattern in $entry.Value) {
        if ($text.IndexOf($pattern, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "$($entry.Key) is missing required content: $pattern"
        }
    }
}
Write-Host 'Open-source readiness verification passed.' -ForegroundColor Green
```

- [ ] **Step 2: Run the verifier and confirm the red state**

Run: `pwsh -NoProfile -File scripts/verify-open-source-readiness.ps1`

Expected: FAIL naming `CONTRIBUTING.md` as the first missing file.

- [ ] **Step 3: Add the community documents**

Write `CONTRIBUTING.md` in Turkish with an English summary. Include exact commands `dotnet restore ImzaKit.slnx`, `dotnet build ImzaKit.slnx -c Release`, `dotnet test ImzaKit.slnx -c Release --no-build`, `pwsh -NoProfile -File scripts/validate-frd.ps1`, small focused changes, tests for behavior changes, no secrets/test certificates, and pull-request evidence expectations.

Write `CODE_OF_CONDUCT.md` using Contributor Covenant 2.1 terms. State expected behavior, unacceptable behavior, maintainer enforcement duties, correction/warning/temporary ban/permanent ban consequences, and GitHub private contact through the repository owner.

Write `SECURITY.md` with `1.0.0-alpha.3` as the supported prerelease, GitHub private security advisories as the reporting channel, an explicit prohibition against public issues for unpatched vulnerabilities, requested reproduction/impact/environment fields, and a best-effort 7-day acknowledgement target without promising a fix deadline.

- [ ] **Step 4: Add structured issue templates**

Create GitHub Issue Forms with these stable IDs:

```yaml
# bug_report.yml fields
name: Hata bildirimi
description: Yeniden üretilebilir bir ImzaKit hatasını bildirin.
body:
  - type: textarea
    id: reproduction
  - type: textarea
    id: expected
  - type: textarea
    id: actual
  - type: input
    id: package-version
  - type: textarea
    id: environment
```

```yaml
# feature_request.yml fields
name: Özellik önerisi
description: Somut bir kullanım ihtiyacı için özellik önerin.
body:
  - type: textarea
    id: use-case
  - type: textarea
    id: proposed-solution
  - type: textarea
    id: scope
  - type: textarea
    id: alternatives
```

Set required validation on reproduction/use-case, environment/scope, and expected behavior. In `config.yml`, set `blank_issues_enabled: false` and add contact links for Discussions and a GitHub Security Advisory using repository URLs.

- [ ] **Step 5: Run the readiness contract**

Run: `pwsh -NoProfile -File scripts/verify-open-source-readiness.ps1`

Expected: `Open-source readiness verification passed.`

- [ ] **Step 6: Commit the community layer**

```bash
git add CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md .github/ISSUE_TEMPLATE scripts/verify-open-source-readiness.ps1
git commit -m "docs: add open source community guidelines"
```

---

### Task 2: Landing Page Contract and Static Site

**Files:**
- Create: `scripts/verify-landing-page.ps1`
- Create: `site/index.html`

**Interfaces:**
- Consumes: published package version `1.0.0-alpha.3`, GitHub repository URLs, NuGet URL, and technical guide path.
- Produces: a self-contained static page at `site/index.html`; `verify-landing-page.ps1` exits `0` with `Landing page verification passed.`

- [ ] **Step 1: Write the failing landing-page verifier**

Create `scripts/verify-landing-page.ps1`. Require the file, then search case-insensitively for:

```powershell
$required = [ordered]@{
    'HTML5 doctype' = '<!doctype html>'
    'Default Turkish language' = 'lang="tr"'
    'Turkish hero' = 'İmzalama altyapınızı birlikte geliştirelim.'
    'English hero' = 'Let''s build signing infrastructure together.'
    'Primary CTA' = 'NuGet ile Başla'
    'Secondary CTA' = 'GitHub''da İncele'
    'Package command' = 'dotnet add package ImzaKit --version 1.0.0-alpha.3'
    'Core registration' = 'AddImzaKitCore'
    'PKCS11 registration' = 'AddImzaKitPkcs11'
    'Language control' = 'id="language-toggle"'
    'Mobile menu state' = 'aria-expanded="false"'
    'Module filter' = 'data-module='
    'Copy action' = 'data-copy'
    'Reduced motion' = 'prefers-reduced-motion'
    'No-script fallback' = '<noscript>'
    'GitHub repository' = 'https://github.com/yasinilkalp/imzakit'
    'NuGet package' = 'https://www.nuget.org/packages/ImzaKit/1.0.0-alpha.3'
    'Technical guide' = 'https://github.com/yasinilkalp/imzakit/blob/main/docs/imzakit-teknik-kullanim-rehberi.html'
    'Security policy' = 'https://github.com/yasinilkalp/imzakit/blob/main/SECURITY.md'
    'Contribution guide' = 'https://github.com/yasinilkalp/imzakit/blob/main/CONTRIBUTING.md'
}
```

Reject `<script src=`, `<link rel="stylesheet"`, `@import`, `http` URLs in CSS `url(...)`, analytics identifiers, and `<img src="http`. Count exactly nine distinct `data-module` cards. Require one `h1`, a skip link, `main`, `nav`, and `footer`.

All links to repository files outside `site/` must use absolute `https://github.com/yasinilkalp/imzakit/blob/main/...` URLs because the Pages artifact contains only `site/`.

- [ ] **Step 2: Run the verifier and confirm the red state**

Run: `pwsh -NoProfile -File scripts/verify-landing-page.ps1`

Expected: FAIL with `Landing page is missing` because `site/index.html` does not exist.

- [ ] **Step 3: Build the semantic page shell**

Create `site/index.html` as one HTML5 file. Use a skip link, sticky `nav`, one `h1`, semantic `main` sections, and `footer`. Include Turkish text as normal visible HTML. Place equivalent English strings in `data-tr` and `data-en` attributes or paired language spans so JavaScript can switch without fetching content.

Use the approved section order:

1. Hero and CTA pair
2. Apache-2.0/.NET 10/single package/nine modules/open source trust strip
3. Prepare → Sign → Complete and Validate flow
4. Six capability cards
5. Nine filterable module cards
6. NuGet and DI code examples
7. Community entry points
8. Alpha and integration-responsibility warning

- [ ] **Step 4: Implement the approved light visual system**

Define CSS custom properties for warm off-white, dark green text, soft green accent, muted text, border, and code surface. Use system fonts, a 1200 px content maximum, responsive grids, visible `:focus-visible`, a 44 px minimum touch target for primary controls, and limited corner radii. Add breakpoints at 900 px and 600 px, `overflow-x: hidden`, internally scrolling code blocks, and `@media (prefers-reduced-motion: reduce)`.

Do not use gradients, external assets, icon libraries, decorative SVG, or excessive card nesting.

- [ ] **Step 5: Add resilient interactions**

Implement these named functions in the inline script:

```javascript
function setLanguage(language) { /* tr or en; update html.lang and localStorage */ }
function toggleMenu() { /* update hidden state and aria-expanded */ }
function filterModules(group) { /* all, signing, edge, platform */ }
async function copyCode(button) { /* Clipboard API with selection fallback text */ }
```

Bind them through `addEventListener`, not inline event attributes. Close the mobile menu when a navigation link is selected. Persist only the language code in `localStorage` under `imzakit-site-language`.

- [ ] **Step 6: Run the landing-page contract**

Run: `pwsh -NoProfile -File scripts/verify-landing-page.ps1`

Expected: `Landing page verification passed.`

- [ ] **Step 7: Commit the deployable site**

```bash
git add site/index.html scripts/verify-landing-page.ps1
git commit -m "feat: add bilingual ImzaKit landing page"
```

---

### Task 3: GitHub Pages Deployment Contract

**Files:**
- Create: `scripts/verify-pages-workflow.ps1`
- Create: `.github/workflows/pages.yml`

**Interfaces:**
- Consumes: `site/index.html`, `scripts/verify-landing-page.ps1`, and `scripts/verify-open-source-readiness.ps1`.
- Produces: a GitHub Pages workflow that validates and deploys the `site/` directory from `main`; verifier message `Pages workflow verification passed.`

- [ ] **Step 1: Write the failing workflow verifier**

Create `scripts/verify-pages-workflow.ps1` and require these literal contracts in `.github/workflows/pages.yml`:

```powershell
$required = @(
    'branches: [main]',
    'workflow_dispatch:',
    'contents: read',
    'pages: write',
    'id-token: write',
    'concurrency:',
    'actions/configure-pages@v5',
    'actions/upload-pages-artifact@v3',
    'path: site',
    'actions/deploy-pages@v4',
    'environment:',
    'name: github-pages',
    'scripts/verify-landing-page.ps1',
    'scripts/verify-open-source-readiness.ps1'
)
```

Also reject `pull_request_target`, `secrets.`, `write-all`, package installation, and arbitrary curl/download steps.

- [ ] **Step 2: Run the verifier and confirm the red state**

Run: `pwsh -NoProfile -File scripts/verify-pages-workflow.ps1`

Expected: FAIL because `.github/workflows/pages.yml` is missing.

- [ ] **Step 3: Create the Pages workflow**

Use this job structure:

```yaml
name: Publish landing page
on:
  push:
    branches: [main]
    paths:
      - site/**
      - scripts/verify-landing-page.ps1
      - scripts/verify-open-source-readiness.ps1
      - .github/workflows/pages.yml
      - CONTRIBUTING.md
      - CODE_OF_CONDUCT.md
      - SECURITY.md
      - .github/ISSUE_TEMPLATE/**
  workflow_dispatch:
permissions:
  contents: read
  pages: write
  id-token: write
concurrency:
  group: pages
  cancel-in-progress: false
jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - shell: pwsh
        run: ./scripts/verify-landing-page.ps1
      - shell: pwsh
        run: ./scripts/verify-open-source-readiness.ps1
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: site
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

- [ ] **Step 4: Run all three static contracts**

Run:

```powershell
pwsh -NoProfile -File scripts/verify-open-source-readiness.ps1
pwsh -NoProfile -File scripts/verify-landing-page.ps1
pwsh -NoProfile -File scripts/verify-pages-workflow.ps1
```

Expected: all three print their `passed` messages and exit `0`.

- [ ] **Step 5: Commit the deployment pipeline**

```bash
git add .github/workflows/pages.yml scripts/verify-pages-workflow.ps1
git commit -m "ci: publish landing page with GitHub Pages"
```

---

### Task 4: Repository Entry Points and Live Status

**Files:**
- Modify: `README.md`
- Modify: `reports/imzakit-gelistirme-durum.html`

**Interfaces:**
- Consumes: final Pages URL, community files, and three verification scripts.
- Produces: discoverable website/contribution links and a status entry recording landing-page readiness without claiming deployment success prematurely.

- [ ] **Step 1: Extend the landing verifier with repository-link assertions**

Add checks that `README.md` contains:

```text
https://yasinilkalp.github.io/imzakit/
CONTRIBUTING.md
SECURITY.md
CODE_OF_CONDUCT.md
```

Add checks that the status report contains `Açık kaynak landing page`, `GitHub Pages`, and `landing page verification passed`.

- [ ] **Step 2: Run the verifier and confirm the red state**

Run: `pwsh -NoProfile -File scripts/verify-landing-page.ps1`

Expected: FAIL naming the missing README or status-report content.

- [ ] **Step 3: Update README entry points**

In Turkish and English source/status sections, add the public website, contributing guide, code of conduct, and security policy. Keep the NuGet prerelease warning unchanged. Do not state that Pages is live until the deployment check succeeds.

- [ ] **Step 4: Update the live status report**

Add a completed work item for the bilingual static page and community files. Add quality-gate rows for all three contract scripts. Set the current stage to `GitHub Pages yayını bekleniyor` until the remote workflow and HTTP checks pass.

- [ ] **Step 5: Run repository documentation checks**

Run:

```powershell
pwsh -NoProfile -File scripts/verify-landing-page.ps1
pwsh -NoProfile -File scripts/verify-open-source-readiness.ps1
pwsh -NoProfile -File scripts/verify-pages-workflow.ps1
pwsh -NoProfile -File scripts/verify-technical-guide.ps1
pwsh -NoProfile -File scripts/validate-frd.ps1
git diff --check
```

Expected: five pass messages, no whitespace errors, and only CRLF conversion warnings if Git reports them.

- [ ] **Step 6: Commit repository documentation integration**

```bash
git add README.md reports/imzakit-gelistirme-durum.html scripts/verify-landing-page.ps1
git commit -m "docs: link open source website and community guides"
```

---

### Task 5: Browser QA, Publish, and Remote Acceptance

**Files:**
- Modify after successful deployment: `reports/imzakit-gelistirme-durum.html`

**Interfaces:**
- Consumes: committed site, Pages workflow, verification scripts, and GitHub repository access.
- Produces: pushed `main`, successful Pages run, HTTP 200 live site, and status-report publication evidence.

- [ ] **Step 1: Run desktop browser QA locally**

Serve the repository on `127.0.0.1` and open `/site/`. Verify from visible DOM and browser state:

- one `h1` and ordered headings;
- Turkish default copy;
- language toggle changes `html.lang` to `en`, translates every section, and survives reload;
- module filters show `9` for all and the expected subset for each category;
- NuGet and DI copy buttons provide success feedback;
- navigation anchors reach the intended sections;
- no console errors or warnings.

- [ ] **Step 2: Run mobile browser QA at 390 × 844**

Verify the mobile menu opens/closes, updates `aria-expanded`, closes after link selection, and can be operated by keyboard. Confirm `document.body.scrollWidth <= document.body.clientWidth`, code blocks scroll internally, CTA buttons remain visible, and reduced-motion rules exist.

- [ ] **Step 3: Run the final local gate**

Run:

```powershell
pwsh -NoProfile -File scripts/verify-open-source-readiness.ps1
pwsh -NoProfile -File scripts/verify-landing-page.ps1
pwsh -NoProfile -File scripts/verify-pages-workflow.ps1
pwsh -NoProfile -File scripts/verify-technical-guide.ps1
pwsh -NoProfile -File scripts/validate-frd.ps1
git diff --check
git status --short
```

Expected: all checks pass; the worktree is clean before push.

- [ ] **Step 4: Push `main` and watch the Pages workflow**

```bash
git push origin main
gh run list --workflow pages.yml --limit 1
gh run watch <run-id> --exit-status
```

Expected: the newest `Publish landing page` run concludes with `success`.

- [ ] **Step 5: Handle first-time Pages configuration only if required**

If the workflow reports that Pages is not enabled for Actions, inspect repository Pages settings. Request user approval immediately before changing repository settings, then set the Pages build type to GitHub Actions. Re-run the workflow with `gh workflow run pages.yml` and watch it to success. Do not change visibility, branch protection, permissions beyond the workflow contract, or custom-domain settings.

- [ ] **Step 6: Verify the live artifact**

Request `https://yasinilkalp.github.io/imzakit/` and require HTTP 200. Open the live URL in a browser and verify the title, Turkish hero, English toggle, GitHub link, NuGet link, and absence of console errors. Treat a GitHub Pages propagation delay as pending, retrying at reasonable intervals without changing code.

- [ ] **Step 7: Record remote acceptance evidence**

Update the status report from `GitHub Pages yayını bekleniyor` to `Açık kaynak landing page yayında`. Record the live URL, successful Actions run URL, deployment date, and HTTP 200 result. Re-run `verify-landing-page.ps1`, `validate-frd.ps1`, and `git diff --check`.

- [ ] **Step 8: Commit and push the final evidence**

```bash
git add reports/imzakit-gelistirme-durum.html
git commit -m "docs: record GitHub Pages publication"
git push origin main
```

Expected: final worktree clean and the follow-up Pages workflow successful.
