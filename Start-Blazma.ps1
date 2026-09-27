<#
.SYNOPSIS
    Starts BLAZMA CYBER (Security • Forensics • Intelligence).

.DESCRIPTION
    Verifies prerequisites, then launches the desktop GUI. PowerShell is only the launcher;
    the application itself is a graphical desktop app.

    This script NEVER installs software silently. If dependencies are missing it explains what
    to do. Project dependencies (from the locked package-lock.json) are installed only when you
    explicitly pass -Install.

.PARAMETER Install
    Install the project's locked npm dependencies (npm ci) before starting.

.PARAMETER Dev
    Start in development mode (hot reload for the UI).

.PARAMETER SkipBuild
    Launch the last build without rebuilding.

.EXAMPLE
    .\Start-Blazma.ps1
.EXAMPLE
    .\Start-Blazma.ps1 -Install
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Dev,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$MinNodeMajor = 20

function Write-Step([string]$Text) { Write-Host "  [*] $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text) { Write-Host "  [+] $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "  [!] $Text" -ForegroundColor Yellow }
function Stop-WithError([string]$English, [string]$Arabic, [string]$Fix) {
    Write-Host ''
    Write-Host "  [x] $English" -ForegroundColor Red
    Write-Host "      $Arabic" -ForegroundColor Red
    if ($Fix) { Write-Host "      -> $Fix" -ForegroundColor Yellow }
    Write-Host ''
    exit 1
}

Write-Host ''
Write-Host '  BLAZMA CYBER' -ForegroundColor Cyan
Write-Host '  Security • Forensics • Intelligence' -ForegroundColor DarkCyan
Write-Host ''

# 1. Platform
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Stop-WithError 'PowerShell 5.1 or newer is required.' 'يتطلب البرنامج PowerShell 5.1 أو أحدث.' 'Update Windows Management Framework.'
}
$onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)
if (-not $onWindows) {
    Write-Warn 'Not running on Windows: Windows-specific modules (Defender, firewall, signatures) will be unavailable.'
} elseif (-not [Environment]::Is64BitOperatingSystem) {
    Stop-WithError 'A 64-bit version of Windows is required.' 'يتطلب البرنامج نسخة Windows بمعمارية 64 بت.' ''
} else {
    Write-Ok "Windows $([Environment]::OSVersion.Version) x64"
}

# 2. Node.js (build/runtime tooling for the desktop app)
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    Stop-WithError 'Node.js was not found.' 'لم يُعثر على Node.js.' "Install Node.js $MinNodeMajor LTS or newer from https://nodejs.org and reopen PowerShell."
}
$nodeVersion = (& $node.Source --version).Trim().TrimStart('v')
$nodeMajor = [int]($nodeVersion.Split('.')[0])
if ($nodeMajor -lt $MinNodeMajor) {
    Stop-WithError "Node.js $nodeVersion is too old (need $MinNodeMajor+)." "إصدار Node.js قديم ($nodeVersion)، المطلوب $MinNodeMajor أو أحدث." 'Install the current Node.js LTS from https://nodejs.org'
}
Write-Ok "Node.js $nodeVersion"

$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) {
    Stop-WithError 'npm was not found.' 'لم يُعثر على npm.' 'Reinstall Node.js (npm is included).'
}

# 3. Project files
if (-not (Test-Path -LiteralPath (Join-Path $Root 'package.json'))) {
    Stop-WithError 'package.json not found next to this script.' 'لم يُعثر على package.json بجانب هذا السكربت.' 'Run the script from the BLAZMA CYBER folder.'
}

Push-Location -LiteralPath $Root
try {
    # 4. Dependencies (never installed silently)
    if ($Install) {
        Write-Step 'Installing locked dependencies (npm ci)...'
        & $npm.Source ci
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError 'Dependency installation failed.' 'فشل تثبيت الاعتماديات.' 'Check your network connection and try again.'
        }
    }
    $electronExe = Join-Path $Root 'node_modules\electron\dist\electron.exe'
    if (-not $onWindows) { $electronExe = Join-Path $Root 'node_modules/electron/dist/electron' }
    if (-not (Test-Path -LiteralPath (Join-Path $Root 'node_modules'))) {
        Stop-WithError 'Dependencies are not installed.' 'الاعتماديات غير مثبتة.' 'Run: .\Start-Blazma.ps1 -Install'
    }
    if (-not (Test-Path -LiteralPath $electronExe)) {
        Stop-WithError 'The Electron runtime is missing.' 'بيئة تشغيل Electron مفقودة.' 'Run: .\Start-Blazma.ps1 -Install'
    }
    Write-Ok 'Dependencies present'

    # 5. Launch
    if ($Dev) {
        Write-Step 'Starting development mode...'
        & $npm.Source run dev
        exit $LASTEXITCODE
    }
    if (-not $SkipBuild) {
        Write-Step 'Building...'
        & $npm.Source run build --silent
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError 'The build failed.' 'فشل بناء المشروع.' 'Run "npm run build" to see the full error.'
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Root 'dist\main\index.cjs'))) {
        Stop-WithError 'No build found.' 'لا توجد نسخة مبنية.' 'Run without -SkipBuild.'
    }
    Write-Ok 'Launching BLAZMA CYBER...'
    Start-Process -FilePath $electronExe -ArgumentList @("`"$Root`"") -WorkingDirectory $Root
}
finally {
    Pop-Location
}
