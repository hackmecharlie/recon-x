# RECON-X | setup_windows.ps1
# Description: Windows setup helper for RECON-X
# Usage: .\setup_windows.ps1

param(
    [switch]$Force
)

function Write-Info([string]$text) { Write-Host "[INFO]  $text" -ForegroundColor Cyan }
function Write-Ok([string]$text) { Write-Host "[OK]    $text" -ForegroundColor Green }
function Write-Warn([string]$text) { Write-Host "[WARN]  $text" -ForegroundColor Yellow }
function Write-ErrorMsg([string]$text) { Write-Host "[ERROR] $text" -ForegroundColor Red }

Write-Info "RECON-X Windows setup"
Write-Info "========================"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $python) {
    Write-ErrorMsg "Python 3.10+ not found. Install Python and make sure 'python' or 'py' is available in PATH."
    exit 1
}

$pythonExe = $python.Source
$versionText = & $pythonExe --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Unable to run Python: $versionText"
    exit 1
}

if ($versionText -match 'Python\s+(\d+)\.(\d+)\.(\d+)') {
    $major = [int]$matches[1]
    $minor = [int]$matches[2]
    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
        Write-ErrorMsg "Python 3.10+ required. Found: $versionText"
        exit 1
    }
    Write-Ok "Python version: $versionText"
} else {
    Write-Warn "Could not parse Python version from '$versionText'"
}

function Check-Binary($name) {
    if (Get-Command $name -ErrorAction SilentlyContinue) {
        Write-Ok "$name found"
        return $true
    }
    Write-Warn "$name not found"
    return $false
}

Check-Binary nmap | Out-Null

$venvDir = Join-Path -Path $PSScriptRoot -ChildPath '.venv'
if (-not (Test-Path $venvDir)) {
    Write-Info "Creating virtual environment at '$venvDir'"
    & $pythonExe -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorMsg "Failed to create virtual environment."
        exit 1
    }
    Write-Ok "Virtual environment created"
} else {
    Write-Ok "Virtual environment already exists"
}

$pythonVenv = Join-Path -Path $venvDir -ChildPath 'Scripts\python.exe'
$pipVenv = Join-Path -Path $venvDir -ChildPath 'Scripts\pip.exe'
if (-not (Test-Path $pythonVenv)) {
    Write-ErrorMsg "Virtual environment python executable not found at $pythonVenv"
    exit 1
}

Write-Info "Upgrading pip, setuptools, and wheel"
& $pythonVenv -m pip install --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) {
    Write-Warn "pip upgrade failed; continuing anyway."
}

Write-Info "Installing Python dependencies from requirements.txt"
& $pipVenv install -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Failed to install Python requirements."
    exit 1
}

Write-Info "Installing RECON-X in editable mode"
& $pipVenv install -e $PSScriptRoot
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Editable install failed."
    exit 1
}

Write-Info "Installing Playwright Chromium"
& $pythonVenv -m playwright install chromium
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Playwright Chromium install failed. You may need to install it manually."
}

Write-Host "`nPost-setup verification" -ForegroundColor Cyan
Write-Host "----------------------" -ForegroundColor Cyan
Check-Binary recon-x | Out-Null
Check-Binary nmap | Out-Null

& $pythonVenv -c "import importlib; mods=['jinja2','impacket','nmap','playwright']; missing=[m for m in mods if importlib.util.find_spec(m) is None]; print('Missing:'+(','.join(missing)) if missing else 'OK')"

Write-Ok "Setup complete"
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  .\run_windows.bat --targets 192.168.1.100 --profile quick --yes"
Write-Host "  .\run_windows.bat --help"
