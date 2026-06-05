$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Main = Join-Path $ProjectRoot "main.py"
$Requirements = Join-Path $ProjectRoot "requirements.txt"
$RequiredImports = @(
    "argon2",
    "cryptography",
    "pyperclip",
    "googleapiclient",
    "google.auth",
    "google_auth_oauthlib",
    "rich",
    "tqdm"
)

function Show-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-WithProgress {
    param(
        [string]$Title,
        [string]$Activity,
        [string]$FilePath,
        [string[]]$Arguments
    )

    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $ProjectRoot -NoNewWindow -PassThru
    $percent = 0

    while (-not $process.HasExited) {
        $percent = ($percent + 7) % 100
        Write-Progress -Activity $Title -Status $Activity -PercentComplete $percent
        Start-Sleep -Milliseconds 180
        $process.Refresh()
    }

    Write-Progress -Activity $Title -Completed

    if ($process.ExitCode -ne 0) {
        throw "$Title failed with exit code $($process.ExitCode)."
    }
}

function Invoke-WithLoadingScreen {
    param(
        [string]$Title,
        [string]$Message,
        [string]$FilePath,
        [string[]]$Arguments
    )

    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $ProjectRoot -NoNewWindow -PassThru
    $frames = @("|", "/", "-", "\")
    $tick = 0

    while (-not $process.HasExited) {
        Clear-Host
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor DarkCyan
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  $($frames[$tick % $frames.Count]) $Message" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  First launch can take a minute. Please keep this window open." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor DarkCyan
        Start-Sleep -Milliseconds 180
        $tick++
        $process.Refresh()
    }

    Clear-Host
    if ($process.ExitCode -ne 0) {
        throw "$Title failed with exit code $($process.ExitCode)."
    }
    Write-Host "$Title complete." -ForegroundColor Green
}

function Get-SystemPython {
    $commands = @("py", "python")
    foreach ($command in $commands) {
        $cmd = Get-Command $command -ErrorAction SilentlyContinue
        if ($cmd) {
            if ($command -eq "py") {
                return @{ FilePath = "py"; Args = @("-3") }
            }
            return @{ FilePath = $cmd.Source; Args = @() }
        }
    }
    return $null
}

function Install-PythonIfMissing {
    $python = Get-SystemPython
    if ($python) {
        return $python
    }

    Show-Step "Python was not found. Checking for winget installer"
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "Python is not installed and winget is not available. Install Python 3.11+ from https://www.python.org/downloads/windows/ and rerun .\run.ps1."
    }

    Write-Host "Installing Python 3.12 with winget. A system installer window may ask for confirmation."
    Invoke-WithProgress `
        -Title "Installing Python" `
        -Activity "Downloading and installing Python 3.12" `
        -FilePath "winget" `
        -Arguments @("install", "-e", "--id", "Python.Python.3.12", "--accept-package-agreements", "--accept-source-agreements")

    $python = Get-SystemPython
    if (-not $python) {
        throw "Python installation finished, but Python is not visible in this terminal yet. Close and reopen PowerShell, then rerun .\run.ps1."
    }

    return $python
}

function Test-RequiredLibraries {
    param([string]$PythonPath)

    $code = @"
import importlib.util
missing = [name for name in $($RequiredImports | ConvertTo-Json -Compress) if importlib.util.find_spec(name) is None]
raise SystemExit(1 if missing else 0)
"@
    & $PythonPath -c $code
    return ($LASTEXITCODE -eq 0)
}

function Install-RequirementsWithTqdm {
    param([string]$PythonPath)

    & $PythonPath -m pip install --disable-pip-version-check --no-warn-script-location "tqdm>=4.66.0"
    if ($LASTEXITCODE -ne 0) {
        throw "Installing tqdm bootstrap dependency failed."
    }

    $installer = @'
from pathlib import Path
import subprocess
import sys
from tqdm import tqdm

requirements = [
    line.strip()
    for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]

for requirement in tqdm(requirements, desc="Installing libraries", unit="pkg", dynamic_ncols=True):
    subprocess.check_call([
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-warn-script-location",
        requirement,
    ])
'@
    & $PythonPath -c $installer $Requirements
    if ($LASTEXITCODE -ne 0) {
        throw "Installing requirements failed."
    }
}

Clear-Host
Write-Host "Password Manager launcher" -ForegroundColor Green
Write-Host "Preparing the local runtime. This may take a moment on first launch."

Show-Step "Checking Python installation"
$SystemPython = Install-PythonIfMissing

if (-not (Test-Path $VenvPython)) {
    Show-Step "Creating virtual environment"
    $venvArgs = @($SystemPython.Args + @("-m", "venv", ".venv"))
    Invoke-WithLoadingScreen `
        -Title "Creating virtual environment" `
        -Message "Building .venv in the project folder..." `
        -FilePath $SystemPython.FilePath `
        -Arguments $venvArgs
}

Show-Step "Checking required libraries"
if (-not (Test-RequiredLibraries -PythonPath $VenvPython)) {
    Show-Step "Installing required libraries"
    Install-RequirementsWithTqdm -PythonPath $VenvPython
} else {
    Write-Host "All required libraries are already installed." -ForegroundColor Green
}

Show-Step "Starting Password Manager"
& $VenvPython $Main
