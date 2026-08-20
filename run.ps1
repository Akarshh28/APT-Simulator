<#
.SYNOPSIS
    APT Simulator - Windows PowerShell Launcher
.DESCRIPTION
    Starts all backend services (HES, MDMS, Detector) and the React Dashboard.
    Uses the in-process event bus instead of Mosquitto.
.NOTES
    Run from the project root: .\run.ps1
#>

param(
    [switch]$Install,
    [switch]$HesOnly,
    [switch]$MdmsOnly,
    [switch]$Test
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

Write-Host ""
Write-Host "  ==============================================" -ForegroundColor Cyan
Write-Host "       APT Simulator - Smart Grid Security      " -ForegroundColor Cyan
Write-Host "            C3iHub, IIT Kanpur                  " -ForegroundColor Cyan
Write-Host "  ==============================================" -ForegroundColor Cyan
Write-Host ""

# Ensure data directories exist
New-Item -ItemType Directory -Force -Path "$ProjectRoot\data" | Out-Null
New-Item -ItemType Directory -Force -Path "$ProjectRoot\data\baseline" | Out-Null

if ($Install) {
    Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
    pip install -r "$ProjectRoot\requirements.txt"
    Write-Host "[+] Dependencies installed." -ForegroundColor Green
    exit 0
}

$env:PYTHONPATH = $ProjectRoot

if ($Test) {
    Write-Host "[*] Running verification tests..." -ForegroundColor Yellow
    python -m pytest "$ProjectRoot\tests" -v
    exit $LASTEXITCODE
}

if ($HesOnly) {
    Write-Host "[*] Starting HES service on port 8001..." -ForegroundColor Yellow
    python -m uvicorn hes.main:app --host 0.0.0.0 --port 8001 --reload
    exit 0
}

if ($MdmsOnly) {
    Write-Host "[*] Starting MDMS service on port 8002..." -ForegroundColor Yellow
    python -m uvicorn mdms.main:app --host 0.0.0.0 --port 8002 --reload
    exit 0
}

Write-Host "[*] Starting all services..." -ForegroundColor Yellow
Write-Host "    MDMS      -> http://localhost:8002" -ForegroundColor Gray
Write-Host "    Detector  -> http://localhost:8003" -ForegroundColor Gray
Write-Host "    Dashboard -> http://localhost:3000" -ForegroundColor Gray
Write-Host "    HES       -> http://localhost:8001" -ForegroundColor Gray
Write-Host ""

$mdmsJob = Start-Job -ScriptBlock {
    Set-Location $using:ProjectRoot
    $env:PYTHONPATH = $using:ProjectRoot
    python -m uvicorn mdms.main:app --host 0.0.0.0 --port 8002
}
Write-Host "[+] MDMS started" -ForegroundColor Green

$detectorJob = Start-Job -ScriptBlock {
    Set-Location $using:ProjectRoot
    $env:PYTHONPATH = $using:ProjectRoot
    python -m uvicorn detector.main:app --host 0.0.0.0 --port 8003
}
Write-Host "[+] Detector started" -ForegroundColor Green

$dashboardJob = Start-Job -ScriptBlock {
    Set-Location "$using:ProjectRoot\dashboard"
    npm run dev
}
Write-Host "[+] Dashboard started" -ForegroundColor Green

Start-Sleep -Seconds 3

Write-Host "[+] Starting HES (foreground)..." -ForegroundColor Green
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Open the Dashboard at: http://localhost:3000" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop all services." -ForegroundColor DarkGray
Write-Host ""

try {
    python -m uvicorn hes.main:app --host 0.0.0.0 --port 8001
}
finally {
    Write-Host ""
    Write-Host "[*] Stopping services..." -ForegroundColor Yellow
    Stop-Job $mdmsJob, $detectorJob, $dashboardJob -ErrorAction SilentlyContinue
    Remove-Job $mdmsJob, $detectorJob, $dashboardJob -Force -ErrorAction SilentlyContinue
    Write-Host "[+] All services stopped." -ForegroundColor Green
}
