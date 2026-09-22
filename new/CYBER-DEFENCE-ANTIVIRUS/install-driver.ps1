# Windows minifilter driver installation script
# Run with admin privileges: powershell -ExecutionPolicy Bypass -File install-driver.ps1

param(
    [ValidateSet('install', 'uninstall', 'status', 'debug')]
    [string]$Action = 'status',
    
    [string]$DriverPath = ".\av-kernel-windows",
    
    [switch]$Force
)

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges"
    exit 1
}

function Test-TestSigningEnabled {
    $bcdEditOutput = bcdedit /enum
    return $bcdEditOutput -contains "testsigning                  Yes"
}

function Install-Driver {
    Write-Host "=== Installing CyberShield Minifilter Driver ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Validate files exist
    $sysFile = Join-Path $DriverPath "build\Release\minifilter.sys"
    $infFile = Join-Path $DriverPath "minifilter.inf"
    
    if (-not (Test-Path $sysFile)) {
        Write-Error "Driver file not found: $sysFile"
        Write-Host "Please run: .\build-driver.bat test-sign"
        return $false
    }
    
    if (-not (Test-Path $infFile)) {
        Write-Error "INF file not found: $infFile"
        return $false
    }
    
    # Check for test signing if using self-signed certs
    Write-Host "Checking test signing status..."
    if (-not (Test-TestSigningEnabled)) {
        Write-Warning "Test signing is not enabled"
        Write-Host "Enable with: bcdedit /set testsigning on"
        Write-Host "Note: This requires a reboot"
        
        if (-not $Force) {
            Write-Host ""
            $response = Read-Host "Enable test signing and reboot now? (y/n)"
            if ($response -eq 'y') {
                Write-Host "Enabling test signing..."
                bcdedit /set testsigning on
                Write-Host "Reboot required. Please restart Windows."
                exit 0
            } else {
                Write-Warning "Test signing not enabled. Installation may fail."
            }
        }
    } else {
        Write-Host "[OK] Test signing is enabled" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Installing driver..."
    
    # Copy driver to system drivers directory
    $sysDir = "$env:SystemRoot\System32\drivers"
    Copy-Item $sysFile "$sysDir\minifilter.sys" -Force
    Copy-Item $infFile "$sysDir\minifilter.inf" -Force
    
    Write-Host "[OK] Files copied to $sysDir" -ForegroundColor Green
    
    # Register driver
    Write-Host "Registering driver..."
    $infPath = Resolve-Path $infFile
    $regResult = pnputil /add-driver $infPath /install
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Driver registration failed"
        return $false
    }
    
    Write-Host "[OK] Driver registered" -ForegroundColor Green
    
    # Start driver
    Write-Host "Starting driver..."
    $startResult = sc.exe start AVFilter
    
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 2) {  # 2 = already running
        Write-Host "[OK] Driver started" -ForegroundColor Green
    } else {
        Write-Warning "Driver may not have started. Check status with 'Get-Service AVFilter'"
    }
    
    Write-Host ""
    Write-Host "=== Installation Complete ===" -ForegroundColor Green
    Write-Host ""
    
    # Verify installation
    Get-DriverStatus
    
    return $true
}

function Uninstall-Driver {
    Write-Host "=== Uninstalling CyberShield Minifilter Driver ===" -ForegroundColor Yellow
    Write-Host ""
    
    # Stop driver
    Write-Host "Stopping driver..."
    sc.exe stop AVFilter | Out-Null
    Start-Sleep -Seconds 2
    
    # Remove driver registration
    Write-Host "Removing driver registration..."
    $infFile = Join-Path $DriverPath "minifilter.inf"
    
    if (Test-Path $infFile) {
        $infPath = Resolve-Path $infFile
        pnputil /delete-driver $(Split-Path -Leaf $infPath) /uninstall 2>/dev/null
    }
    
    # Remove driver file
    Write-Host "Removing driver files..."
    Remove-Item "$env:SystemRoot\System32\drivers\minifilter.sys" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\System32\drivers\minifilter.inf" -Force -ErrorAction SilentlyContinue
    
    Write-Host "[OK] Driver uninstalled" -ForegroundColor Green
    Write-Host ""
}

function Get-DriverStatus {
    Write-Host "=== Driver Status ===" -ForegroundColor Cyan
    Write-Host ""
    
    $service = Get-Service -Name AVFilter -ErrorAction SilentlyContinue
    
    if ($null -eq $service) {
        Write-Host "Status: NOT INSTALLED" -ForegroundColor Red
        return
    }
    
    $statusColor = if ($service.Status -eq "Running") { "Green" } else { "Yellow" }
    Write-Host "Service Name: $($service.Name)"
    Write-Host "Display Name: $($service.DisplayName)"
    Write-Host "Status: $($service.Status)" -ForegroundColor $statusColor
    Write-Host "Start Type: $($service.StartType)"
    Write-Host ""
    
    # Check device in Device Manager
    Write-Host "Device Manager entries:"
    $devices = Get-PnpDevice -FriendlyName "*AVFilter*" -ErrorAction SilentlyContinue
    
    if ($devices.Count -eq 0) {
        Write-Host "  (No devices found)" -ForegroundColor Gray
    } else {
        foreach ($device in $devices) {
            Write-Host "  - $($device.FriendlyName): $($device.Status)"
        }
    }
}

function Show-DebugInfo {
    Write-Host "=== Debug Information ===" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "System Information:"
    $osVersion = [System.Environment]::OSVersion
    Write-Host "  OS: $($osVersion.VersionString)"
    Write-Host "  Architecture: $([System.Environment]::Is64BitOperatingSystem ? 'x64' : 'x86')"
    Write-Host ""
    
    Write-Host "Driver Configuration:"
    Write-Host "  Driver Path: $(Join-Path $DriverPath 'minifilter.sys')"
    Write-Host "  INF Path: $(Join-Path $DriverPath 'minifilter.inf')"
    Write-Host "  System Driver Path: $env:SystemRoot\System32\drivers"
    Write-Host ""
    
    Write-Host "Registry Configuration:"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AVFilter"
    if (Test-Path $regPath) {
        $regKey = Get-Item $regPath
        Write-Host "  Registry Key: $regPath (EXISTS)"
        
        # Show relevant values
        foreach ($value in @('Type', 'Start', 'DisplayName')) {
            $val = Get-ItemProperty $regPath -Name $value -ErrorAction SilentlyContinue
            if ($null -ne $val) {
                Write-Host "    $value: $($val.$value)"
            }
        }
    } else {
        Write-Host "  Registry Key: $regPath (NOT FOUND)"
    }
    
    Write-Host ""
    Write-Host "Event Log (Last 5 entries):"
    $events = Get-EventLog -LogName System -Source AVFilter -Newest 5 -ErrorAction SilentlyContinue
    
    if ($null -eq $events) {
        Write-Host "  (No events found)" -ForegroundColor Gray
    } else {
        foreach ($event in $events) {
            Write-Host "  [$($event.TimeGenerated)] $($event.Message)"
        }
    }
}

# Main switch
switch ($Action) {
    'install' {
        Install-Driver
    }
    'uninstall' {
        $confirm = Read-Host "Are you sure you want to uninstall the driver? (yes/no)"
        if ($confirm -eq 'yes') {
            Uninstall-Driver
        } else {
            Write-Host "Uninstall cancelled."
        }
    }
    'status' {
        Get-DriverStatus
    }
    'debug' {
        Show-DebugInfo
    }
    default {
        Get-DriverStatus
    }
}

Write-Host ""
