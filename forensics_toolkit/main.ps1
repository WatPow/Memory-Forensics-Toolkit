#!/usr/bin/env pwsh

# ForensicToolkit - Main Script
# Author: Claude
# Description: Forensic Analysis Tool for Windows Memory Dumps using Volatility 3

# Import modules
. "$PSScriptRoot\core\config.ps1"
. "$PSScriptRoot\core\utils.ps1"
. "$PSScriptRoot\core\report.ps1"

function Show-Banner {
    Write-Host "`n`n=================================================" -ForegroundColor Cyan
    Write-Host "           MEMORY FORENSICS TOOLKIT" -ForegroundColor Cyan
    Write-Host "         Powered by Volatility 3" -ForegroundColor Cyan
    Write-Host "=================================================`n" -ForegroundColor Cyan
}

function Show-Menu {
    Write-Host "Please select an analysis category:" -ForegroundColor Yellow
    Write-Host "1. System Information" -ForegroundColor Green
    Write-Host "2. Process Analysis" -ForegroundColor Green
    Write-Host "3. DLLs and Modules" -ForegroundColor Green
    Write-Host "4. Handle Analysis" -ForegroundColor Green
    Write-Host "5. Memory/Malware Analysis" -ForegroundColor Green
    Write-Host "6. Network Analysis" -ForegroundColor Green
    Write-Host "7. File Analysis" -ForegroundColor Green
    Write-Host "8. Registry Analysis" -ForegroundColor Green
    Write-Host "9. User Activity" -ForegroundColor Green
    Write-Host "10. Run Full Analysis" -ForegroundColor Magenta
    Write-Host "11. Exit" -ForegroundColor Red
    Write-Host "`nEnter your choice: " -NoNewline -ForegroundColor Yellow
}

function Invoke-MainMenu {
    param (
        [string]$MemoryDump
    )
    
    if (-not $MemoryDump) {
        $MemoryDump = Read-Host "Please provide the path to the memory dump file"
    }
    
    if (-not (Test-Path $MemoryDump)) {
        Write-Error "Memory dump file not found at: $MemoryDump"
        exit
    }
    
    $config = Get-Configuration -MemoryDump $MemoryDump
    
    Show-Banner
    
    while ($true) {
        Show-Menu
        $choice = Read-Host
        
        switch ($choice) {
            "1" { . "$PSScriptRoot\modules\system_info\analyzer.ps1"; Invoke-SystemInfoAnalysis -Config $config }
            "2" { . "$PSScriptRoot\modules\processes\analyzer.ps1"; Invoke-ProcessAnalysis -Config $config }
            "3" { . "$PSScriptRoot\modules\modules\analyzer.ps1"; Invoke-ModulesAnalysis -Config $config }
            "4" { . "$PSScriptRoot\modules\handles\analyzer.ps1"; Invoke-HandleAnalysis -Config $config }
            "5" { . "$PSScriptRoot\modules\memory\analyzer.ps1"; Invoke-MemoryAnalysis -Config $config }
            "6" { . "$PSScriptRoot\modules\network\analyzer.ps1"; Invoke-NetworkAnalysis -Config $config }
            "7" { . "$PSScriptRoot\modules\filesystem\analyzer.ps1"; Invoke-FileAnalysis -Config $config }
            "8" { . "$PSScriptRoot\modules\registry\analyzer.ps1"; Invoke-RegistryAnalysis -Config $config }
            "9" { . "$PSScriptRoot\modules\user_activity\analyzer.ps1"; Invoke-UserActivityAnalysis -Config $config }
            "10" { Invoke-FullAnalysis -Config $config }
            "11" { Write-Host "Exiting..."; exit }
            default { Write-Host "Invalid choice. Please try again." -ForegroundColor Red }
        }
    }
}

function Invoke-FullAnalysis {
    param (
        [PSCustomObject]$Config
    )
    
    Write-Host "`nRunning full forensic analysis..." -ForegroundColor Cyan
    
    . "$PSScriptRoot\modules\system_info\analyzer.ps1"; Invoke-SystemInfoAnalysis -Config $Config
    . "$PSScriptRoot\modules\processes\analyzer.ps1"; Invoke-ProcessAnalysis -Config $Config
    . "$PSScriptRoot\modules\modules\analyzer.ps1"; Invoke-ModulesAnalysis -Config $Config
    . "$PSScriptRoot\modules\handles\analyzer.ps1"; Invoke-HandleAnalysis -Config $Config
    . "$PSScriptRoot\modules\memory\analyzer.ps1"; Invoke-MemoryAnalysis -Config $Config
    . "$PSScriptRoot\modules\network\analyzer.ps1"; Invoke-NetworkAnalysis -Config $Config
    . "$PSScriptRoot\modules\filesystem\analyzer.ps1"; Invoke-FileAnalysis -Config $Config
    . "$PSScriptRoot\modules\registry\analyzer.ps1"; Invoke-RegistryAnalysis -Config $Config
    . "$PSScriptRoot\modules\user_activity\analyzer.ps1"; Invoke-UserActivityAnalysis -Config $Config
    
    Export-FullReport -Config $Config
}

# Check parameters
if ($args.Count -gt 0) {
    Invoke-MainMenu -MemoryDump $args[0]
} else {
    Invoke-MainMenu
} 