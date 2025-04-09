# System Information Analysis Module

function Invoke-SystemInfoAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["system_info"]
    
    Write-Host "`n=== Running System Information Analysis ===" -ForegroundColor Cyan
    
    # Run windows.info plugin
    $infoOutput = Invoke-Volatility -Config $Config -Plugin "windows.info" -OutputDir $outputDir -OutputFileName "windows.info.txt"
    
    if ($infoOutput) {
        # Store result in configuration
        Set-AnalysisResult -Config $Config -Category "system_info" -Plugin "windows.info" -OutputFile $infoOutput
        
        # Parse key information
        $infoContent = Get-Content -Path $infoOutput -Raw
        
        # Extract key information using regex
        $osVersion = if ($infoContent -match 'NtMajorVersion\s+:\s+(\d+)') { $matches[1] } else { "Unknown" }
        $minorVersion = if ($infoContent -match 'NtMinorVersion\s+:\s+(\d+)') { $matches[1] } else { "Unknown" }
        $buildNumber = if ($infoContent -match 'NtBuildNumber\s+:\s+(\d+)') { $matches[1] } else { "Unknown" }
        $kernelBase = if ($infoContent -match 'KernelBase\s+:\s+(0x\w+)') { $matches[1] } else { "Unknown" }
        $ntBuildLab = if ($infoContent -match 'NtBuildLab\s+:\s+(.+)$') { $matches[1].Trim() } else { "Unknown" }
        
        # Format system info summary
        $summary = @"
System Information Summary:
--------------------------
OS Version: Windows $osVersion.$minorVersion (Build $buildNumber)
Kernel Base: $kernelBase
Build Lab: $ntBuildLab

"@
        
        # Display summary
        Write-Host $summary -ForegroundColor Green
        
        # Save summary
        $summaryFile = Join-Path $outputDir "system_info_summary.txt"
        $summary | Out-File -FilePath $summaryFile -Encoding utf8
        
        # Create HTML report
        $htmlContent = @"
<h2>System Information Summary</h2>
<table>
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>OS Version</td><td>Windows $osVersion.$minorVersion (Build $buildNumber)</td></tr>
    <tr><td>Kernel Base</td><td>$kernelBase</td></tr>
    <tr><td>Build Lab</td><td>$ntBuildLab</td></tr>
</table>

<h3>Full System Information</h3>
<pre>$infoContent</pre>
"@
        
        $htmlFile = Join-Path $outputDir "system_info_report.html"
        Export-HTMLReport -Config $Config -Title "System Information Analysis" -Content $htmlContent -OutputFile $htmlFile
        
        return $true
    } else {
        Write-Host "Failed to retrieve system information." -ForegroundColor Red
        return $false
    }
} 