# Modules Analysis Module
# Analyzes loaded DLLs and drivers

function Invoke-ModulesAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["modules"]
    
    Write-Host "`n=== Running DLLs and Modules Analysis ===" -ForegroundColor Cyan
    
    # Define plugins related to modules and DLLs
    $plugins = @(
        @{Name = "windows.dlllist"; Description = "List loaded DLLs for each process"},
        @{Name = "windows.modules"; Description = "List loaded kernel modules"},
        @{Name = "windows.driverscan"; Description = "Scan for driver objects"}
    )
    
    # Execute each plugin
    foreach ($plugin in $plugins) {
        Write-Host "Running $($plugin.Name): $($plugin.Description)" -ForegroundColor Yellow
        $outputFile = "$($plugin.Name).txt"
        $output = Invoke-Volatility -Config $Config -Plugin $plugin.Name -OutputDir $outputDir -OutputFileName $outputFile
        
        if ($output) {
            Set-AnalysisResult -Config $Config -Category "modules" -Plugin $plugin.Name -OutputFile $output
        }
    }
    
    # Analyze DLLs and drivers for suspicious entries
    Find-SuspiciousModules -Config $Config
    
    # Generate HTML report
    Export-ModulesReport -Config $Config
    
    return $true
}

function Find-SuspiciousModules {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["modules"]
    
    # Check if the required data exists
    $hasDllData = $Config.AnalysisResults.ContainsKey("modules") -and 
                  $Config.AnalysisResults["modules"].ContainsKey("windows.dlllist")
    
    $hasDriverData = $Config.AnalysisResults.ContainsKey("modules") -and 
                    $Config.AnalysisResults["modules"].ContainsKey("windows.driverscan")
    
    if (-not ($hasDllData -or $hasDriverData)) {
        Write-Host "No module or driver data available for analysis." -ForegroundColor Yellow
        return
    }
    
    # Define suspicious patterns
    $suspiciousPatterns = @{
        # Suspicious paths
        '\\Temp\\' = "Module loaded from Temp directory";
        '\\AppData\\Local\\Temp\\' = "Module loaded from user Temp directory";
        '\\Downloads\\' = "Module loaded from Downloads directory";
        '\\Windows\\System32\\.*\\.*\.dll' = "DLL in subfolder of System32 (unusual)";
        '\\Users\\.*\\' = "Module loaded from user directory";
        
        # Suspicious naming patterns
        '^[a-z]{1,4}\.dll$' = "Suspiciously short or generic name";
        '^[0-9]+\.dll$' = "Numeric-only DLL name";
        '^\w{8}\.dll$' = "Random-looking 8-character DLL name";
        'svchost[^\\].*\.dll' = "Possible svchost masquerading";
        
        # Known malicious DLLs or patterns
        'winsec\.dll' = "Known malicious DLL";
        'cryptbase\.dll' = "Potentially hijacked crypto DLL";
        'wininet\.dll' = "Potentially hijacked networking DLL";
        'secur32\.dll' = "Potentially hijacked security DLL";
        'ntdll\.dll\.mui' = "Unusual ntdll variant";
        
        # Unsigned drivers
        'NOT_SIGNED' = "Unsigned driver";
        'UNSIGNED' = "Unsigned driver"
    }
    
    $suspiciousDlls = @()
    $suspiciousDrivers = @()
    $dllStats = @{}
    $driverStats = @{}
    
    # Process DLL data if available
    if ($hasDllData) {
        $dllListFile = $Config.AnalysisResults["modules"]["windows.dlllist"]
        $dllContent = Get-Content -Path $dllListFile
        
        $currentProcess = ""
        $currentPID = ""
        
        foreach ($line in $dllContent) {
            # Extract process information
            if ($line -match '^\s*(\S+)\s+pid:\s+(\d+)') {
                $currentProcess = $matches[1]
                $currentPID = $matches[2]
                continue
            }
            
            # Extract DLL path
            if ($line -match '^\s*0x\w+\s+0x\w+\s+(\S.*)$') {
                $dllPath = $matches[1].Trim()
                
                # Get base DLL name
                $dllName = if ($dllPath -match '\\([^\\]+)$') { $matches[1] } else { $dllPath }
                
                # Count DLLs
                if (-not $dllStats.ContainsKey($dllName)) {
                    $dllStats[$dllName] = 0
                }
                $dllStats[$dllName]++
                
                # Check for suspicious patterns
                $isSuspicious = $false
                $reasons = @()
                
                foreach ($pattern in $suspiciousPatterns.Keys) {
                    if ($dllPath -match $pattern -or $dllName -match $pattern) {
                        $isSuspicious = $true
                        $reasons += $suspiciousPatterns[$pattern]
                    }
                }
                
                # Add if suspicious
                if ($isSuspicious) {
                    $suspiciousDlls += [PSCustomObject]@{
                        Process = $currentProcess
                        PID = $currentPID
                        DLL = $dllPath
                        Name = $dllName
                        Reasons = $reasons -join ", "
                    }
                }
            }
        }
    }
    
    # Process driver data if available
    if ($hasDriverData) {
        $driverFile = $Config.AnalysisResults["modules"]["windows.driverscan"]
        $driverContent = Get-Content -Path $driverFile
        
        # Skip header
        for ($i = 1; $i -lt $driverContent.Count; $i++) {
            $line = $driverContent[$i]
            if ($line -notmatch '\S') { continue }
            
            # Extract driver information - regex might need adjustment based on actual output
            if ($line -match '0x\w+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S.*)$') {
                $driverName = $matches[1]
                $driverStart = $matches[2]
                $driverSize = $matches[3]
                $driverService = $matches[4].Trim()
                
                # Count driver names
                if (-not $driverStats.ContainsKey($driverName)) {
                    $driverStats[$driverName] = 0
                }
                $driverStats[$driverName]++
                
                # Check for suspicious patterns
                $isSuspicious = $false
                $reasons = @()
                
                foreach ($pattern in $suspiciousPatterns.Keys) {
                    if ($driverName -match $pattern -or $driverService -match $pattern) {
                        $isSuspicious = $true
                        $reasons += $suspiciousPatterns[$pattern]
                    }
                }
                
                # Check for suspicious start types
                if ($driverStart -eq "0" -or $driverStart -eq "1") {
                    $isSuspicious = $true
                    $reasons += "Boot or system start driver (high privilege)"
                }
                
                # Add if suspicious
                if ($isSuspicious) {
                    $suspiciousDrivers += [PSCustomObject]@{
                        Name = $driverName
                        StartType = $driverStart
                        Size = $driverSize
                        Service = $driverService
                        Reasons = $reasons -join ", "
                    }
                }
            }
        }
    }
    
    # Generate report
    $reportFile = Join-Path $outputDir "suspicious_modules.txt"
    $output = "Suspicious Modules and Drivers Report`n"
    $output += "=================================`n`n"
    
    # Report suspicious DLLs
    if ($suspiciousDlls.Count -gt 0) {
        $output += "Suspicious DLLs:`n"
        $output += "---------------`n"
        
        foreach ($dll in ($suspiciousDlls | Sort-Object -Property Process)) {
            $output += "Process: $($dll.Process) (PID: $($dll.PID))`n"
            $output += "DLL: $($dll.DLL)`n"
            $output += "Reasons: $($dll.Reasons)`n`n"
        }
    } else {
        $output += "No overtly suspicious DLLs detected.`n`n"
    }
    
    # Report suspicious drivers
    if ($suspiciousDrivers.Count -gt 0) {
        $output += "Suspicious Drivers:`n"
        $output += "-----------------`n"
        
        foreach ($driver in $suspiciousDrivers) {
            $output += "Driver: $($driver.Name)`n"
            $output += "Service: $($driver.Service)`n"
            $output += "Start Type: $($driver.StartType)`n"
            $output += "Size: $($driver.Size) bytes`n"
            $output += "Reasons: $($driver.Reasons)`n`n"
        }
    } else {
        $output += "No overtly suspicious drivers detected.`n`n"
    }
    
    # Add statistics
    $output += "DLL Statistics:`n"
    $output += "--------------`n"
    $output += "Total unique DLLs: $($dllStats.Count)`n`n"
    
    $output += "Most Common DLLs:`n"
    foreach ($dll in ($dllStats.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10)) {
        $output += "  $($dll.Key): $($dll.Value) instances`n"
    }
    $output += "`n"
    
    $output += "Driver Statistics:`n"
    $output += "----------------`n"
    $output += "Total unique drivers: $($driverStats.Count)`n"
    
    # Save report
    $output | Out-File -FilePath $reportFile -Encoding utf8
    Write-Host "Module analysis completed. See $reportFile for details." -ForegroundColor Green
    
    # Export as CSV for easier analysis
    if ($suspiciousDlls.Count -gt 0) {
        $csvFile = Join-Path $outputDir "suspicious_dlls.csv"
        $suspiciousDlls | Export-Csv -Path $csvFile -NoTypeInformation
    }
    
    if ($suspiciousDrivers.Count -gt 0) {
        $csvFile = Join-Path $outputDir "suspicious_drivers.csv"
        $suspiciousDrivers | Export-Csv -Path $csvFile -NoTypeInformation
    }
}

function Export-ModulesReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["modules"]
    $reportFile = Join-Path $outputDir "modules_analysis_report.html"
    
    # Start building HTML content
    $content = "<h2>DLLs and Modules Analysis</h2>"
    
    # Add suspicious modules if found
    $suspiciousFile = Join-Path $outputDir "suspicious_modules.txt"
    if (Test-Path $suspiciousFile) {
        $suspiciousContent = Get-Content -Path $suspiciousFile -Raw
        $content += "<h3>Suspicious Modules and Drivers</h3><div class='suspicious'><pre>$suspiciousContent</pre></div>"
    }
    
    # Add modules data if available
    if ($Config.AnalysisResults["modules"].ContainsKey("windows.modules")) {
        $modulesFile = $Config.AnalysisResults["modules"]["windows.modules"]
        $modulesContent = Get-Content -Path $modulesFile -Raw
        $content += "<h3>Kernel Modules</h3><pre>$modulesContent</pre>"
    }
    
    # Add drivers data if available
    if ($Config.AnalysisResults["modules"].ContainsKey("windows.driverscan")) {
        $driversFile = $Config.AnalysisResults["modules"]["windows.driverscan"]
        $driversContent = Get-Content -Path $driversFile -Raw
        $content += "<h3>Driver Objects</h3><pre>$driversContent</pre>"
    }
    
    # Generate the HTML report
    Export-HTMLReport -Config $Config -Title "DLLs and Modules Analysis Report" -Content $content -OutputFile $reportFile
} 