# Registry Analysis Module
# Analyzes registry artifacts for persistence mechanisms and other indicators

function Invoke-RegistryAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["registry"]
    
    Write-Host "`n=== Running Registry Analysis ===" -ForegroundColor Cyan
    
    # Define registry analysis plugins
    $plugins = @(
        @{
            Name = "windows.registry.hivelist"; 
            Description = "List registry hives"
        },
        @{
            Name = "windows.registry.printkey"; 
            Description = "Autorun keys (Run/RunOnce)";
            AdditionalArgs = "--key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'"
        },
        @{
            Name = "windows.registry.userassist"; 
            Description = "User activity in registry"
        }
        # Removed unsupported plugins: windows.registry.shimcache and windows.registry.amcache
    )
    
    # Execute each plugin
    foreach ($plugin in $plugins) {
        Write-Host "Running $($plugin.Name): $($plugin.Description)" -ForegroundColor Yellow
        
        # Fix for ternary operator
        $filenameSuffix = ""
        if ($plugin.AdditionalArgs) {
            $filenameSuffix = "_" + ($plugin.AdditionalArgs -replace '[^a-zA-Z0-9]', '_')
        }
        $outputFile = "$($plugin.Name)$filenameSuffix.txt"
        
        $output = Invoke-Volatility -Config $Config -Plugin $plugin.Name -OutputDir $outputDir -OutputFileName $outputFile -AdditionalArgs $plugin.AdditionalArgs
        
        if ($output) {
            # Fix for ternary operator
            $pluginKey = $plugin.Name
            if ($plugin.AdditionalArgs) {
                $pluginKey = "$($plugin.Name)_args"
            }
            
            Set-AnalysisResult -Config $Config -Category "registry" -Plugin $pluginKey -OutputFile $output
        }
    }
    
    # Extra persistence keys to check
    $persistenceKeys = @(
        "Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "Software\Microsoft\Windows\CurrentVersion\RunServices",
        "Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        "Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        "Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
        "Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
    )
    
    foreach ($key in $persistenceKeys) {
        $sanitizedKey = $key -replace '[\\]', '_' -replace '[\s]', '_'
        $outputFile = "windows.registry.printkey_$sanitizedKey.txt"
        $additionalArgs = "--key '$key'"
        
        Write-Host "Checking persistence key: $key" -ForegroundColor Yellow
        $output = Invoke-Volatility -Config $Config -Plugin "windows.registry.printkey" -OutputDir $outputDir -OutputFileName $outputFile -AdditionalArgs $additionalArgs
        
        if ($output) {
            Set-AnalysisResult -Config $Config -Category "registry" -Plugin "windows.registry.printkey_$sanitizedKey" -OutputFile $output
        }
    }
    
    # Analyze persistence mechanisms
    Find-PersistenceMechanisms -Config $Config
    
    # Generate HTML report
    Export-RegistryReport -Config $Config
    
    return $true
}

function Find-PersistenceMechanisms {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["registry"]
    
    # Paths to analyze
    $suspiciousPaths = @{
        # Executables in temp or download directories
        '\\Temp\\.*\.exe' = "Executable in Temp directory";
        '\\Downloads\\.*\.exe' = "Executable in Downloads directory";
        '\\AppData\\.*\.exe' = "Executable in AppData directory";
        
        # Suspicious locations and file types
        '\.scr$' = "Screen saver executable (potential malware)";
        '\.bat$' = "Batch file";
        '\.vbs$' = "VBScript file";
        '\.ps1$' = "PowerShell script";
        'powershell' = "PowerShell execution";
        'cmd\.exe' = "Command prompt";
        'wscript\.exe' = "Windows Script Host";
        'rundll32\.exe' = "RunDLL32";
        'regsvr32\.exe' = "RegSvr32 (COM registration)";
        'schtasks\.exe' = "Scheduled Tasks manipulation";
        'at\.exe' = "AT scheduled job";
        
        # Encoded commands
        '-enc' = "Encoded PowerShell command";
        '-encodedcommand' = "Encoded PowerShell command";
        '-encoded' = "Encoded command";
        
        # Network activity in autorun
        'http:' = "URL in autorun (possible dropper)";
        'https:' = "URL in autorun (possible dropper)";
        'ftp:' = "FTP in autorun (possible dropper)"
    }
    
    $persistenceReport = @()
    
    # Collect results from Run keys
    $runKeyFiles = $Config.AnalysisResults["registry"].Keys | Where-Object { $_ -match "printkey" }
    
    foreach ($keyFile in $runKeyFiles) {
        $keyData = Get-Content -Path $Config.AnalysisResults["registry"][$keyFile] -Raw
        
        # Extract registry key name from file
        $keyName = if ($keyFile -match "printkey_(.+)\.txt") { 
            $matches[1] -replace '_', '\' 
        } else { 
            "Unknown" 
        }
        
        # Look for registry values with paths
        $valueMatches = [regex]::Matches($keyData, '(\S+)\s+REG_\w+\s+(.+?)\r?\n')
        
        foreach ($match in $valueMatches) {
            $valueName = $match.Groups[1].Value.Trim()
            $valuePath = $match.Groups[2].Value.Trim()
            
            # Check for suspicious patterns
            $isSuspicious = $false
            $reason = ""
            
            foreach ($pattern in $suspiciousPaths.Keys) {
                if ($valuePath -match $pattern) {
                    $isSuspicious = $true
                    $reason += $suspiciousPaths[$pattern] + "; "
                }
            }
            
            # Add to report
            $persistenceReport += [PSCustomObject]@{
                KeyName = $keyName
                ValueName = $valueName
                Path = $valuePath
                IsSuspicious = $isSuspicious
                Reason = $reason.TrimEnd("; ")
            }
        }
    }
    
    # Generate report
    if ($persistenceReport.Count -gt 0) {
        $reportFile = Join-Path $outputDir "persistence_mechanisms.txt"
        $output = "Persistence Mechanisms Analysis`n"
        $output += "=============================`n`n"
        
        # Report suspicious entries first
        $suspiciousEntries = $persistenceReport | Where-Object { $_.IsSuspicious }
        if ($suspiciousEntries.Count -gt 0) {
            $output += "Suspicious Autorun Entries:`n"
            $output += "-------------------------`n"
            
            foreach ($entry in $suspiciousEntries) {
                $output += "Registry Key: $($entry.KeyName)`n"
                $output += "Value Name: $($entry.ValueName)`n"
                $output += "Path: $($entry.Path)`n"
                $output += "Reason: $($entry.Reason)`n`n"
            }
        }
        
        # List all persistence entries
        $output += "All Autorun Entries:`n"
        $output += "------------------`n"
        
        foreach ($entry in $persistenceReport) {
            $output += "Registry Key: $($entry.KeyName)`n"
            $output += "Value Name: $($entry.ValueName)`n"
            $output += "Path: $($entry.Path)`n"
            if ($entry.IsSuspicious) {
                $output += "*** SUSPICIOUS: $($entry.Reason) ***`n"
            }
            $output += "`n"
        }
        
        # Save report
        $output | Out-File -FilePath $reportFile -Encoding utf8
        Write-Host "Persistence mechanism analysis completed. See $reportFile for details." -ForegroundColor Green
        
        # Export as CSV for easier analysis
        $csvFile = Join-Path $outputDir "persistence_mechanisms.csv"
        $persistenceReport | Export-Csv -Path $csvFile -NoTypeInformation
    }
    else {
        Write-Host "No persistence mechanisms found." -ForegroundColor Yellow
    }
    
    # Analyze user activity from UserAssist if available
    if ($Config.AnalysisResults["registry"].ContainsKey("windows.registry.userassist")) {
        Analyze-UserActivity -Config $Config
    }
}

function Analyze-UserActivity {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["registry"]
    $userAssistFile = $Config.AnalysisResults["registry"]["windows.registry.userassist"]
    $userAssistContent = Get-Content -Path $userAssistFile -Raw
    
    # Extract user activity from UserAssist
    $activities = [regex]::Matches($userAssistContent, 'REG_BINARY\s+:\s+(.+?)\s+Count:\s+(\d+)\s+Focus:\s+(\d+)(?:\s+Time:\s+(.+?))?(?:\r?\n|$)')
    
    if ($activities.Count -gt 0) {
        $activityReport = @()
        
        foreach ($activity in $activities) {
            $path = $activity.Groups[1].Value.Trim()
            $count = $activity.Groups[2].Value.Trim()
            $focus = $activity.Groups[3].Value.Trim()
            
            # Fix for potential ternary issue
            $time = "Unknown"
            if ($activity.Groups.Count -gt 4) {
                $time = $activity.Groups[4].Value.Trim()
            }
            
            $activityReport += [PSCustomObject]@{
                Path = $path
                Count = $count
                Focus = $focus
                Time = $time
            }
        }
        
        # Sort by most recent activity
        $sortedActivities = $activityReport | Sort-Object -Property Time -Descending
        
        # Generate report
        $reportFile = Join-Path $outputDir "user_activity.txt"
        $output = "User Activity Analysis`n"
        $output += "====================`n`n"
        
        $output += "Recent User Activities:`n"
        $output += "---------------------`n"
        
        foreach ($activity in ($sortedActivities | Select-Object -First 20)) {
            $output += "Program: $($activity.Path)`n"
            $output += "Run Count: $($activity.Count)`n"
            $output += "Focus Count: $($activity.Focus)`n"
            $output += "Last Run Time: $($activity.Time)`n`n"
        }
        
        # Save report
        $output | Out-File -FilePath $reportFile -Encoding utf8
        Write-Host "User activity analysis completed. See $reportFile for details." -ForegroundColor Green
        
        # Export as CSV for easier analysis
        $csvFile = Join-Path $outputDir "user_activity.csv"
        $sortedActivities | Export-Csv -Path $csvFile -NoTypeInformation
    }
}

function Export-RegistryReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["registry"]
    $reportFile = Join-Path $outputDir "registry_analysis_report.html"
    
    # Start building HTML content
    $content = "<h2>Registry Analysis</h2>"
    
    # Add persistence mechanisms if found
    $persistenceFile = Join-Path $outputDir "persistence_mechanisms.txt"
    if (Test-Path $persistenceFile) {
        $persistenceContent = Get-Content -Path $persistenceFile -Raw
        $content += "<h3>Persistence Mechanisms</h3><div class='suspicious'><pre>$persistenceContent</pre></div>"
    }
    
    # Add user activity if found
    $userActivityFile = Join-Path $outputDir "user_activity.txt"
    if (Test-Path $userActivityFile) {
        $userActivityContent = Get-Content -Path $userActivityFile -Raw
        $content += "<h3>User Activity</h3><pre>$userActivityContent</pre>"
    }
    
    # Add userassist data if available
    if ($Config.AnalysisResults["registry"].ContainsKey("windows.registry.userassist")) {
        $userassistFile = $Config.AnalysisResults["registry"]["windows.registry.userassist"]
        $userassistContent = Get-Content -Path $userassistFile -Raw
        $content += "<h3>UserAssist Data</h3><pre>$userassistContent</pre>"
    }
    
    # Add run keys data if available
    $runKeyFiles = $Config.AnalysisResults["registry"].Keys | Where-Object { $_ -match "Run'" }
    foreach ($keyFile in $runKeyFiles) {
        $keyData = Get-Content -Path $Config.AnalysisResults["registry"][$keyFile] -Raw
        $keyName = if ($keyFile -match "windows\.registry\.printkey.*?--key\s+'([^']+)'") { $matches[1] } else { $keyFile }
        $content += "<h3>Registry Key: $keyName</h3><pre>$keyData</pre>"
    }
    
    # Generate the HTML report
    Export-HTMLReport -Config $Config -Title "Registry Analysis Report" -Content $content -OutputFile $reportFile
} 