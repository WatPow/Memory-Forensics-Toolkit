# Handles Analysis Module
# Analyzes process handles to files, registry, etc.

function Invoke-HandleAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["handles"]
    
    Write-Host "`n=== Running Handles Analysis ===" -ForegroundColor Cyan
    
    # Define handles plugin
    $plugins = @(
        @{Name = "windows.handles"; Description = "Process handles to files, registry keys, etc."}
    )
    
    # Execute the plugin
    foreach ($plugin in $plugins) {
        Write-Host "Running $($plugin.Name): $($plugin.Description)" -ForegroundColor Yellow
        $outputFile = "$($plugin.Name).txt"
        $output = Invoke-Volatility -Config $Config -Plugin $plugin.Name -OutputDir $outputDir -OutputFileName $outputFile
        
        if ($output) {
            Set-AnalysisResult -Config $Config -Category "handles" -Plugin $plugin.Name -OutputFile $output
        }
    }
    
    # Analyze handles for interesting data
    Analyze-Handles -Config $Config
    
    # Generate HTML report
    Export-HandlesReport -Config $Config
    
    return $true
}

function Analyze-Handles {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["handles"]
    
    # Check if handle data exists
    if (-not $Config.AnalysisResults.ContainsKey("handles") -or 
        -not $Config.AnalysisResults["handles"].ContainsKey("windows.handles")) {
        Write-Host "Handle data not available for analysis." -ForegroundColor Yellow
        return
    }
    
    $handlesFile = $Config.AnalysisResults["handles"]["windows.handles"]
    $handlesContent = Get-Content -Path $handlesFile
    
    # Initialize data structures
    $processByHandles = @{}
    $handleTypes = @{}
    $interestingHandles = @()
    $fileExtensions = @{}
    
    # Define interesting patterns
    $interestingPatterns = @{
        # Interesting file paths
        '\\Users\\.*\\AppData\\' = "User AppData directory";
        '\\Users\\.*\\Documents\\' = "User Documents";
        '\\Windows\\Temp\\' = "Windows Temp directory";
        '\\Temp\\' = "Temp directory";
        '\\Downloads\\' = "Downloads folder";
        '\\ProgramData\\' = "ProgramData folder";
        
        # Interesting file types
        '\.exe$' = "Executable file";
        '\.dll$' = "DLL file";
        '\.ps1$' = "PowerShell script";
        '\.bat$' = "Batch file";
        '\.vbs$' = "VBScript file";
        '\.doc$|\.docx$' = "Word document";
        '\.xls$|\.xlsx$' = "Excel spreadsheet";
        '\.pdf$' = "PDF document";
        '\.zip$|\.rar$|\.7z$' = "Archive file";
        
        # Interesting registry keys
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' = "Autorun registry key";
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' = "User autorun registry key";
        'HKLM\\SYSTEM\\CurrentControlSet\\Services' = "Services registry key";
        'HKLM\\SAM\\' = "SAM database access";
        'HKLM\\SECURITY\\' = "Security database access";
        
        # Network related
        'TCP' = "TCP connection";
        'UDP' = "UDP connection";
        '\\Device\\Afd' = "Network socket";
        
        # Other sensitive objects
        'lsass.exe' = "LSASS process access (potential credential theft)";
        'ADMIN\\C\\$' = "Administrative share access";
        'Token' = "Process token access";
        'Process' = "Process handle (potential injection)"
    }
    
    # Parse handle data
    # Skip header line
    for ($i = 1; $i -lt $handlesContent.Count; $i++) {
        $line = $handlesContent[$i]
        if ($line -notmatch '\S') { continue }
        
        # Parse line - adjust regex pattern based on actual handles output format
        if ($line -match '(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$') {
            $processName = $matches[1]
            $processPID = $matches[2]
            $handleValue = $matches[3]  # Handle ID
            $handleType = $matches[4]   # Type (File, Key, etc.)
            $grantedAccess = $matches[5] # Access rights
            $handleName = $matches[6].Trim() # Object name
            
            # Skip unnamed handles
            if ($handleName -eq "" -or $handleName -eq "-") {
                continue
            }
            
            # Count by process
            $processKey = "$processName ($processPID)"
            if (-not $processByHandles.ContainsKey($processKey)) {
                $processByHandles[$processKey] = 0
            }
            $processByHandles[$processKey]++
            
            # Count by handle type
            if (-not $handleTypes.ContainsKey($handleType)) {
                $handleTypes[$handleType] = 0
            }
            $handleTypes[$handleType]++
            
            # Count file extensions
            if ($handleType -eq "File" -and $handleName -match '\.([^\.\\]+)$') {
                $extension = $matches[1].ToLower()
                if (-not $fileExtensions.ContainsKey($extension)) {
                    $fileExtensions[$extension] = 0
                }
                $fileExtensions[$extension]++
            }
            
            # Check for interesting patterns
            $isInteresting = $false
            $reasons = @()
            
            foreach ($pattern in $interestingPatterns.Keys) {
                if ($handleName -match $pattern) {
                    $isInteresting = $true
                    $reasons += $interestingPatterns[$pattern]
                }
            }
            
            # Add if interesting
            if ($isInteresting) {
                $interestingHandles += [PSCustomObject]@{
                    Process = $processName
                    PID = $processPID
                    Type = $handleType
                    Name = $handleName
                    Access = $grantedAccess
                    Reasons = $reasons -join ", "
                }
            }
        }
    }
    
    # Generate report
    $reportFile = Join-Path $outputDir "handle_analysis.txt"
    $output = "Handle Analysis Report`n"
    $output += "====================`n`n"
    
    # Interesting handles section
    if ($interestingHandles.Count -gt 0) {
        $output += "Interesting Handles:`n"
        $output += "------------------`n"
        
        foreach ($handle in ($interestingHandles | Sort-Object -Property Process)) {
            $output += "Process: $($handle.Process) (PID: $($handle.PID))`n"
            $output += "Type: $($handle.Type)`n"
            $output += "Object: $($handle.Name)`n"
            $output += "Access: $($handle.Access)`n"
            $output += "Interest: $($handle.Reasons)`n`n"
        }
    } else {
        $output += "No particularly interesting handles detected.`n`n"
    }
    
    # Handle statistics
    $output += "Handle Statistics:`n"
    $output += "-----------------`n"
    $output += "Top Processes by Handle Count:`n"
    foreach ($proc in ($processByHandles.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10)) {
        $output += "  $($proc.Key): $($proc.Value) handles`n"
    }
    $output += "`n"
    
    $output += "Handle Types:`n"
    foreach ($type in ($handleTypes.GetEnumerator() | Sort-Object -Property Value -Descending)) {
        $output += "  $($type.Key): $($type.Value) handles`n"
    }
    $output += "`n"
    
    if ($fileExtensions.Count -gt 0) {
        $output += "Top File Extensions:`n"
        foreach ($ext in ($fileExtensions.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10)) {
            $output += "  .$($ext.Key): $($ext.Value) files`n"
        }
    }
    
    # Save report
    $output | Out-File -FilePath $reportFile -Encoding utf8
    Write-Host "Handle analysis completed. See $reportFile for details." -ForegroundColor Green
    
    # Export as CSV for easier analysis
    if ($interestingHandles.Count -gt 0) {
        $csvFile = Join-Path $outputDir "interesting_handles.csv"
        $interestingHandles | Export-Csv -Path $csvFile -NoTypeInformation
    }
}

function Export-HandlesReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["handles"]
    $reportFile = Join-Path $outputDir "handles_analysis_report.html"
    
    # Start building HTML content
    $content = "<h2>Handles Analysis</h2>"
    
    # Add handle analysis if found
    $analysisFile = Join-Path $outputDir "handle_analysis.txt"
    if (Test-Path $analysisFile) {
        $analysisContent = Get-Content -Path $analysisFile -Raw
        $content += "<h3>Handle Analysis</h3><pre>$analysisContent</pre>"
    }
    
    # Add raw handles data if available
    if ($Config.AnalysisResults["handles"].ContainsKey("windows.handles")) {
        $handlesFile = $Config.AnalysisResults["handles"]["windows.handles"]
        $handlesContent = Get-Content -Path $handlesFile -Raw
        $content += "<h3>Raw Handle Data</h3><pre>$handlesContent</pre>"
    }
    
    # Generate the HTML report
    Export-HTMLReport -Config $Config -Title "Handles Analysis Report" -Content $content -OutputFile $reportFile
} 