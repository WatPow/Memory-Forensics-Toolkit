# Process Analysis Module

function Invoke-ProcessAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["processes"]
    
    Write-Host "`n=== Running Process Analysis ===" -ForegroundColor Cyan
    
    # Define process-related plugins
    $processPlugins = @(
        @{
            Name = "windows.psscan"
            OutputFile = "process_list.txt"
            Description = "List of processes"
            AdditionalArgs = ""
            ForceUTF8 = $true # Force UTF-8 encoding for this plugin
        },
        @{
            Name = "windows.pslist"
            OutputFile = "process_tree.txt"
            Description = "Process tree"
        },
        @{
            Name = "windows.pstree"
            OutputFile = "process_tree_alt.txt"
            Description = "Alternative process tree view"
        },
        @{
            Name = "windows.cmdline"
            OutputFile = "process_command_lines.txt"
            Description = "Command lines for each process"
        },
        @{
            Name = "windows.dlllist"
            OutputFile = "process_dlls.txt"
            Description = "DLLs loaded by each process"
        },
        @{
            Name = "windows.handles"
            OutputFile = "process_handles.txt"
            Description = "Handles opened by processes"
        },
        @{
            Name = "windows.malfind"
            OutputFile = "suspicious_processes.txt"
            Description = "Potentially malicious processes"
        },
        @{
            Name = "windows.svclist" # Replaced windows.getsvc with windows.svclist
            OutputFile = "services.txt"
            Description = "Services information"
        }
    )
    
    # Execute each plugin
    foreach ($plugin in $processPlugins) {
        Write-Host "Running $($plugin.Name) - $($plugin.Description)" -ForegroundColor Yellow
        
        try {
            # Handle encoding-sensitive plugins differently
            if ($plugin.ForceUTF8) {
                # Create a batch file for running Volatility directly with UTF-8 output
                $batchFile = Join-Path $outputDir "run_vol.bat"
                $outputFile = Join-Path $outputDir $plugin.OutputFile
                $errorFile = Join-Path $outputDir "process_list_errors.txt"
                $volCommand = "$($Config.VolatilityCmd) -f `"$($Config.MemoryDump)`" $($plugin.Name)"
                
                # Create a batch file with UTF-8 encoding setup
                @"
@echo off
chcp 65001 >nul
$volCommand > "$outputFile" 2> "$errorFile"
"@ | Out-File -FilePath $batchFile -Encoding ascii
                
                # Run the batch file
                Write-Host "Running special UTF-8 command for $($plugin.Name)" -ForegroundColor Yellow
                cmd /c $batchFile
                
                # Clean up batch file
                Remove-Item $batchFile -Force -ErrorAction SilentlyContinue
                
                if (Test-Path $outputFile) {
                    Write-Host "Successfully executed $($plugin.Name) with UTF-8 encoding" -ForegroundColor Green
                    Set-AnalysisResult -Config $Config -Category "processes" -Plugin $plugin.Name -OutputFile $outputFile
                } else {
                    Write-Warning "Failed to create output file for $($plugin.Name)"
                }
            } else {
                # Standard execution for other plugins
                $outputFile = Invoke-Volatility -Config $Config -Plugin $plugin.Name -OutputDir $outputDir -OutputFileName $plugin.OutputFile -AdditionalArgs $plugin.AdditionalArgs
                
                # Check if output was successful
                if (Test-Path $outputFile) {
                    $content = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
                    if ([string]::IsNullOrWhiteSpace($content) -or $content -match "Error executing volatility plugin") {
                        Write-Warning "Plugin $($plugin.Name) produced no output or encountered an error. See $outputFile for details."
                    }
                    
                    Set-AnalysisResult -Config $Config -Category "processes" -Plugin $plugin.Name -OutputFile $outputFile
                }
            }
        }
        catch {
            Write-Error "Error executing $($plugin.Name): $_"
            # Create an empty file or error indicator file so the output directory isn't missing expected files
            $errorMsg = "Error executing $($plugin.Name): $_"
            $outputFile = Join-Path $outputDir $plugin.OutputFile
            $errorMsg | Out-File -FilePath $outputFile -Encoding utf8
            Set-AnalysisResult -Config $Config -Category "processes" -Plugin $plugin.Name -OutputFile $outputFile
        }
    }
    
    # Additional analysis: Find suspicious processes
    Find-SuspiciousProcesses -Config $Config -OutputDir $outputDir
    
    # Generate HTML report
    Export-ProcessReport -Config $Config -OutputDir $outputDir
    
    return $true
}

function Find-SuspiciousProcesses {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputDir
    )
    
    # Check if pslist data exists
    $pslistFile = Join-Path $OutputDir "process_tree.txt"
    if (-not (Test-Path $pslistFile)) {
        Write-Host "Process list data not available for suspicious process analysis." -ForegroundColor Yellow
        return
    }
    
    $pslistContent = Get-Content -Path $pslistFile
    
    # Define suspicious indicators
    $suspiciousNames = @{
        # System-like processes with slight variations
        'scvhost' = 3; # Typosquatting svchost
        'csrss\d+' = 3; # Suspicious csrss naming pattern
        'lsas[^s]' = 3; # Suspicious lsass variant
        'smss\d+' = 3; # Suspicious smss naming pattern
        
        # Known suspicious process names
        'nc\.exe' = 3; # NetCat
        'mimikatz' = 5; # Password dumping tool
        'meterpreter' = 5; # Metasploit payload
        'psexec' = 3; # PsExec (can be legitimate but often used maliciously)
        
        # Generic suspicious names
        'temp\d*\.exe' = 2;
        'svchast' = 4;
        'svchos' = 4;
        'rundll\d{2}' = 2;
        'backdoor' = 5;
        'hack' = 2;
        'pwdump' = 4;
        'scan' = 1;
        'crack' = 2;
        'sniff' = 2
    }
    
    # Define suspicious process patterns
    $suspiciousPatterns = @{
        # Paths
        'C:\\Windows\\Temp\\.*\.exe' = 3;
        'C:\\Temp\\.*\.exe' = 3;
        'C:\\Users\\.*\\AppData\\Local\\Temp\\.*\.exe' = 2;
        
        # Command line patterns
        '-e powershell' = 4; # Encoded PowerShell commands
        'bypass' = 2; # Bypass techniques
        'hidden' = 2; # Hidden window/process
        'downloadstring' = 4; # Web download
    }
    
    # Process detection
    $suspiciousProcesses = @()
    
    # Skip header line
    for ($i = 1; $i -lt $pslistContent.Count; $i++) {
        $line = $pslistContent[$i]
        if ($line -notmatch '\S') { continue }
        
        # Extract process information
        # This regex pattern might need adjustment based on actual pslist output format
        if ($line -match '^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)') {
            $processName = $matches[1]
            $processPID = $matches[2]
            $ppid = $matches[3]
            
            # Check for suspicious names
            $score = 0
            $reasons = @()
            
            foreach ($pattern in $suspiciousNames.Keys) {
                if ($processName -match $pattern) {
                    $score += $suspiciousNames[$pattern]
                    $reasons += "Suspicious name pattern: $pattern"
                }
            }
            
            # Also check cmdline if available
            $cmdlineFile = Join-Path $OutputDir "process_command_lines.txt"
            if (Test-Path $cmdlineFile) {
                $cmdlineContent = Get-Content -Path $cmdlineFile -Raw
                
                # Find command line for this PID
                $cmdlinePattern = "PID\s+$processPID\s.*?CommandLine\s+:\s+(.*?)(?:\r?\n\r?\n|\r?\n[A-Z])"
                if ($cmdlineContent -match $cmdlinePattern) {
                    $cmdline = $matches[1]
                    
                    foreach ($pattern in $suspiciousPatterns.Keys) {
                        if ($cmdline -match $pattern) {
                            $score += $suspiciousPatterns[$pattern]
                            $reasons += "Suspicious command line pattern: $pattern"
                        }
                    }
                }
            }
            
            # Add if suspicious
            if ($score -gt 0) {
                $suspiciousProcesses += [PSCustomObject]@{
                    Name = $processName
                    PID = $processPID
                    PPID = $ppid
                    Score = $score
                    Reasons = $reasons -join ", "
                }
            }
        }
    }
    
    # Save results
    if ($suspiciousProcesses.Count -gt 0) {
        $suspiciousFile = Join-Path $OutputDir "detected_suspicious_processes.txt"
        
        $output = "Suspicious Processes Report`n"
        $output += "=========================`n`n"
        
        foreach ($proc in $suspiciousProcesses | Sort-Object -Property Score -Descending) {
            $output += "Process: $($proc.Name) (PID: $($proc.PID), PPID: $($proc.PPID))`n"
            $output += "Suspicion Score: $($proc.Score)`n"
            $output += "Reasons: $($proc.Reasons)`n`n"
        }
        
        $output | Out-File -FilePath $suspiciousFile -Encoding utf8
        Write-Host "Found $($suspiciousProcesses.Count) suspicious processes. See $suspiciousFile for details." -ForegroundColor Red
        
        # Save CSV format for easier analysis
        $csvFile = Join-Path $OutputDir "detected_suspicious_processes.csv"
        $suspiciousProcesses | Export-Csv -Path $csvFile -NoTypeInformation
    }
    else {
        Write-Host "No suspicious processes detected." -ForegroundColor Green
    }
}

function Export-ProcessReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputDir
    )
    
    $reportFile = Join-Path $OutputDir "process_analysis_report.html"
    
    # Start building HTML content
    $content = "<h2>Process Analysis</h2>"
    
    # Add pslist data if available
    $pslistFile = Join-Path $OutputDir "process_tree.txt"
    if (Test-Path $pslistFile) {
        $pslistContent = Get-Content -Path $pslistFile -Raw
        $content += "<h3>Process List</h3><pre>$pslistContent</pre>"
    }
    
    # Add pstree data if available
    $pstreeFile = Join-Path $OutputDir "process_tree_alt.txt"
    if (Test-Path $pstreeFile) {
        $pstreeContent = Get-Content -Path $pstreeFile -Raw
        $content += "<h3>Process Tree</h3><pre>$pstreeContent</pre>"
    }
    
    # Add cmdline data if available
    $cmdlineFile = Join-Path $OutputDir "process_command_lines.txt"
    if (Test-Path $cmdlineFile) {
        $cmdlineContent = Get-Content -Path $cmdlineFile -Raw
        $content += "<h3>Command Lines</h3><pre>$cmdlineContent</pre>"
    }
    
    # Add suspicious processes if found
    $suspiciousFile = Join-Path $OutputDir "detected_suspicious_processes.txt"
    if (Test-Path $suspiciousFile) {
        $suspiciousContent = Get-Content -Path $suspiciousFile -Raw
        $content += "<h3>Suspicious Processes</h3><div class='suspicious'><pre>$suspiciousContent</pre></div>"
    }
    
    # Generate the HTML report
    Export-HTMLReport -Config $Config -Title "Process Analysis Report" -Content $content -OutputFile $reportFile
} 