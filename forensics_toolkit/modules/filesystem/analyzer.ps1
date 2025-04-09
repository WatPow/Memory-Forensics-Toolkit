# File System Analysis Module
# Analyzes files in memory for forensic investigation

function Invoke-FileAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["filesystem"]
    
    Write-Host "`n=== Running File System Analysis ===" -ForegroundColor Cyan
    
    # Define filesystem-related plugins
    $plugins = @(
        @{
            Name = "windows.filescan"
            Description = "Scan for file objects"
            ForceUTF8 = $true # Force UTF-8 encoding for this plugin
        }
    )
    
    # Execute each plugin
    foreach ($plugin in $plugins) {
        Write-Host "Running $($plugin.Name): $($plugin.Description)" -ForegroundColor Yellow
        $outputFile = "$($plugin.Name).txt"
        
        # Handle encoding-sensitive plugins differently
        if ($plugin.ForceUTF8) {
            $outputPath = Join-Path $outputDir $outputFile
            $errorFile = Join-Path $outputDir "$($plugin.Name)_errors.txt"
            $batchFile = Join-Path $outputDir "run_vol_utf8.bat"
            $volCommand = "$($Config.VolatilityCmd) -f `"$($Config.MemoryDump)`" $($plugin.Name)"
            
            # Create a batch file with UTF-8 encoding setup
            @"
@echo off
chcp 65001 >nul
$volCommand > "$outputPath" 2> "$errorFile"
"@ | Out-File -FilePath $batchFile -Encoding ascii
            
            # Run the batch file
            Write-Host "Running with UTF-8 encoding for $($plugin.Name)" -ForegroundColor Yellow
            cmd /c $batchFile
            
            # Clean up batch file
            Remove-Item $batchFile -Force -ErrorAction SilentlyContinue
            
            if (Test-Path $outputPath) {
                Write-Host "Successfully executed $($plugin.Name) with UTF-8 encoding" -ForegroundColor Green
                Set-AnalysisResult -Config $Config -Category "filesystem" -Plugin $plugin.Name -OutputFile $outputPath
            } else {
                Write-Warning "Failed to create output file for $($plugin.Name)"
            }
        }
        else {
            # Standard execution for non-UTF8 plugins
            $output = Invoke-Volatility -Config $Config -Plugin $plugin.Name -OutputDir $outputDir -OutputFileName $outputFile
            
            if ($output) {
                Set-AnalysisResult -Config $Config -Category "filesystem" -Plugin $plugin.Name -OutputFile $output
            }
        }
    }
    
    # Look for suspicious files
    Find-SuspiciousFiles -Config $Config
    
    # Generate HTML report
    Export-FileSystemReport -Config $Config
    
    return $true
}

function Find-SuspiciousFiles {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["filesystem"]
    
    # Check if filescan data exists
    if (-not $Config.AnalysisResults.ContainsKey("filesystem") -or 
        -not $Config.AnalysisResults["filesystem"].ContainsKey("windows.filescan")) {
        Write-Host "File scan data not available for suspicious file analysis." -ForegroundColor Yellow
        return
    }
    
    $filescanFile = $Config.AnalysisResults["filesystem"]["windows.filescan"]
    $filescanContent = Get-Content -Path $filescanFile
    
    # Define suspicious file patterns
    $suspiciousFilePatterns = @{
        # Temp directories
        '\\Windows\\Temp\\.*\.exe' = "Executable in Windows temp directory";
        '\\Temp\\.*\.exe' = "Executable in temp directory";
        '\\AppData\\Local\\Temp\\.*\.exe' = "Executable in user temp directory";
        
        # Suspicious extensions
        '\.scr$' = "Screen saver executable";
        '\.bat$' = "Batch file";
        '\.vbs$' = "Visual Basic script";
        '\.ps1$' = "PowerShell script";
        '\.jse?$' = "JScript file";
        '\.hta$' = "HTML Application";
        '\.pif$' = "Program Information File (can contain executable code)";
        
        # Download directories
        '\\Downloads\\.*\.exe' = "Executable in Downloads folder";
        
        # Common malware names
        '\\nc\.exe' = "Netcat utility";
        '\\ncat\.exe' = "Nmap Netcat utility";
        '\\psexec\.exe' = "PsExec utility";
        'backdoor' = "Possible backdoor";
        'trojan' = "Possible trojan";
        'hack' = "Hacking tool";
        'crack' = "Cracking tool";
        
        # Suspicious paths
        '\\Windows\\System32\\.*\\.*\.exe' = "Executable in subfolder of System32 (unusual)";
        '\\Windows\\.*\\\.\.\\' = "Path traversal pattern in Windows directory";
        
        # Data exfiltration or packaging
        '\.rar$' = "RAR archive file";
        '\.7z$' = "7-Zip archive file";
        '\.zip$' = "ZIP archive file";
        '\.tar$' = "TAR archive file";
        '\.gz$' = "Gzip compressed file"
    }
    
    # Capture suspicious files
    $suspiciousFiles = @()
    $fileExtensions = @{}
    $executables = 0
    
    for ($i = 1; $i -lt $filescanContent.Count; $i++) {
        $line = $filescanContent[$i]
        if ($line -notmatch '\S') { continue }
        
        # Parse line - adjust regex pattern based on actual filescan output format
        if ($line -match '0x\w+\s+\w+\s+\d+\s+\d+\s+(.*?)\s*$') {
            $filePath = $matches[1].Trim()
            
            # Skip non-file paths or empty paths
            if (-not $filePath -or $filePath -eq "" -or -not $filePath.Contains("\")) {
                continue
            }
            
            # Get file extension
            $extension = ""
            if ($filePath -match '\.([^\.\\]+)$') {
                $extension = $matches[1].ToLower()
                
                # Count file extensions
                if (-not $fileExtensions.ContainsKey($extension)) {
                    $fileExtensions[$extension] = 0
                }
                $fileExtensions[$extension]++
                
                # Count executables
                if ($extension -eq "exe" -or $extension -eq "dll" -or $extension -eq "sys") {
                    $executables++
                }
            }
            
            # Check for suspicious patterns
            $isSuspicious = $false
            $reasons = @()
            
            foreach ($pattern in $suspiciousFilePatterns.Keys) {
                if ($filePath -match $pattern) {
                    $isSuspicious = $true
                    $reasons += $suspiciousFilePatterns[$pattern]
                }
            }
            
            # Add to list if suspicious
            if ($isSuspicious) {
                $suspiciousFiles += [PSCustomObject]@{
                    Path = $filePath
                    Extension = $extension
                    Reasons = $reasons -join ", "
                }
            }
        }
    }
    
    # Generate report
    $reportFile = Join-Path $outputDir "suspicious_files.txt"
    $output = "Suspicious Files Report`n"
    $output += "=====================`n`n"
    
    if ($suspiciousFiles.Count -gt 0) {
        $output += "Suspicious Files Found:`n"
        $output += "----------------------`n"
        
        foreach ($file in $suspiciousFiles) {
            $output += "File: $($file.Path)`n"
            $output += "Extension: $($file.Extension)`n"
            $output += "Reasons: $($file.Reasons)`n`n"
        }
    } else {
        $output += "No overtly suspicious files detected.`n`n"
    }
    
    # File statistics
    $output += "File Statistics:`n"
    $output += "---------------`n"
    $output += "Executable files (exe/dll/sys): $executables`n`n"
    
    $output += "Top File Extensions:`n"
    foreach ($ext in ($fileExtensions.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10)) {
        $output += "  .$($ext.Key): $($ext.Value) files`n"
    }
    
    # Save report
    $output | Out-File -FilePath $reportFile -Encoding utf8
    Write-Host "File analysis completed. See $reportFile for details." -ForegroundColor Green
    
    # Export as CSV for easier analysis
    if ($suspiciousFiles.Count -gt 0) {
        $csvFile = Join-Path $outputDir "suspicious_files.csv"
        $suspiciousFiles | Export-Csv -Path $csvFile -NoTypeInformation
    }
}

function Export-FileSystemReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["filesystem"]
    $reportFile = Join-Path $outputDir "filesystem_analysis_report.html"
    
    # Start building HTML content
    $content = "<h2>File System Analysis</h2>"
    
    # Add suspicious files if found
    $suspiciousFile = Join-Path $outputDir "suspicious_files.txt"
    if (Test-Path $suspiciousFile) {
        $suspiciousContent = Get-Content -Path $suspiciousFile -Raw
        $content += "<h3>Suspicious Files</h3><div class='suspicious'><pre>$suspiciousContent</pre></div>"
    }
    
    # Add filescan data if available
    if ($Config.AnalysisResults["filesystem"].ContainsKey("windows.filescan")) {
        $filescanFile = $Config.AnalysisResults["filesystem"]["windows.filescan"]
        $filescanContent = Get-Content -Path $filescanFile -Raw
        $content += "<h3>File Scan Results</h3><pre>$filescanContent</pre>"
    }
    
    # Generate the HTML report
    Export-HTMLReport -Config $Config -Title "File System Analysis Report" -Content $content -OutputFile $reportFile
}