# Memory Analysis Module
# Used for detecting malware and suspicious memory patterns

function Invoke-MemoryAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["memory"]
    
    Write-Host "`n=== Running Memory/Malware Analysis ===" -ForegroundColor Cyan
    
    # Define memory/malware analysis plugins
    $plugins = @(
        @{
            Name = "windows.malfind"; 
            Description = "Detect hidden and injected code"
        },
        @{
            Name = "windows.vadinfo"; 
            Description = "Virtual Address Descriptor information"
            ForceUTF8 = $true # Force UTF-8 encoding for this plugin
        }
        # Removed unsupported plugin: windows.apihooks
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
                Set-AnalysisResult -Config $Config -Category "memory" -Plugin $plugin.Name -OutputFile $outputPath
            } else {
                Write-Warning "Failed to create output file for $($plugin.Name)"
            }
        }
        else {
            # Standard execution for non-UTF8 plugins
            $output = Invoke-Volatility -Config $Config -Plugin $plugin.Name -OutputDir $outputDir -OutputFileName $outputFile
            
            if ($output) {
                Set-AnalysisResult -Config $Config -Category "memory" -Plugin $plugin.Name -OutputFile $output
            }
        }
    }
    
    # Special analysis: Detect code injection with malfind
    Detect-CodeInjection -Config $Config
    
    # Generate HTML report
    Export-MemoryReport -Config $Config
    
    return $true
}

function Detect-CodeInjection {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["memory"]
    
    # Check if malfind data exists
    if (-not $Config.AnalysisResults.ContainsKey("memory") -or 
        -not $Config.AnalysisResults["memory"].ContainsKey("windows.malfind")) {
        Write-Host "Malfind data not available for code injection analysis." -ForegroundColor Yellow
        return
    }
    
    $malfindFile = $Config.AnalysisResults["memory"]["windows.malfind"]
    $malfindContent = Get-Content -Path $malfindFile -Raw
    
    # Extract process information from malfind output
    $processes = @{}
    $regexMatches = [regex]::Matches($malfindContent, 'Process\s+([^\s]+)\s+Pid\s+(\d+).*?Protection\s+([^\r\n]+)')
    
    foreach ($match in $regexMatches) {
        $processName = $match.Groups[1].Value
        $processPID = $match.Groups[2].Value
        $protection = $match.Groups[3].Value
        
        if (-not $processes.ContainsKey($processPID)) {
            $processes[$processPID] = @{
                Name = $processName
                Count = 0
                Protection = @{}
            }
        }
        
        $processes[$processPID].Count++
        
        # Count protection types
        if (-not $processes[$processPID].Protection.ContainsKey($protection)) {
            $processes[$processPID].Protection[$protection] = 0
        }
        
        $processes[$processPID].Protection[$protection]++
    }
    
    # Generate report on suspicious memory regions
    $injectionReportFile = Join-Path $outputDir "code_injection_analysis.txt"
    $output = "Code Injection Analysis Report`n"
    $output += "============================`n`n"
    
    if ($processes.Count -gt 0) {
        $output += "Processes with Suspicious Memory Regions:`n"
        $output += "----------------------------------------`n"
        
        foreach ($pid in $processes.Keys) {
            $proc = $processes[$pid]
            $output += "Process: $($proc.Name) (PID: $pid)`n"
            $output += "Number of Suspicious Memory Regions: $($proc.Count)`n"
            $output += "Protection Types:`n"
            
            foreach ($protection in $proc.Protection.Keys) {
                $output += "  - $protection`: $($proc.Protection[$protection]) regions`n"
            }
            
            # Check for executable+writable memory (often used for shellcode)
            if (($proc.Protection.Keys -join " ") -match "PAGE_EXECUTE_READWRITE") {
                $output += "  !!! WARNING: Contains executable and writable memory - strong indicator of code injection !!!`n"
            }
            
            $output += "`n"
        }
    }
    else {
        $output += "No code injection detected.`n"
    }
    
    # Save report
    $output | Out-File -FilePath $injectionReportFile -Encoding utf8
    Write-Host "Code injection analysis completed. See $injectionReportFile for details." -ForegroundColor Green
    
    # Also extract hex dumps for further analysis
    $hexdumps = [regex]::Matches($malfindContent, '(0x[0-9a-f]+)  ([0-9a-f\s]+)')
    
    if ($hexdumps.Count -gt 0) {
        $hexdumpFile = Join-Path $outputDir "hexdumps.txt"
        $hexOutput = "Suspicious Memory Hexdumps`n"
        $hexOutput += "=========================`n`n"
        
        foreach ($hexdump in $hexdumps) {
            $address = $hexdump.Groups[1].Value
            $bytes = $hexdump.Groups[2].Value
            $hexOutput += "Address: $address`n"
            $hexOutput += "Bytes: $bytes`n`n"
        }
        
        $hexOutput | Out-File -FilePath $hexdumpFile -Encoding utf8
    }
}

function Export-MemoryReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["memory"]
    $reportFile = Join-Path $outputDir "memory_analysis_report.html"
    
    # Start building HTML content
    $content = "<h2>Memory/Malware Analysis</h2>"
    
    # Add malfind data if available
    if ($Config.AnalysisResults["memory"].ContainsKey("windows.malfind")) {
        $malfindFile = $Config.AnalysisResults["memory"]["windows.malfind"]
        $malfindContent = Get-Content -Path $malfindFile -Raw
        $content += "<h3>Malware Detection (malfind)</h3><pre class='suspicious'>$malfindContent</pre>"
    }
    
    # Add code injection analysis if available
    $injectionFile = Join-Path $outputDir "code_injection_analysis.txt"
    if (Test-Path $injectionFile) {
        $injectionContent = Get-Content -Path $injectionFile -Raw
        $content += "<h3>Code Injection Analysis</h3><pre class='suspicious'>$injectionContent</pre>"
    }
    
    # Removed section for API hooks since the plugin is not supported
    
    # Generate the HTML report
    Export-HTMLReport -Config $Config -Title "Memory and Malware Analysis Report" -Content $content -OutputFile $reportFile
} 