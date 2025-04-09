# Network Analysis Module
# Analyzes network connections and artifacts

function Invoke-NetworkAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["network"]
    
    Write-Host "`n=== Running Network Analysis ===" -ForegroundColor Cyan
    
    # Define network analysis plugins
    $plugins = @(
        @{Name = "windows.netscan"; Description = "Active/recently closed network connections"},
        @{Name = "windows.netstat"; Description = "Network connection statistics"}
    )
    
    # Execute each plugin
    foreach ($plugin in $plugins) {
        Write-Host "Running $($plugin.Name): $($plugin.Description)" -ForegroundColor Yellow
        $outputFile = "$($plugin.Name).txt"
        $output = Invoke-Volatility -Config $Config -Plugin $plugin.Name -OutputDir $outputDir -OutputFileName $outputFile
        
        if ($output) {
            Set-AnalysisResult -Config $Config -Category "network" -Plugin $plugin.Name -OutputFile $output
        }
    }
    
    # Analyze suspicious connections
    Find-SuspiciousConnections -Config $Config
    
    # Generate HTML report
    Export-NetworkReport -Config $Config
    
    return $true
}

function Find-SuspiciousConnections {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["network"]
    
    # Check if netscan data exists
    if (-not $Config.AnalysisResults.ContainsKey("network") -or 
        -not $Config.AnalysisResults["network"].ContainsKey("windows.netscan")) {
        Write-Host "Network scan data not available for connection analysis." -ForegroundColor Yellow
        return
    }
    
    $netscanFile = $Config.AnalysisResults["network"]["windows.netscan"]
    $netscanContent = Get-Content -Path $netscanFile
    
    # Define suspicious indicators
    $suspiciousIPs = @{
        # Common non-standard ports
        '.*:4444' = "Potential Metasploit default handler";
        '.*:8080' = "Common alternative HTTP port";
        '.*:1080' = "SOCKS proxy";
        '.*:31337' = "Common backdoor port";
        '.*:6667' = "IRC (common C2 channel)";
        '.*:6666' = "IRC alternative";
        '.*:5554' = "Sasser worm";
        '.*:5900' = "VNC remote access";
        '.*:3389' = "RDP remote access";
        '.*:22' = "SSH remote access";
        '.*:23' = "Telnet remote access";
        
        # IP ranges to monitor (examples)
        '^10\..*' = "Internal IP address";
        '^192\.168\..*' = "Internal IP address";
        '^172\.(1[6-9]|2[0-9]|3[0-1])\..*' = "Internal IP address";
        '^169\.254\..*' = "Link-local address (APIPA)"
    }
    
    # Patterns for suspicious processes
    $suspiciousProcesses = @{
        'cmd\.exe' = "Command shell with network connection";
        'powershell\.exe' = "PowerShell with network connection";
        'nc\.exe' = "NetCat utility";
        'ncat\.exe' = "Nmap NetCat utility";
        'netsh\.exe' = "Network shell utility";
        'svchost\.exe:.*:.*:.*:.*:.*:LISTENING' = "Service host listening on non-standard port"
    }
    
    # Collect suspicious connections
    $suspiciousConnections = @()
    $foreignAddresses = @{}
    $localPorts = @{}
    $remoteConnections = 0
    
    # Skip header line
    for ($i = 1; $i -lt $netscanContent.Count; $i++) {
        $line = $netscanContent[$i]
        if ($line -notmatch '\S') { continue }
        
        # Parse line - adjust regex pattern based on actual netscan output format
        if ($line -match '([^\s]+)\s+(\d+).*?(\d+\.\d+\.\d+\.\d+|\*|\[::1\]|\[::\]):(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*):(\d+)\s+([^\s]+)') {
            $processName = $matches[1]
            $processPID = $matches[2]
            $localAddress = $matches[3]
            $localPort = $matches[4]
            $foreignAddress = $matches[5]
            $foreignPort = $matches[6]
            $state = $matches[7]
            
            # Build connection info
            $connInfo = "$processName ($processPID) $localAddress`:$localPort -> $foreignAddress`:$foreignPort [$state]"
            $isSuspicious = $false
            $reason = ""
            
            # Check for suspicious process names
            foreach ($pattern in $suspiciousProcesses.Keys) {
                if ($connInfo -match $pattern) {
                    $isSuspicious = $true
                    $reason += $suspiciousProcesses[$pattern] + "; "
                }
            }
            
            # Check for suspicious IPs or ports
            foreach ($pattern in $suspiciousIPs.Keys) {
                if ("$foreignAddress`:$foreignPort" -match $pattern) {
                    $isSuspicious = $true
                    $reason += $suspiciousIPs[$pattern] + "; "
                }
            }
            
            # Track unique foreign addresses (excluding wildcards)
            if ($foreignAddress -ne "*" -and $foreignAddress -ne "[::]") {
                if (-not $foreignAddresses.ContainsKey($foreignAddress)) {
                    $foreignAddresses[$foreignAddress] = 0
                }
                $foreignAddresses[$foreignAddress]++
                
                # Count remote (external) connections
                if ($foreignAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.)') {
                    $remoteConnections++
                }
            }
            
            # Track local ports
            if (-not $localPorts.ContainsKey($localPort)) {
                $localPorts[$localPort] = 0
            }
            $localPorts[$localPort]++
            
            # Add to suspicious list if flagged
            if ($isSuspicious) {
                $suspiciousConnections += [PSCustomObject]@{
                    Process = $processName
                    PID = $processPID
                    LocalAddress = "$localAddress`:$localPort"
                    RemoteAddress = "$foreignAddress`:$foreignPort"
                    State = $state
                    Reason = $reason.TrimEnd("; ")
                }
            }
        }
    }
    
    # Generate report
    $reportFile = Join-Path $outputDir "suspicious_connections.txt"
    $output = "Suspicious Network Connections Report`n"
    $output += "====================================`n`n"
    
    if ($suspiciousConnections.Count -gt 0) {
        $output += "Suspicious Connections:`n"
        $output += "----------------------`n"
        
        foreach ($conn in $suspiciousConnections) {
            $output += "Process: $($conn.Process) (PID: $($conn.PID))`n"
            $output += "Connection: $($conn.LocalAddress) -> $($conn.RemoteAddress) [$($conn.State)]`n"
            $output += "Reason: $($conn.Reason)`n`n"
        }
    }
    else {
        $output += "No overtly suspicious connections detected.`n`n"
    }
    
    # Connection statistics
    $output += "Network Connection Statistics:`n"
    $output += "----------------------------`n"
    $output += "Total unique remote addresses: $($foreignAddresses.Count)`n"
    $output += "Remote (external) connections: $remoteConnections`n"
    $output += "Unique local ports in use: $($localPorts.Count)`n`n"
    
    $output += "Top Remote Addresses:`n"
    foreach ($addr in ($foreignAddresses.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10)) {
        if ($addr.Key -ne "*" -and $addr.Key -ne "[::1]" -and $addr.Key -ne "[::]") {
            $output += "  $($addr.Key): $($addr.Value) connections`n"
        }
    }
    $output += "`n"
    
    $output += "Top Local Ports:`n"
    foreach ($port in ($localPorts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10)) {
        $output += "  Port $($port.Key): $($port.Value) connections`n"
    }
    
    # Save report
    $output | Out-File -FilePath $reportFile -Encoding utf8
    Write-Host "Network connection analysis completed. See $reportFile for details." -ForegroundColor Green
    
    # Export as CSV for easier analysis
    if ($suspiciousConnections.Count -gt 0) {
        $csvFile = Join-Path $outputDir "suspicious_connections.csv"
        $suspiciousConnections | Export-Csv -Path $csvFile -NoTypeInformation
    }
}

function Export-NetworkReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["network"]
    $reportFile = Join-Path $outputDir "network_analysis_report.html"
    
    # Start building HTML content
    $content = "<h2>Network Analysis</h2>"
    
    # Add netscan data if available
    if ($Config.AnalysisResults["network"].ContainsKey("windows.netscan")) {
        $netscanFile = $Config.AnalysisResults["network"]["windows.netscan"]
        $netscanContent = Get-Content -Path $netscanFile -Raw
        $content += "<h3>Network Connections</h3><pre>$netscanContent</pre>"
    }
    
    # Add suspicious connections if found
    $suspiciousFile = Join-Path $outputDir "suspicious_connections.txt"
    if (Test-Path $suspiciousFile) {
        $suspiciousContent = Get-Content -Path $suspiciousFile -Raw
        $content += "<h3>Suspicious Network Connections</h3><div class='suspicious'><pre>$suspiciousContent</pre></div>"
    }
    
    # Generate the HTML report
    Export-HTMLReport -Config $Config -Title "Network Analysis Report" -Content $content -OutputFile $reportFile
} 