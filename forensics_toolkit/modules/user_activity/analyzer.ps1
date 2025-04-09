# User Activity Analysis Module
# Analyzes artifacts related to user activity

function Invoke-UserActivityAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["user_activity"]
    
    Write-Host "`n=== Running User Activity Analysis ===" -ForegroundColor Cyan
    
    # Define user activity related plugins
    # Removed unsupported windows.clipboard plugin
    
    # Use registry data if available
    if ($Config.AnalysisResults.ContainsKey("registry")) {
        $hasUserAssist = $Config.AnalysisResults["registry"].ContainsKey("windows.registry.userassist")
        
        if ($hasUserAssist) {
            Analyze-UserArtifacts -Config $Config -HasUserAssist $hasUserAssist
        }
    }
    
    # Generate HTML report
    Export-UserActivityReport -Config $Config
    
    return $true
}

function Analyze-UserArtifacts {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $false)]
        [bool]$HasUserAssist = $false
    )
    
    $outputDir = $Config.OutputDirectories["user_activity"]
    
    # Initialize program execution timeline
    $executions = @()
    
    # Process UserAssist data if available
    if ($HasUserAssist) {
        $userAssistFile = $Config.AnalysisResults["registry"]["windows.registry.userassist"]
        $userAssistContent = Get-Content -Path $userAssistFile
        
        foreach ($line in $userAssistContent) {
            # Extract UserAssist entries with timestamps
            if ($line -match 'REG_BINARY\s+:\s+(.+?)\s+Count:\s+(\d+).*?Time:\s+(.+?)(?:\r?\n|$)') {
                $program = $matches[1].Trim()
                $count = $matches[2].Trim()
                $timestamp = $matches[3].Trim()
                
                # Add to timeline
                $executions += [PSCustomObject]@{
                    Timestamp = $timestamp
                    Program = $program
                    Count = $count
                    Source = "UserAssist"
                }
            }
        }
    }
    
    # Generate timeline report if we have data
    if ($executions.Count -gt 0) {
        # Sort by timestamp
        $sortedExecutions = $executions | Sort-Object -Property Timestamp -Descending
        
        # Generate report
        $reportFile = Join-Path $outputDir "program_execution_timeline.txt"
        $output = "Program Execution Timeline`n"
        $output += "========================`n`n"
        
        foreach ($execution in $sortedExecutions) {
            $output += "Time: $($execution.Timestamp)`n"
            $output += "Program: $($execution.Program)`n"
            if ($execution.Count -ne "N/A") {
                $output += "Run Count: $($execution.Count)`n"
            }
            $output += "Source: $($execution.Source)`n`n"
        }
        
        # Save report
        $output | Out-File -FilePath $reportFile -Encoding utf8
        Write-Host "Program execution timeline created. See $reportFile for details." -ForegroundColor Green
        
        # Export as CSV for easier analysis
        $csvFile = Join-Path $outputDir "program_execution_timeline.csv"
        $sortedExecutions | Export-Csv -Path $csvFile -NoTypeInformation
    }
}

function Export-UserActivityReport {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    $outputDir = $Config.OutputDirectories["user_activity"]
    $reportFile = Join-Path $outputDir "user_activity_report.html"
    
    # Start building HTML content
    $content = "<h2>User Activity Analysis</h2>"
    
    # Add program execution timeline if available
    $timelineFile = Join-Path $outputDir "program_execution_timeline.txt"
    if (Test-Path $timelineFile) {
        $timelineContent = Get-Content -Path $timelineFile -Raw
        $content += "<h3>Program Execution Timeline</h3><pre>$timelineContent</pre>"
    }
    
    # Generate the HTML report
    Export-HTMLReport -Config $Config -Title "User Activity Analysis Report" -Content $content -OutputFile $reportFile
} 