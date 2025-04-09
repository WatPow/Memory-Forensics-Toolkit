# Utility Functions for Forensic Analysis Toolkit

function Invoke-Volatility {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$Plugin,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputDir,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputFileName,
        
        [Parameter(Mandatory = $false)]
        [string]$AdditionalArgs = ""
    )
    
    # Set output directory
    if (-not $OutputDir) {
        $OutputDir = $Config.OutputDirectories["reports"]
    }
    
    # Set output file name
    if (-not $OutputFileName) {
        $OutputFileName = "$Plugin.txt"
    }
    
    # Full path to output file
    $outputPath = Join-Path $OutputDir $OutputFileName
    
    # Check if AdditionalArgs contains --output-file parameter
    $hasCustomOutputFile = $AdditionalArgs -match "--output-file=([^\s]+)"
    $customOutputFile = if ($hasCustomOutputFile) { $matches[1] } else { $null }
    
    # Basic volatility command
    $volCommand = "$($Config.VolatilityCmd) -f $($Config.MemoryDump) $Plugin $AdditionalArgs"
    
    # Execute command and save to file
    try {
        Write-Host "Running: $volCommand" -ForegroundColor Yellow
        
        # Check if the command contains redirection or custom output file
        if ($AdditionalArgs -match "2>" -or $hasCustomOutputFile) {
            # For commands with redirection or custom output, use Invoke-Expression directly
            $result = Invoke-Expression "$volCommand" | Out-String
            
            # If there's a custom output file, we'll still write to our standard location
            # but the plugin handler will use the custom file for processing (e.g., utf8 fix)
            if (-not $hasCustomOutputFile) {
                if (-not $result) {
                    $result = "No output from $Plugin or plugin execution failed."
                }
                $result | Out-File -FilePath $outputPath -Encoding utf8
            }
            else {
                # Create a minimal placeholder file so the output path exists
                "Output redirected to $customOutputFile" | Out-File -FilePath $outputPath -Encoding utf8
            }
        } else {
            # For normal commands
            $result = Invoke-Expression "$volCommand" | Out-String
            
            # Always save output, even if it's an error message
            if (-not $result) {
                $result = "No output from $Plugin or plugin execution failed."
            }
            
            $result | Out-File -FilePath $outputPath -Encoding utf8
        }
        
        Write-Host "Results saved to: $outputPath" -ForegroundColor Green
        return $outputPath
    }
    catch {
        $errorMsg = "Error executing $Plugin"
        Write-Error "$errorMsg`: $_"
        "$errorMsg`: $_" | Out-File -FilePath $outputPath -Encoding utf8
        return $outputPath
    }
}

function Get-SuspiciousScore {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Item,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Indicators
    )
    
    $score = 0
    
    foreach ($indicator in $Indicators.Keys) {
        if ($Item -match $indicator) {
            $score += $Indicators[$indicator]
        }
    }
    
    return $score
}

function Format-TableOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    $content = Get-Content -Path $FilePath -Raw
    return $content -replace ('\s{2,}', '  ')
}

function Find-Anomalies {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DataFile,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$AnalysisLogic
    )
    
    # Read the data file
    $data = Get-Content -Path $DataFile
    
    # Apply the analysis logic
    $anomalies = & $AnalysisLogic -Data $data
    
    return $anomalies
}

function Compare-WithBaseline {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CurrentData,
        
        [Parameter(Mandatory = $true)]
        [string]$BaselineData
    )
    
    $current = Get-Content -Path $CurrentData
    $baseline = Get-Content -Path $BaselineData
    
    $diff = Compare-Object -ReferenceObject $baseline -DifferenceObject $current
    
    return $diff
}

function Get-TimestampFromText {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    
    $pattern = '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
    if ($Text -match $pattern) {
        return $matches[0]
    }
    
    return $null
}

function ConvertTo-ReadableSize {
    param (
        [Parameter(Mandatory = $true)]
        [long]$Bytes
    )
    
    if ($Bytes -lt 1KB) {
        return "$Bytes B"
    }
    elseif ($Bytes -lt 1MB) {
        return "{0:N2} KB" -f ($Bytes / 1KB)
    }
    elseif ($Bytes -lt 1GB) {
        return "{0:N2} MB" -f ($Bytes / 1MB)
    }
    else {
        return "{0:N2} GB" -f ($Bytes / 1GB)
    }
} 