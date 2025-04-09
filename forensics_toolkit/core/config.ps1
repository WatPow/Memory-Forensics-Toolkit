# Configuration Module for Forensic Analysis Toolkit
# Handles settings, paths, and environment setup

function Get-Configuration {
    param (
        [Parameter(Mandatory = $true)]
        [string]$MemoryDump
    )
    
    # Get absolute path to memory dump
    $MemoryDumpPath = Resolve-Path $MemoryDump -ErrorAction SilentlyContinue
    if (-not $MemoryDumpPath) {
        $MemoryDumpPath = $MemoryDump
    }
    
    # Create timestamp for output directories
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    # Set up output directories
    $baseOutputDir = Join-Path $PSScriptRoot "..\..\output\$timestamp"
    New-Item -ItemType Directory -Path $baseOutputDir -Force | Out-Null
    
    # Create subdirectories for each analysis category
    $outputDirs = @{
        "system_info" = Join-Path $baseOutputDir "system_info"
        "processes" = Join-Path $baseOutputDir "processes"
        "modules" = Join-Path $baseOutputDir "modules"
        "handles" = Join-Path $baseOutputDir "handles"
        "memory" = Join-Path $baseOutputDir "memory"
        "network" = Join-Path $baseOutputDir "network"
        "filesystem" = Join-Path $baseOutputDir "filesystem"
        "registry" = Join-Path $baseOutputDir "registry"
        "user_activity" = Join-Path $baseOutputDir "user_activity"
        "reports" = Join-Path $baseOutputDir "reports"
    }
    
    # Create all output directories
    foreach ($dir in $outputDirs.Values) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    
    # Define volatility command
    $volatilityCmd = "vol"
    
    # Check if volatility is installed
    try {
        $null = Invoke-Expression "$volatilityCmd -h"
    }
    catch {
        Write-Error "Volatility 3 not found. Please make sure it's installed and available in your PATH."
        exit
    }
    
    # Return config object
    return [PSCustomObject]@{
        MemoryDump = $MemoryDumpPath
        Timestamp = $timestamp
        OutputDirectories = $outputDirs
        VolatilityCmd = $volatilityCmd
        AnalysisResults = @{}
    }
}

function Set-AnalysisResult {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Plugin,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )
    
    if (-not $Config.AnalysisResults.ContainsKey($Category)) {
        $Config.AnalysisResults[$Category] = @{}
    }
    
    $Config.AnalysisResults[$Category][$Plugin] = $OutputFile
} 