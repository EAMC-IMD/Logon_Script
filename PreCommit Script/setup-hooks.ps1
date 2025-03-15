# Define paths
$repoRoot         = Split-Path -Parent $PSScriptRoot   # Repo root
$hookDir          = "$repoRoot\.git\hooks"              # Git hooks directory
$hookBatch        = "$hookDir\pre-commit"             # Batch file path
$hookScriptSource = "$repoRoot\PreCommit Script\pre-commit.ps1"

# Create Git hooks directory if it doesn't exist
if (!(Test-Path $hookDir)) {
    $null = New-Item -ItemType Directory -Path $hookDir
}

# Write the pre-commit batch file that calls the PowerShell script
@'
@echo off
powershell.exe -ExecutionPolicy Bypass -File "%~dp0..\..\PreCommit Script\pre-commit.ps1"
exit %ERRORLEVEL%
'@ | Set-Content -Path $hookBatch -Force

Write-Host "Pre-commit hook installed successfully."