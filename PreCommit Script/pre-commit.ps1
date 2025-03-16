#!/usr/bin/env pwsh
$PRIVATE_DIR = "Private"
$SOURCE_DIR = "SOURCE"

# Ensure the script only runs when necessary
$staged_files = git diff --cached --name-only | Where-Object { $_ -match "^$PRIVATE_DIR/" }

if (-not $staged_files) {
    exit 0  # No relevant files staged, exit early
}

Write-Host "Processing staged files from $PRIVATE_DIR..."

foreach ($file in $staged_files) {
    # Determine relative path
    $relative_path = $file -replace "^$PRIVATE_DIR/", ""

    # Special case for PowerShell file renaming
    $target_filename = if ($relative_path -eq "eamclogonLCI.ps1") { "logon.ps1" } else { $relative_path }

    # Define target path in SOURCE
    $source_file = Join-Path $SOURCE_DIR $target_filename

    # Create the target directory if it doesn't exist
    $source_dir = Split-Path -Parent $source_file
    if (!(Test-Path $source_dir)) {
        New-Item -ItemType Directory -Path $source_dir -Force | Out-Null
    }

    if ($file -match "\.json$") {
        Write-Host "Sanitizing JSON file: $file -> $source_file"
        (Get-Content $file -Raw) -replace '(":[\s]*")([^"]*EAMC[^"]*)(")', '$1$3' -replace 'EAMC', '' | Set-Content -Encoding UTF8 $source_file

    } elseif ($file -match "\.ps1$") {
        Write-Host "Sanitizing PowerShell script: $file -> $source_file"
        (Get-Content $file -Raw) -replace 'EAMC', '' | Set-Content -Encoding UTF8 $source_file

    } else {
        Write-Host "Copying non-JSON/PS1 file: $file -> $source_file"
        Copy-Item -Path $file -Destination $source_file -Force
    }

    # Convert file to CRLF (Windows line endings) to avoid Git showing every line as changed
    $content = Get-Content -Raw $source_file -Encoding UTF8
    $content = $content -replace "`r?`n", "`r`n"  # Normalize to CRLF
    Set-Content -Path $source_file -Value $content -Encoding UTF8

    # Stage the updated file
    git add $source_file
}

Write-Host "All modified files staged successfully."
exit 0