# Early exit if not domain-joined
#if (-not $env:USERDOMAIN) { exit 0 }

# Extract Site Code (First 4 chars of COMPUTERNAME)
$SiteCode = 'EAMC' # $env:COMPUTERNAME.Substring(0,4)

# Define regex pattern for sensitive values
$regex = "(`"|')(?<redact>(\\\\)?$SiteCode[^`"']+)(`"|')"

# Define script file to sanitize (only staged version, not working copy)
$scriptPath = "$PSScriptRoot\..\SOURCE\logon.ps1"

# Get staged content
$stagedContent = git show :SOURCE/logon.ps1

# Sanitize the content
$sanitizedContent = $stagedContent -ireplace $regex, "`$(throw `"Value has been redacted. Replace this with local value.`")"

# Write the sanitized content to the staging area without modifying the local file
$sanitizedContent | Out-File $scriptPath -Encoding utf8 -Force -NoNewline

# Re-add the sanitized file to the commit (but leave the working copy unchanged)
git add SOURCE/logon.ps1

Write-Host "Pre-commit sanitization completed. Sensitive values redacted in commit."
exit 0