<#
.SYNOPSIS
    Remediates STIG WN11-AU-000570 by ensuring Windows 11 audits
    Object Access >> Detailed File Share - Failure using AuditPol.

.NOTES
    Author          : Alejandro Castillo
    LinkedIn        : linkedin.com/in/alejandro-castillo-156907218/
    GitHub          : github.com/acRei
    Date Created    : 2026-1-26
    Last Modified   : 2026-1-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000570

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run in an elevated PowerShell session (Run as Administrator).
    Example:
    PS C:\> .\WN11-AU-000570-Audit-Detailed-File-Share-Failures.ps1

    Check reference:
    - AuditPol /get /category:*
    Required:
    - Object Access >> Detailed File Share - Failure
#>

# -----------------------------
# Configuration (STIG baseline)
# -----------------------------
$StigId      = "WN11-AU-000570"
$Subcategory = "Detailed File Share"

# -----------------------------
# Helper: Admin check
# -----------------------------
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal       = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator to query/set audit policy. STIG: $StigId"
    exit 1
}

# -----------------------------
# Helper: Get current setting
# -----------------------------
function Get-AuditPolSetting {
    param(
        [Parameter(Mandatory)]
        [string]$SubcategoryName
    )

    # Example output line usually looks like:
    # "Detailed File Share                   Failure"
    # or "Detailed File Share                   Success and Failure"
    $raw = & auditpol.exe /get /subcategory:$SubcategoryName 2>$null
    if (-not $raw) { return $null }

    $line = $raw | Where-Object { $_ -match "^\s*$([regex]::Escape($SubcategoryName))\s+" } | Select-Object -First 1
    if (-not $line) { return $null }

    # Return the trailing setting text (everything after the subcategory name)
    return ($line -replace "^\s*$([regex]::Escape($SubcategoryName))\s+", "").Trim()
}

try {
    # 1) Read current audit policy for the subcategory
    $currentSetting = Get-AuditPolSetting -SubcategoryName $Subcategory

    if ($null -eq $currentSetting) {
        Write-Warning "Could not read AuditPol setting for '$Subcategory'. Attempting to set it anyway..."
    } else {
        Write-Host "Current '$Subcategory' setting: $currentSetting"
    }

    # 2) Determine compliance: Failure must be enabled
    $isCompliant = $false
    if ($currentSetting) {
        # Compliant if the setting includes the word "Failure" (e.g., "Failure" or "Success and Failure")
        $isCompliant = ($currentSetting -match '\bFailure\b') -and ($currentSetting -notmatch 'No Auditing')
    }

    if ($isCompliant) {
        Write-Host "Compliant: '$Subcategory' is auditing Failures (STIG: $StigId). No changes made."
        exit 0
    }

    # 3) Remediate: Enable Failure auditing for Detailed File Share
    Write-Warning "Non-compliant: Enabling Failure auditing for '$Subcategory' (STIG: $StigId)..."
    & auditpol.exe /set /subcategory:$Subcategory /failure:enable | Out-Null

    # 4) Re-check and report final state
    $finalSetting = Get-AuditPolSetting -SubcategoryName $Subcategory
    Write-Host "Final '$Subcategory' setting: $finalSetting"

    if ($finalSetting -and ($finalSetting -match '\bFailure\b') -and ($finalSetting -notmatch 'No Auditing')) {
        Write-Host "Remediation successful: Failures are now audited for '$Subcategory' (STIG: $StigId)."
        exit 0
    } else {
        Write-Error "Remediation may have failed: '$Subcategory' does not show Failure auditing enabled. STIG: $StigId"
        exit 1
    }

} catch {
    Write-Error "Failed to check/remediate $StigId. Details: $($_.Exception.Message)"
    exit 1
}
