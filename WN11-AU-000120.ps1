<#
.SYNOPSIS
    Remediates STIG WN11-AU-000120 by ensuring Windows 11 audits
    System >> IPsec Driver - Failure using AuditPol.

.NOTES
    Author          : Alejandro Castillo
    LinkedIn        : linkedin.com/in/alejandro-castillo-156907218/
    GitHub          : github.com/acRei
    Date Created    : 2026-1-26
    Last Modified   : 2026-1-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000120

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run in an elevated PowerShell session (Run as Administrator).
    Example:
    PS C:\> .\WN11-AU-000120-Audit-IPsec-Driver-Failures.ps1

    Check reference:
    - AuditPol /get /category:*
    Required:
    - System >> IPsec Driver - Failure
#>

# -----------------------------
# Configuration (STIG baseline)
# -----------------------------
$StigId      = "WN11-AU-000120"
$Subcategory = "IPsec Driver"

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
# Helper: Get current AuditPol setting (for one subcategory)
# -----------------------------
function Get-AuditPolSetting {
    param(
        [Parameter(Mandatory)]
        [string]$SubcategoryName
    )

    $raw = & auditpol.exe /get /subcategory:$SubcategoryName 2>$null
    if (-not $raw) { return $null }

    $line = $raw | Where-Object { $_ -match "^\s*$([regex]::Escape($SubcategoryName))\s+" } | Select-Object -First 1
    if (-not $line) { return $null }

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
        $isCompliant = ($currentSetting -match '\bFailure\b') -and ($currentSetting -notmatch 'No Auditing')
    }

    if ($isCompliant) {
        Write-Host "Compliant: '$Subcategory' is auditing Failures (STIG: $StigId). No changes made."
        exit 0
    }

    # 3) Remediate: Enable Failure auditing for IPsec Driver
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
