<#
.SYNOPSIS
    Remediates STIG WN11-CC-000197 by turning off Microsoft consumer experiences to prevent
    unwanted suggested app installations via DisableWindowsConsumerFeatures = 1.
    Creates the CloudContent policy key if it does not exist.

.NOTES
    Author          : Alejandro Castillo
    LinkedIn        : linkedin.com/in/alejandro-castillo-156907218/
    GitHub          : github.com/acRei
    Date Created    : 2026-1-26
    Last Modified   : 2026-1-26
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run in an elevated PowerShell session (Run as Administrator).
    Example:
    PS C:\> .\WN11-CC-000197-Turn-Off-Microsoft-Consumer-Experiences.ps1

    This sets the registry value:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures = 1
#>

# -----------------------------
# Configuration (STIG baseline)
# -----------------------------
$StigId = "WN11-CC-000197"
$Path   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$Name   = "DisableWindowsConsumerFeatures"
$Value  = 1

# -----------------------------
# Helper: Admin check
# -----------------------------
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal       = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator to modify HKLM. STIG: $StigId"
    exit 1
}

try {
    # 1) Create the full key path if it doesn't exist (including CloudContent)
    New-Item -Path $Path -Force | Out-Null

    # 2) Read current value (if any)
    $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name

    # 3) Create or set the value to the required value
    if ($null -eq $current) {
        New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
        Write-Host "Created '$Name' and set to $Value (compliant with $StigId)."
    }
    elseif ([int]$current -ne $Value) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
        Write-Host "'$Name' was $current; updated to $Value (compliant with $StigId)."
    }
    else {
        Write-Host "'$Name' is already $current (compliant with $StigId). No changes made."
    }

    # 4) Output final setting for verification/logging
    $final = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    Write-Host "Final setting: $Path\$Name = $final"

} catch {
    Write-Error "Failed to remediate $StigId. Details: $($_.Exception.Message)"
    exit 1
}
