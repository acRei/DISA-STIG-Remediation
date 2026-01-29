<#
.SYNOPSIS
    Remediates STIG WN11-CC-000285 by requiring secure (encrypted) RPC communication for
    Remote Desktop Session Host via the policy registry value fEncryptRPCTraffic = 1.

.NOTES
    Author          : Alejandro Castillo
    LinkedIn        : linkedin.com/in/alejandro-castillo-156907218/
    GitHub          : github.com/acRei
    Date Created    : 2026-1-28
    Last Modified   : 2026-1-28
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000285

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run in an elevated PowerShell session (Run as Administrator).
    Example:
    PS C:\> .\WN11-CC-000285-Require-Secure-RPC-RDSH.ps1

    This sets the policy registry value:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic = 1
#>

# -----------------------------
# Configuration (STIG baseline)
# -----------------------------
$StigId = "WN11-CC-000285"
$Path   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$Name   = "fEncryptRPCTraffic"
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
    # 1) Ensure the policy key exists
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
        Write-Host "Created missing registry key: $Path"
    }

    # 2) Read current value (if any)
    $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name

    # 3) Create the value if it doesn't exist, or set it to the required value if incorrect
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
