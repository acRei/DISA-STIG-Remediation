<#
.SYNOPSIS
    Ensures BitLocker "Configure minimum PIN length for startup" is compliant by creating/setting
    HKLM:\SOFTWARE\Policies\Microsoft\FVE\MinimumPIN to 6 (or greater) per STIG WN11-00-000032.

.NOTES
    Author          : Alejandro Castillo
    LinkedIn        : linkedin.com/in/alejandro-castillo-156907218/
    GitHub          : github.com/acRei
    Date Created    : 2026-1-28
    Last Modified   : 2026-1-28
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000032

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run in an elevated PowerShell session (Run as Administrator).
    Example:
    PS C:\> .\WN11-00-000032-Configure-Minimum-BitLocker-PIN.ps1

    Notes:
    - This script sets the policy registry value used by Group Policy:
      HKLM\SOFTWARE\Policies\Microsoft\FVE\MinimumPIN
    - If you manage BitLocker settings via domain GPO, apply via GPO instead.
#>

$path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$name = "MinimumPIN"
$min  = 6

# Create the key if missing
if (-not (Test-Path $path)) {
  New-Item -Path $path -Force | Out-Null
}

# Read current value (if it exists)
$current = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name

# Create or raise it to at least 6
if ($null -eq $current) {
  New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $min -Force | Out-Null
}
elseif ([int]$current -lt $min) {
  Set-ItemProperty -Path $path -Name $name -Value $min -Type DWord
}

# Output final value
(Get-ItemProperty -Path $path -Name $name).$name
