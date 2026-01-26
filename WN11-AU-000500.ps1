<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Alejandro Castillo
    LinkedIn        : linkedin.com/in/alejandro-castillo-156907218/
    GitHub          : github.com/acRei
    Date Created    : 2026-1-26
    Last Modified   : 2026-1-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN11-AU-000500.ps1 
#>

<# 
Checks for the Application Event Log policy key/value (MaxSize).
If missing, creates the key and/or value and sets it to 32768 (KB).
If present but smaller than 32768, raises it to 32768.
#>

$Path     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$Name     = "MaxSize"
$MinValue = 32768  # KB

try {
    # Ensure the registry key exists
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
        Write-Host "Created missing key: $Path"
    }

    # Read existing value (if any)
    $current = $null
    try {
        $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        # Value does not exist
        $current = $null
    }

    if ($null -eq $current) {
        # Create the value if missing
        New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $MinValue -Force | Out-Null
        Write-Host "Created $Name and set to $MinValue KB (compliant)."
    }
    elseif ([int]$current -lt $MinValue) {
        # Raise value if too small
        Set-ItemProperty -Path $Path -Name $Name -Value $MinValue -Type DWord
        Write-Host "$Name was $current KB; updated to $MinValue KB (compliant)."
    }
    else {
        Write-Host "$Name is $current KB (compliant). No changes made."
    }

} catch {
    Write-Error "Failed to check/apply $Path\$Name. Run PowerShell as Administrator. Details: $($_.Exception.Message)"
    exit 1
}
