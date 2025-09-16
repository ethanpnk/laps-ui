#requires -Version 5.1
<#!
.SYNOPSIS
    Helper module to authenticate to Microsoft Graph and retrieve Windows LAPS
    secrets for Intune managed devices.
#>

function Ensure-LapsGraphModule {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw [System.Exception]::new('GraphModuleMissing')
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null
    try {
        Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue | Out-Null
    } catch {
        # DeviceManagement module is optional; ignore load failures.
    }
}

function Connect-IntuneGraph {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$Scopes = @('DeviceManagementManagedDevices.Read.All')
    )

    Ensure-LapsGraphModule
    Connect-MgGraph -Scopes $Scopes -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
    $ctx = Get-MgContext
    if (-not $ctx) {
        throw "Unable to obtain Microsoft Graph context."
    }
    return $ctx
}

function Disconnect-IntuneGraph {
    [CmdletBinding()]
    param()

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    } catch {
        # Ignore disconnect failures.
    }
}

function Search-IntuneDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceName,

        [Parameter()]
        [int]$Top = 25
    )

    Ensure-LapsGraphModule

    $safe = $DeviceName.Replace("'", "''")
    $filters = @()
    if ($safe) {
        $filters += "deviceName eq '$safe'"
        $filters += "startsWith(deviceName,'$safe')"
    }

    $results = @()
    foreach ($filter in $filters) {
        $encodedFilter = [Uri]::EscapeDataString($filter)
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=$encodedFilter&`$top=$Top"
        try {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($resp.value) {
                $results += $resp.value
            }
        } catch {
            throw
        }
    }

    if (-not $results) {
        return @()
    }

    $unique = @{}
    foreach ($dev in $results) {
        if ($dev.id -and -not $unique.ContainsKey($dev.id)) {
            $unique[$dev.id] = $dev
        }
    }

    return @($unique.Values)
}

function Get-IntuneLapsPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId
    )

    Ensure-LapsGraphModule

    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$DeviceId/windowsLapsManagedDeviceInformation"
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop

    $expiration = $null
    if ($resp.passwordExpirationDateTime) {
        try {
            $expiration = ([DateTime]::Parse($resp.passwordExpirationDateTime)).ToLocalTime()
        } catch {
            $expiration = $null
        }
    }

    [pscustomobject]@{
        Password             = $resp.password
        PasswordExpiration   = $expiration
        AdministratorAccount = $resp.administratorAccountName
        Raw                  = $resp
    }
}

Export-ModuleMember -Function @(
    'Connect-IntuneGraph',
    'Disconnect-IntuneGraph',
    'Search-IntuneDevices',
    'Get-IntuneLapsPassword'
)
