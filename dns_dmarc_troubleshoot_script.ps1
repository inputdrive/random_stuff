<#
.SYNOPSIS
    Checks whether a domain publishes a DMARC TXT record.

.DESCRIPTION
    Asks for a full domain name such as example.com, then queries
    _dmarc.<domain>. A name that already starts with _dmarc. is queried
    as entered.

.PARAMETER Domain
    Full domain name. When omitted, the script prompts for it.

.EXAMPLE
    .\dns_dmarc_troubleshoot_script.ps1

.EXAMPLE
    .\dns_dmarc_troubleshoot_script.ps1 -Domain example.com
#>
[CmdletBinding()]
param(
    [string]$Domain
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-DmarcQuery {
    param([string]$Raw)

    $name = $Raw.Trim()
    if ($name -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
        $name = ([Uri]$name).IdnHost
    }
    $name = $name.Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($name) -or $name -notmatch '\.' -or $name -match '\s|/') {
        throw "Enter a full domain name such as example.com"
    }

    if ($name -match '(?i)^_dmarc\.(.+)$') {
        return [pscustomobject]@{
            Display = $Matches[1]
            Query   = $name
        }
    }

    return [pscustomobject]@{
        Display = $name
        Query   = "_dmarc.$name"
    }
}

if ([string]::IsNullOrWhiteSpace($Domain)) {
    $Domain = Read-Host "Enter the full domain name (example: example.com)"
}

try {
    $query = Get-DmarcQuery -Raw $Domain
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    exit 2
}

try {
    $records = @(
        Resolve-DnsName -Name $query.Query -Type TXT -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Type -eq 'TXT' }
    )
}
catch {
    $message = $_.Exception.Message
    if ($message -match 'does not exist|name error|no records|NXDOMAIN') {
        Write-Host "$($query.Display) : DMARC MISSING" -ForegroundColor Red
        exit 1
    }
    Write-Host "$($query.Display) : LOOKUP FAILED: $message" -ForegroundColor Red
    exit 2
}

$texts = @(
    foreach ($record in $records) {
        $joined = -join @($record.Strings)
        if (-not [string]::IsNullOrWhiteSpace($joined)) {
            $joined
        }
    }
)

if (-not $texts -or $texts.Count -eq 0) {
    Write-Host "$($query.Display) : DMARC MISSING" -ForegroundColor Red
    exit 1
}

$dmarc = @($texts | Where-Object { $_ -match '^(?i)\s*v=DMARC1\b' })
if ($dmarc.Count -eq 0) {
    Write-Host "$($query.Display) : TXT FOUND, NOT A DMARC RECORD" -ForegroundColor Yellow
    foreach ($text in $texts) {
        Write-Host "  $text"
    }
    exit 1
}

Write-Host "$($query.Display) : DMARC FOUND" -ForegroundColor Green
foreach ($text in $dmarc) {
    Write-Host "  $text"
}
exit 0
