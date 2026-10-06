<#
.SYNOPSIS
    Audits Windows startup registry entries and optionally removes residual
    configurations that leave ghost items in the Startup GUI (Task Manager /
    Settings > Apps > Startup).

.DESCRIPTION
    Scans Run / RunOnce and Explorer\StartupApproved keys under HKCU and HKLM
    (including Wow6432Node). Flags:
      - Orphaned StartupApproved values with no matching Run / StartupFolder entry
      - Run entries whose target executable no longer exists
      - StartupApproved entries whose linked path no longer exists

    Default mode is audit-only. Pass -Clean to remove residuals (supports -WhatIf).

.PARAMETER Clean
    Remove residual registry values instead of only reporting them.

.PARAMETER IncludeStartupFolders
    Also scan user and common Startup folders for broken shortcuts.

.PARAMETER ExportPath
    Optional path to write a JSON audit report.

.EXAMPLE
    .\Audit-StartupResiduals.ps1

.EXAMPLE
    .\Audit-StartupResiduals.ps1 -Clean -WhatIf

.EXAMPLE
    .\Audit-StartupResiduals.ps1 -Clean -IncludeStartupFolders -ExportPath .\startup-audit.json
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Clean,
    [switch]$IncludeStartupFolders,
    [string]$ExportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ExecutablePathFromCommand {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $null
    }

    $trimmed = $CommandLine.Trim()

    # Quoted path: "C:\Path\app.exe" args
    if ($trimmed -match '^"([^"]+)"') {
        return $Matches[1]
    }

    # Unquoted path with optional args — take first token if it looks like a path
    if ($trimmed -match '^([A-Za-z]:\\[^\s]+)') {
        return $Matches[1]
    }

    # Environment-expanded paths
    $expanded = [Environment]::ExpandEnvironmentVariables($trimmed)
    if ($expanded -match '^"([^"]+)"') {
        return $Matches[1]
    }
    if ($expanded -match '^([A-Za-z]:\\[^\s]+)') {
        return $Matches[1]
    }

    # Bare executable name (PATH lookup not performed — treat as present if non-empty)
    if ($trimmed -match '^[^\s\\/]+\.exe(\s|$)') {
        return $null  # cannot verify; skip missing-file flag
    }

    return $null
}

function Test-PathExistsSafe {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $true  # unverifiable — do not treat as residual
    }

    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($Path)
        return (Test-Path -LiteralPath $expanded -PathType Leaf) -or
               (Test-Path -LiteralPath $expanded -PathType Container)
    }
    catch {
        return $false
    }
}

function Get-RegistryValueMap {
    param([string]$KeyPath)

    $map = @{}
    if (-not (Test-Path -LiteralPath $KeyPath)) {
        return $map
    }

    try {
        $key = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
        foreach ($name in $key.GetValueNames()) {
            if ([string]::IsNullOrEmpty($name)) { continue }
            $map[$name] = $key.GetValue($name)
        }
    }
    catch {
        Write-Warning "Could not read $KeyPath : $_"
    }

    return $map
}

function Get-StartupApprovedState {
    param([byte[]]$Binary)

    if (-not $Binary -or $Binary.Length -lt 4) {
        return 'Unknown'
    }

    # First byte: 0x02/0x03 often enabled; 0x01 disabled (varies by Windows build)
    switch ($Binary[0]) {
        0x00 { return 'Disabled' }
        0x01 { return 'Disabled' }
        0x02 { return 'Enabled' }
        0x03 { return 'Enabled' }
        default { return ('Raw:0x{0:X2}' -f $Binary[0]) }
    }
}

# --- Registry locations that feed the Startup GUI ---

$runRoots = @(
    @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'CurrentUser' },
    @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'CurrentUser' },
    @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'LocalMachine'; Admin = $true },
    @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'LocalMachine'; Admin = $true },
    @{ Hive = 'HKLM'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Scope = 'LocalMachine32'; Admin = $true },
    @{ Hive = 'HKLM'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'LocalMachine32'; Admin = $true }
)

$approvedRoots = @(
    @{
        Path         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        RelatedRuns  = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
        Kind         = 'Run'
        Scope        = 'CurrentUser'
    },
    @{
        Path         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        RelatedRuns  = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
        Kind         = 'Run32'
        Scope        = 'CurrentUser'
    },
    @{
        Path         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
        RelatedRuns  = @()
        Kind         = 'StartupFolder'
        Scope        = 'CurrentUser'
        FolderPaths  = @(
            [Environment]::GetFolderPath('Startup')
        )
    },
    @{
        Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        RelatedRuns  = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        Kind         = 'Run'
        Scope        = 'LocalMachine'
        Admin        = $true
    },
    @{
        Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        RelatedRuns  = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        Kind         = 'Run32'
        Scope        = 'LocalMachine'
        Admin        = $true
    },
    @{
        Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
        RelatedRuns  = @()
        Kind         = 'StartupFolder'
        Scope        = 'LocalMachine'
        Admin        = $true
        FolderPaths  = @(
            [Environment]::GetFolderPath('CommonStartup')
        )
    }
)

$isAdmin = Test-IsAdmin
$findings = [System.Collections.Generic.List[object]]::new()
$removed  = [System.Collections.Generic.List[object]]::new()

Write-Host ''
Write-Host '=== Windows Startup Residual Audit ===' -ForegroundColor Cyan
Write-Host ("Run as admin: {0}" -f $isAdmin)
Write-Host ("Mode:         {0}" -f $(if ($Clean) { 'CLEAN' } else { 'AUDIT (read-only)' }))
Write-Host ''

# Build Run name -> command maps
$runMaps = @{}
foreach ($root in $runRoots) {
    if ($root.Admin -and -not $isAdmin) {
        Write-Warning "Skipping $($root.Path) (requires elevation)."
        continue
    }
    $runMaps[$root.Path] = Get-RegistryValueMap -KeyPath $root.Path
}

# --- 1. Run entries with missing targets ---
Write-Host '--- Run / RunOnce entries ---' -ForegroundColor Yellow
foreach ($root in $runRoots) {
    if (-not $runMaps.ContainsKey($root.Path)) { continue }
    $values = $runMaps[$root.Path]
    if ($values.Count -eq 0) {
        Write-Host "  [empty] $($root.Path)"
        continue
    }

    foreach ($name in ($values.Keys | Sort-Object)) {
        $command = [string]$values[$name]
        $exePath = Get-ExecutablePathFromCommand -CommandLine $command
        $missing = $false
        if ($null -ne $exePath -and -not (Test-PathExistsSafe -Path $exePath)) {
            $missing = $true
        }

        $status = if ($missing) { 'RESIDUAL (missing file)' } else { 'OK' }
        $color  = if ($missing) { 'Red' } else { 'Green' }
        Write-Host ("  [{0}] {1} = {2}" -f $status, $name, $command) -ForegroundColor $color

        if ($missing) {
            $item = [pscustomobject]@{
                Category     = 'MissingTarget'
                Kind         = 'Run'
                RegistryPath = $root.Path
                Name         = $name
                Command      = $command
                TargetPath   = $exePath
                Reason       = 'Executable path does not exist'
            }
            $findings.Add($item)

            if ($Clean) {
                $target = Join-Path $root.Path $name
                if ($PSCmdlet.ShouldProcess($target, 'Remove residual Run value')) {
                    Remove-ItemProperty -LiteralPath $root.Path -Name $name -Force
                    $removed.Add($item)
                    # Drop from in-memory map so StartupApproved pass treats it as orphaned
                    if ($runMaps.ContainsKey($root.Path) -and $runMaps[$root.Path].ContainsKey($name)) {
                        $runMaps[$root.Path].Remove($name)
                    }
                    Write-Host "    -> removed" -ForegroundColor Magenta
                }
            }
        }
    }
}

# --- 2. Orphaned / broken StartupApproved entries (ghost GUI items) ---
Write-Host ''
Write-Host '--- StartupApproved (Startup GUI state) ---' -ForegroundColor Yellow

foreach ($root in $approvedRoots) {
    if ($root.Admin -and -not $isAdmin) {
        Write-Warning "Skipping $($root.Path) (requires elevation)."
        continue
    }

    if (-not (Test-Path -LiteralPath $root.Path)) {
        Write-Host "  [missing key] $($root.Path)"
        continue
    }

    $approved = Get-RegistryValueMap -KeyPath $root.Path
    if ($approved.Count -eq 0) {
        Write-Host "  [empty] $($root.Path)"
        continue
    }

    # Collect related Run names
    $relatedNames = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($runPath in $root.RelatedRuns) {
        if ($runMaps.ContainsKey($runPath)) {
            foreach ($n in $runMaps[$runPath].Keys) {
                [void]$relatedNames.Add($n)
            }
        }
        elseif (Test-Path -LiteralPath $runPath) {
            foreach ($n in (Get-RegistryValueMap -KeyPath $runPath).Keys) {
                [void]$relatedNames.Add($n)
            }
        }
    }

    # Startup folder file names (for StartupFolder approved keys)
    $folderFileNames = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    if ($root.Kind -eq 'StartupFolder' -and $root.FolderPaths) {
        foreach ($folder in $root.FolderPaths) {
            if ([string]::IsNullOrWhiteSpace($folder) -or -not (Test-Path -LiteralPath $folder)) {
                continue
            }
            Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$folderFileNames.Add($_.Name) }
        }
    }

    foreach ($name in ($approved.Keys | Sort-Object)) {
        $binary = $approved[$name]
        $state  = if ($binary -is [byte[]]) {
            Get-StartupApprovedState -Binary $binary
        } else {
            'Unknown'
        }

        $isResidual = $false
        $reason     = $null

        if ($root.Kind -eq 'StartupFolder') {
            if (-not $folderFileNames.Contains($name)) {
                $isResidual = $true
                $reason = 'No matching shortcut/file in Startup folder'
            }
        }
        else {
            if (-not $relatedNames.Contains($name)) {
                $isResidual = $true
                $reason = 'No matching value in related Run key(s) — ghost Startup GUI entry'
            }
            else {
                # Matched Run entry exists — check if its target is missing
                foreach ($runPath in $root.RelatedRuns) {
                    $map = if ($runMaps.ContainsKey($runPath)) { $runMaps[$runPath] } else { $null }
                    if ($null -eq $map) { continue }
                    if (-not $map.ContainsKey($name)) { continue }
                    $cmd = [string]$map[$name]
                    $exe = Get-ExecutablePathFromCommand -CommandLine $cmd
                    if ($null -ne $exe -and -not (Test-PathExistsSafe -Path $exe)) {
                        $isResidual = $true
                        $reason = "Matched Run entry points to missing file: $exe"
                    }
                }
            }
        }

        $status = if ($isResidual) { 'RESIDUAL' } else { 'OK' }
        $color  = if ($isResidual) { 'Red' } else { 'Green' }
        Write-Host ("  [{0}] ({1}) {2}\{3}" -f $status, $state, $root.Path, $name) -ForegroundColor $color
        if ($reason) {
            Write-Host "         $reason" -ForegroundColor DarkYellow
        }

        if ($isResidual) {
            $item = [pscustomobject]@{
                Category     = 'OrphanedStartupApproved'
                Kind         = $root.Kind
                RegistryPath = $root.Path
                Name         = $name
                Command      = $null
                TargetPath   = $null
                Reason       = $reason
                GuiState     = $state
            }
            $findings.Add($item)

            if ($Clean) {
                $target = Join-Path $root.Path $name
                if ($PSCmdlet.ShouldProcess($target, 'Remove residual StartupApproved value')) {
                    Remove-ItemProperty -LiteralPath $root.Path -Name $name -Force
                    $removed.Add($item)
                    Write-Host "    -> removed" -ForegroundColor Magenta
                }
            }
        }
    }
}

# --- 3. Optional Startup folder shortcut audit ---
if ($IncludeStartupFolders) {
    Write-Host ''
    Write-Host '--- Startup folders ---' -ForegroundColor Yellow

    $folders = @(
        [pscustomobject]@{ Label = 'User'; Path = [Environment]::GetFolderPath('Startup') },
        [pscustomobject]@{ Label = 'Common'; Path = [Environment]::GetFolderPath('CommonStartup') }
    )

    foreach ($folder in $folders) {
        if ([string]::IsNullOrWhiteSpace($folder.Path) -or -not (Test-Path -LiteralPath $folder.Path)) {
            Write-Host "  [missing] $($folder.Label): $($folder.Path)"
            continue
        }

        $items = @(Get-ChildItem -LiteralPath $folder.Path -Force -ErrorAction SilentlyContinue)
        if ($items.Count -eq 0) {
            Write-Host "  [empty] $($folder.Label): $($folder.Path)"
            continue
        }

        foreach ($file in $items) {
            $broken = $false
            $target = $null

            if ($file.Extension -eq '.lnk') {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($file.FullName)
                    $target = $shortcut.TargetPath
                    if (-not [string]::IsNullOrWhiteSpace($target) -and
                        -not (Test-PathExistsSafe -Path $target)) {
                        $broken = $true
                    }
                }
                catch {
                    $broken = $true
                    $target = '(unreadable shortcut)'
                }
            }

            $status = if ($broken) { 'RESIDUAL (broken shortcut)' } else { 'OK' }
            $color  = if ($broken) { 'Red' } else { 'Green' }
            Write-Host ("  [{0}] {1}\{2}" -f $status, $folder.Path, $file.Name) -ForegroundColor $color
            if ($target) {
                Write-Host "         -> $target"
            }

            if ($broken) {
                $item = [pscustomobject]@{
                    Category     = 'BrokenShortcut'
                    Kind         = 'StartupFolder'
                    RegistryPath = $folder.Path
                    Name         = $file.Name
                    Command      = $null
                    TargetPath   = $target
                    Reason       = 'Startup shortcut target does not exist'
                }
                $findings.Add($item)

                if ($Clean) {
                    if ($PSCmdlet.ShouldProcess($file.FullName, 'Remove broken startup shortcut')) {
                        Remove-Item -LiteralPath $file.FullName -Force
                        $removed.Add($item)
                        Write-Host "    -> removed" -ForegroundColor Magenta
                    }
                }
            }
        }
    }
}

# --- Summary ---
Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor Cyan
Write-Host ("Residuals found:  {0}" -f $findings.Count)
if ($Clean) {
    Write-Host ("Residuals removed: {0}" -f $removed.Count)
}
elseif ($findings.Count -gt 0) {
    Write-Host 'Re-run with -Clean to remove residuals (add -WhatIf to preview).' -ForegroundColor DarkYellow
}

if (-not $isAdmin) {
    Write-Host 'Tip: re-run elevated to include HKLM / machine-wide StartupApproved keys.' -ForegroundColor DarkYellow
}

if ($ExportPath) {
    $report = [pscustomobject]@{
        GeneratedAt     = (Get-Date).ToString('o')
        ComputerName    = $env:COMPUTERNAME
        UserName        = $env:USERNAME
        IsAdmin         = $isAdmin
        Mode            = $(if ($Clean) { 'Clean' } else { 'Audit' })
        Findings        = $findings
        Removed         = $removed
    }
    $dir = Split-Path -Parent $ExportPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ExportPath -Encoding UTF8
    Write-Host "Report written: $ExportPath" -ForegroundColor Cyan
}

# Non-zero exit when residuals exist (useful for automation)
if ($findings.Count -gt 0) {
    exit 2
}
exit 0
