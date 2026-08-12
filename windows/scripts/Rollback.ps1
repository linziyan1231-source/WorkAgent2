[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$PortalCli = 'C:\Program Files\AionUiPortal\portal.exe',
    [string]$RollbackEvidencePath
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
$portalConfig = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$publicUri = [Uri][string]$portalConfig.public_base_url
if (-not $publicUri.IsAbsoluteUri -or $publicUri.Scheme -notin @('http', 'https')) { throw 'Portal public_base_url has an unsupported scheme.' }
$healthUri = ('{0}://127.0.0.1:25808/healthz' -f $publicUri.Scheme)
$stoppedServices = [Collections.Generic.List[string]]::new()
try {
    foreach ($serviceName in @('AionUiPortalAdmin', 'AionUiPortal', 'AionKimiDatasourceBroker')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -Force -ErrorAction Stop
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            $stoppedServices.Add($serviceName)
        }
    }
    & (Join-Path $PSScriptRoot 'Stop-AllInstances.ps1') -PortalCli $PortalCli -ConfigPath $ConfigPath
    if ([string]::IsNullOrWhiteSpace($RollbackEvidencePath)) {
        & $PortalCli --config $ConfigPath release rollback
        if ($LASTEXITCODE -ne 0) { throw 'Release rollback failed.' }
    } else {
        $evidencePath = (Resolve-Path -LiteralPath $RollbackEvidencePath).Path
        $expectedEvidenceRoot = [IO.Path]::GetFullPath('C:\ProgramData\AionUiPortal\upgrade-rollback').TrimEnd('\') + '\'
        if (-not $evidencePath.StartsWith($expectedEvidenceRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Rollback evidence must be under the protected Portal upgrade-rollback directory.'
        }
        $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
        if ($evidence.format_version -ne 1 -or [string]::IsNullOrWhiteSpace([string]$evidence.release_id)) { throw 'Rollback evidence format is invalid.' }
        $allowedTargets = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [void]$allowedTargets.Add([IO.Path]::GetFullPath($ConfigPath))
        [void]$allowedTargets.Add([IO.Path]::GetFullPath([string]$portalConfig.current_release_file))
        foreach ($name in @('AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionKimiDatasourceBroker.exe')) {
            [void]$allowedTargets.Add([IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PortalCli) $name)))
        }
        $userConfigRoot = [string]$portalConfig.user_config_root
        if ($userConfigRoot -and (Test-Path -LiteralPath $userConfigRoot -PathType Container)) {
            foreach ($sidDir in @(Get-ChildItem -LiteralPath $userConfigRoot -Directory -Force)) {
                if ($sidDir.Name -notmatch '^S-1-[0-9-]+$') { throw "Unexpected non-SID UserHost config directory: $($sidDir.FullName)" }
                [void]$allowedTargets.Add([IO.Path]::GetFullPath((Join-Path $sidDir.FullName 'userhost.json')))
            }
        }
        foreach ($entry in @($evidence.entries)) {
            $target = [IO.Path]::GetFullPath([string]$entry.target)
            if (-not $allowedTargets.Contains($target)) { throw "Rollback evidence contains a target outside the release boundary: $target" }
            if ([bool]$entry.existed) {
                $backup = [IO.Path]::GetFullPath([string]$entry.backup)
                if (-not $backup.StartsWith((Split-Path -Parent $evidencePath).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Rollback backup escaped evidence directory: $backup" }
                $backupHash = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($backupHash -cne [string]$entry.sha256) { throw "Rollback backup hash mismatch: $backup" }
                Copy-Item -LiteralPath $backup -Destination $target -Force
            } elseif (Test-Path -LiteralPath $target -PathType Leaf) {
                Remove-Item -LiteralPath $target -Force
            }
        }
    }
    & $PortalCli --config $ConfigPath acl apply
    if ($LASTEXITCODE -ne 0) { throw 'Post-rollback ACL application failed.' }
    & $PortalCli --config $ConfigPath acl verify
    if ($LASTEXITCODE -ne 0) { throw 'Post-rollback integrity/ACL verification failed.' }
} finally {
    foreach ($serviceName in @('AionUiPortal', 'AionUiPortalAdmin', 'AionKimiDatasourceBroker')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Stopped') {
            try {
                Start-Service -Name $serviceName -ErrorAction Stop
                (Get-Service $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            } catch { Write-Warning "Failed to restart $serviceName after rollback: $($_.Exception.Message)" }
        }
    }
}
$handler = New-Object Net.Http.HttpClientHandler
$handler.UseProxy = $false
if ($publicUri.Scheme -eq 'https') {
    $handler.ServerCertificateCustomValidationCallback = [Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
}
$client = [Net.Http.HttpClient]::new($handler)
try {
    $response = $client.GetAsync($healthUri).GetAwaiter().GetResult()
    if (-not $response.IsSuccessStatusCode) { throw "Portal health check returned HTTP $([int]$response.StatusCode)." }
} finally { $client.Dispose(); $handler.Dispose() }
Write-Host 'Rollback completed without deleting or restoring over user data.'
