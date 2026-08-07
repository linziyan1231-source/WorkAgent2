[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$BuildManifestPath,
    [Parameter(Mandatory)][string]$NotificationPath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:+-]{2,199}$')][string]$NotificationId,
    [string]$Title = '系统升级通知'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseContract.ps1')

foreach ($path in @($BuildManifestPath, $NotificationPath)) {
    if (-not [IO.Path]::IsPathFullyQualified($path)) { throw "Path must be absolute: $path" }
}
if (-not (Test-Path -LiteralPath $BuildManifestPath -PathType Leaf)) {
    throw "Build manifest is missing: $BuildManifestPath"
}
$manifestItem = Get-Item -LiteralPath $BuildManifestPath -Force
if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Build manifest must not be a reparse point: $BuildManifestPath"
}
$manifest = Get-Content -LiteralPath $BuildManifestPath -Raw | ConvertFrom-Json
$scope = [string]$manifest.release_scope
$components = @($manifest.included_components | ForEach-Object { [string]$_ })
Assert-ReleaseScopeContract -ReleaseScope $scope -IncludedComponents $components

$destination = [IO.Path]::GetFullPath($NotificationPath)
$parent = Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "Notification parent directory is missing: $parent"
}
$parentItem = Get-Item -LiteralPath $parent -Force
if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Notification parent directory must not be a reparse point: $parent"
}
if (Test-Path -LiteralPath $destination) {
    $destinationItem = Get-Item -LiteralPath $destination -Force
    if ($destinationItem.PSIsContainer -or ($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Notification destination must be a normal file: $destination"
    }
}

$interruptionClass = Get-UpgradeInterruptionClass -ReleaseScope $scope -IncludedComponents $components
$message = Get-UpgradeNotificationMessage -ReleaseScope $scope -IncludedComponents $components
$payload = [ordered]@{
    notifications = @([ordered]@{
        id = $NotificationId
        title = $Title
        message = $message
        published_at = [DateTime]::UtcNow.ToString('o')
    })
}
$json = ($payload | ConvertTo-Json -Depth 5 -Compress) + "`n"
if ($PSCmdlet.ShouldProcess($destination, "publish $interruptionClass upgrade notification")) {
    [IO.File]::WriteAllText($destination, $json, [Text.UTF8Encoding]::new($false))
}
Write-Host "Upgrade notification prepared: class=$interruptionClass message=$message"
