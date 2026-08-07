[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$KimiToolRoot
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($KimiToolRoot)
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Kimi tool root is missing: $root"
}
$serverPath = Join-Path $root 'Lib\site-packages\kimi_cli\acp\server.py'
if (-not (Test-Path -LiteralPath $serverPath -PathType Leaf)) {
    throw "Kimi ACP server source is missing: $serverPath"
}

$source = [IO.File]::ReadAllText($serverPath)
$marker = 'def _check_static_api_key_usable() -> bool:'
if ($source.Contains($marker)) {
    if (($source.Split($marker).Count - 1) -ne 1) {
        throw 'Kimi ACP static API-key compatibility patch is duplicated.'
    }
    return
}

$needle = @'
    def _check_auth(self) -> None:
        """Check if Kimi Code authentication is complete. Raise AUTH_REQUIRED if not."""
        reason = self._check_token_usable()
'@
$replacement = @'
    @staticmethod
    def _check_static_api_key_usable() -> bool:
        """Return whether the configured default model uses a complete static API-key provider."""
        try:
            config = load_config()
            model = config.models.get(config.default_model) if config.default_model else None
            provider = config.providers.get(model.provider) if model else None
            return bool(
                model
                and provider
                and provider.oauth is None
                and provider.base_url
                and model.model
                and provider.api_key.get_secret_value()
            )
        except Exception:
            return False

    def _check_auth(self) -> None:
        """Check if the configured static API key or Kimi Code OAuth is complete."""
        if self._check_static_api_key_usable():
            return
        reason = self._check_token_usable()
'@
$occurrences = $source.Split($needle).Count - 1
if ($occurrences -ne 1) {
    throw "Expected exactly one supported Kimi ACP authentication block, found $occurrences."
}
$patched = $source.Replace($needle, $replacement)
[IO.File]::WriteAllText($serverPath, $patched, [Text.UTF8Encoding]::new($false))
