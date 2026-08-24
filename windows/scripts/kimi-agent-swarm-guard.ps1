[CmdletBinding()]
param(
    [ValidateRange(1, 128)]
    [int]$MaxNewAgentsPerSession = 4,

    [Parameter(Mandatory)]
    [string]$StateDirectory
)

$ErrorActionPreference = 'Stop'

function Deny([string]$message) {
    [Console]::Error.WriteLine($message)
    exit 2
}

try {
    $inputText = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($inputText)) {
        Deny 'AgentSwarm was blocked because its policy hook received no input.'
    }

    $request = $inputText | ConvertFrom-Json -ErrorAction Stop
    if ([string]$request.tool_name -cne 'AgentSwarm') { exit 0 }
    if ([string]::IsNullOrWhiteSpace([string]$request.session_id)) {
        Deny 'AgentSwarm was blocked because the session id is missing.'
    }

    $items = @($request.tool_input.items)
    $newAgentCount = @($items | Where-Object { $null -ne $_ }).Count
    if ($newAgentCount -eq 0) { exit 0 }

    [void][IO.Directory]::CreateDirectory($StateDirectory)
    $sessionBytes = [Text.Encoding]::UTF8.GetBytes([string]$request.session_id)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $sessionHash = -join ($hasher.ComputeHash($sessionBytes) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $hasher.Dispose()
    }
    $statePath = Join-Path $StateDirectory ($sessionHash + '.count')

    $used = 0
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $raw = [IO.File]::ReadAllText($statePath).Trim()
        if (-not [int]::TryParse($raw, [ref]$used) -or $used -lt 0) {
            Deny 'AgentSwarm was blocked because its session policy state is invalid.'
        }
    }

    $requestedTotal = $used + $newAgentCount
    if ($requestedTotal -gt $MaxNewAgentsPerSession) {
        Deny "AgentSwarm is limited to $MaxNewAgentsPerSession new subagents per conversation; $used already used and $newAgentCount requested. Continue locally or reuse existing agents."
    }

    [IO.File]::WriteAllText($statePath, [string]$requestedTotal, [Text.UTF8Encoding]::new($false))

    Get-ChildItem -LiteralPath $StateDirectory -Filter '*.count' -File -ErrorAction SilentlyContinue |
        Where-Object LastWriteTimeUtc -lt ([DateTime]::UtcNow.AddDays(-30)) |
        Remove-Item -Force -ErrorAction SilentlyContinue
} catch {
    Deny ('AgentSwarm was blocked because its policy hook failed: ' + $_.Exception.Message)
}

exit 0
