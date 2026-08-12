[CmdletBinding()]
param(
    [string]$GuidePath = (Join-Path $PSScriptRoot '..\..\AionUi\packages\desktop\src\renderer\pages\help\guide.zh-CN.html'),
    [string]$ReferencePath = (Join-Path $PSScriptRoot '..\.tools\AionCore-src\crates\aionui-app\assets\builtin-skills\workagent-help\references\help.zh-CN.md')
)

$resolvedGuide = (Resolve-Path -LiteralPath $GuidePath -ErrorAction Stop).Path
$referenceDirectory = Split-Path -Parent $ReferencePath
if (-not (Test-Path -LiteralPath $referenceDirectory -PathType Container)) {
    throw "WorkAgent help skill reference directory does not exist: $referenceDirectory"
}

$html = Get-Content -Raw -LiteralPath $resolvedGuide
$options = [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

$text = [regex]::Replace($html, '<(style|script)\b[^>]*>.*?</\1>', '', $options)
$text = [regex]::Replace($text, '<(img|svg)\b[^>]*>.*?</\1>', '', $options)
$text = [regex]::Replace($text, '<img\b[^>]*?/?>', '', $options)
$text = [regex]::Replace($text, '<h1\b[^>]*>', "`n# ", $options)
$text = [regex]::Replace($text, '<h2\b[^>]*>', "`n## ", $options)
$text = [regex]::Replace($text, '<h3\b[^>]*>', "`n### ", $options)
$text = [regex]::Replace($text, '</h[1-3]>', "`n", $options)
$text = [regex]::Replace($text, '<li\b[^>]*>', '- ', $options)
$text = [regex]::Replace($text, '</li>', "`n", $options)
$text = [regex]::Replace($text, '<br\s*/?>', "`n", $options)
$text = [regex]::Replace($text, '</p>', "`n", $options)
$text = [regex]::Replace($text, '</tr>', "`n", $options)
$text = [regex]::Replace($text, '</t[dh]>', "`n", $options)
$text = [regex]::Replace($text, '<[^>]+>', '', $options)
$text = [System.Net.WebUtility]::HtmlDecode($text)

$normalizedLines = foreach ($line in ($text -split "`r?`n")) {
    ($line -replace '[\t ]+', ' ').Trim()
}
$normalized = ($normalizedLines -join "`n") -replace "(`n\s*){3,}", "`n`n"
$header = @'
# WorkAgent 中文帮助文档

> 此文件由 WorkAgent 内置中文帮助文档自动生成。请勿手工编辑。

'@

Set-Content -LiteralPath $ReferencePath -Value ($header + $normalized.Trim() + "`n") -Encoding utf8
Write-Host "Synced WorkAgent help reference: $ReferencePath"
