param(
  [switch]$NoPause
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) {
  Write-Host "[codex-setup] $msg"
}

function Pause-Exit([int]$code = 0) {
  if ($NoPause) {
    exit $code
  }

  Write-Host ""
  try {
    [void](Read-Host "按回车键退出...")
  }
  catch {
    # ignore pause failure in non-interactive hosts
  }

  exit $code
}

function Test-Command($name) {
  return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function Normalize-BaseUrl([string]$url) {
  $u = $url.TrimEnd("/")
  if (-not ($u.ToLower().StartsWith("http://") -or $u.ToLower().StartsWith("https://"))) {
    $u = "http://$u"
  }
  if ($u.ToLower().EndsWith("/v1")) { return $u }
  return "$u/v1"
}

function Mask-ApiKey([string]$key) {
  if ([string]::IsNullOrWhiteSpace($key)) { return "(未配置)" }
  if ($key.Length -le 6) { return "******" }
  $prefix = $key.Substring(0, 4)
  $suffix = $key.Substring($key.Length - 3)
  return "$prefix******$suffix"
}

function Ensure-NodeNpm {
  if ((Test-Command "node") -and (Test-Command "npm")) { return }

  Write-Info "未检测到 Node.js/npm，尝试通过 winget 安装..."
  if (-not (Test-Command "winget")) {
    throw "未检测到 winget，请先手动安装 Node.js LTS（https://nodejs.org/）"
  }

  winget install OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements
}

function Get-CurrentCodexVersion {
  if (-not (Test-Command "codex")) { return "" }
  $v = (codex --version 2>$null)
  if ([string]::IsNullOrWhiteSpace($v)) { return "" }
  return ($v.Trim().Split(" ") | Select-Object -Last 1)
}

function Get-LatestCodexVersion {
  try {
    $v = (npm view @openai/codex version 2>$null)
    if ([string]::IsNullOrWhiteSpace($v)) { return "" }
    return $v.Trim()
  }
  catch {
    return ""
  }
}

function Install-OrUpdate-Codex {
  $localVer = Get-CurrentCodexVersion
  $latestVer = Get-LatestCodexVersion

  if (-not [string]::IsNullOrWhiteSpace($localVer) -and -not [string]::IsNullOrWhiteSpace($latestVer) -and $localVer -eq $latestVer) {
    Write-Info "Codex CLI 已是最新版本: $localVer"
    return
  }

  if (-not [string]::IsNullOrWhiteSpace($localVer) -and -not [string]::IsNullOrWhiteSpace($latestVer)) {
    Write-Info "检测到 Codex CLI 可更新: $localVer -> $latestVer"
  }
  elseif (-not [string]::IsNullOrWhiteSpace($localVer)) {
    Write-Info "已安装 Codex CLI 版本: $localVer（无法获取远程版本，将继续使用当前版本）"
    return
  }
  else {
    Write-Info "未检测到 Codex CLI，开始安装..."
  }

  Write-Info "正在安装/更新 Codex CLI..."
  npm install -g @openai/codex@latest
  Write-Info ("当前版本: " + (codex --version))
}

function Save-UserEnv($baseUrl, $apiKey) {
  [Environment]::SetEnvironmentVariable("OPENAI_BASE_URL", $baseUrl, "User")
  [Environment]::SetEnvironmentVariable("OPENAI_API_KEY", $apiKey, "User")
  $env:OPENAI_BASE_URL = $baseUrl
  $env:OPENAI_API_KEY = $apiKey
}

function Try-CodexLogin($baseUrl, $apiKey) {
  Write-Info "正在写入 Codex 登录态..."
  try {
    $apiKey | codex login --with-api-key *> $null
    Write-Info "Codex 登录态写入成功。"
  }
  catch {
    Write-Info "Codex 登录态写入失败（不影响环境变量配置）。"
    Write-Info "可手动执行: `$env:OPENAI_BASE_URL='$baseUrl'; codex login --with-api-key"
  }
}

function Resolve-Config {
  $existingUrl = [Environment]::GetEnvironmentVariable("OPENAI_BASE_URL", "User")
  $existingKey = [Environment]::GetEnvironmentVariable("OPENAI_API_KEY", "User")

  if (-not [string]::IsNullOrWhiteSpace($existingUrl) -or -not [string]::IsNullOrWhiteSpace($existingKey)) {
    Write-Info "检测到当前配置："
    if (-not [string]::IsNullOrWhiteSpace($existingUrl)) {
      Write-Info "- URL: $existingUrl"
    }
    else {
      Write-Info "- URL: (未配置)"
    }

    Write-Info ("- API Key: " + (Mask-ApiKey $existingKey))
  }
  else {
    Write-Info "未检测到历史配置。"
  }

  if (-not [string]::IsNullOrWhiteSpace($existingUrl) -and -not [string]::IsNullOrWhiteSpace($existingKey)) {
    $answer = Read-Host "是否更新 URL/API Key？[y/N]"
    if (-not [string]::IsNullOrWhiteSpace($answer) -and $answer.Trim().ToLower() -eq "y") {
      # continue to prompt update
    }
    else {
      return @($existingUrl, $existingKey)
    }
  }

  $urlPrompt = "请输入 Base URL（示例: https://your-domain 或 http://127.0.0.1:8317）"
  if (-not [string]::IsNullOrWhiteSpace($existingUrl)) {
    $urlPrompt += "（回车沿用当前）"
  }
  $inputUrl = Read-Host $urlPrompt
  if ([string]::IsNullOrWhiteSpace($inputUrl) -and -not [string]::IsNullOrWhiteSpace($existingUrl)) {
    $inputUrl = $existingUrl
  }

  if (-not [string]::IsNullOrWhiteSpace($existingKey)) {
    $inputKey = Read-Host "请输入 API Key（回车沿用当前）"
  }
  else {
    $inputKey = Read-Host "请输入 API Key"
  }
  if ([string]::IsNullOrWhiteSpace($inputKey) -and -not [string]::IsNullOrWhiteSpace($existingKey)) {
    $inputKey = $existingKey
  }

  if ([string]::IsNullOrWhiteSpace($inputUrl) -or [string]::IsNullOrWhiteSpace($inputKey)) {
    throw "Base URL 和 API Key 不能为空"
  }

  return @($inputUrl.Trim(), $inputKey.Trim())
}

function Main {
  Write-Info "开始配置 Codex 代理接入..."
  Ensure-NodeNpm
  Install-OrUpdate-Codex

  $result = Resolve-Config
  $baseUrl = Normalize-BaseUrl($result[0])
  $apiKey = $result[1]

  Save-UserEnv $baseUrl $apiKey
  Try-CodexLogin $baseUrl $apiKey

  Write-Info "配置完成。"
  Write-Info "OPENAI_BASE_URL=$env:OPENAI_BASE_URL"
  Write-Info ("API Key=" + (Mask-ApiKey $env:OPENAI_API_KEY))
  Write-Info "已写入当前用户环境变量。请重新打开终端后运行 codex。"
}

try {
  Main
  Pause-Exit 0
}
catch {
  Write-Host "[codex-setup] 配置失败：$($_.Exception.Message)" -ForegroundColor Red
  Pause-Exit 1
}
