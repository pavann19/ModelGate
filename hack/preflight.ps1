$ErrorActionPreference = "Stop"

$SetupEnvtestVersion = "v0.0.0-20250308055145-5fe7bb3edc86"
$EnvtestKubernetesVersion = "1.31.0"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$ToolsDirectory = Join-Path $RepositoryRoot ".tools\bin"
$SetupEnvtest = Join-Path $ToolsDirectory "setup-envtest.exe"

function Require-Command {
    param([string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found on PATH."
    }
}

Require-Command "go"

New-Item -ItemType Directory -Force -Path $ToolsDirectory | Out-Null

Write-Host "Installing pinned setup-envtest $SetupEnvtestVersion..."
$env:GOBIN = $ToolsDirectory
go install "sigs.k8s.io/controller-runtime/tools/setup-envtest@$SetupEnvtestVersion"
if ($LASTEXITCODE -ne 0) {
    throw "Could not install setup-envtest $SetupEnvtestVersion."
}

Write-Host "Resolving envtest Kubernetes $EnvtestKubernetesVersion assets..."
$AssetsPath = & $SetupEnvtest use $EnvtestKubernetesVersion -p path
if ($LASTEXITCODE -ne 0 -or -not $AssetsPath) {
    throw "Could not resolve envtest assets for Kubernetes $EnvtestKubernetesVersion."
}

foreach ($Binary in @("kube-apiserver", "etcd")) {
    $Candidates = @(
        (Join-Path $AssetsPath $Binary),
        (Join-Path $AssetsPath "$Binary.exe")
    )
    if (-not ($Candidates | Where-Object { Test-Path -LiteralPath $_ })) {
        throw "The envtest asset '$Binary' is missing from $AssetsPath."
    }
}

Write-Host "Preflight passed."
Write-Host "Run envtest in this shell with:"
Write-Host ('  $env:KUBEBUILDER_ASSETS = "{0}"' -f $AssetsPath)
Write-Host "  go test ./test/e2e/... -v -timeout 120s"
