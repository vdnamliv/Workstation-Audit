param(
  [string]$Version = "1.0.0",
  [string]$BuildDir = "..\..\..\dist"
)

$ErrorActionPreference = "Stop"

# Paths
$RepoRoot = Resolve-Path "..\..\.."
$OutExe   = Join-Path $RepoRoot "dist\vt-agent.exe"
$WiXDir   = Resolve-Path "."

Write-Host "==> 1) Build agent"
pushd $RepoRoot
go build -o "dist\vt-agent.exe" ".\agent\cmd\vt-agent"
popd

Write-Host "==> 2) Prepare WiX input dir: $BuildDir"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# Copy exe từ output thật sang BuildDir
Copy-Item -Force $OutExe (Join-Path $BuildDir "vt-agent.exe")

# CA pem: nếu bạn đã có ca.pem thật ở dist, copy; nếu chưa, tạo placeholder (lab)
$SrcCA = Join-Path $RepoRoot "dist\ca.pem"
$DstCA = Join-Path $BuildDir "ca.pem"
if (Test-Path $SrcCA) {
  Copy-Item -Force $SrcCA $DstCA
  Write-Host "Using existing ca.pem from dist"
} else {
  @"
-----BEGIN CERTIFICATE-----
# PUT YOUR REAL CA PEM HERE FOR LAB ONLY
-----END CERTIFICATE-----
"@ | Set-Content -NoNewline -Path $DstCA -Encoding ascii
  Write-Warning "Created placeholder ca.pem — replace with real CA in dist\ca.pem for TLS"
}

# config.json mẫu (có thể sửa SERVER URL/CA path theo nhu cầu)
$Cfg = @"
{
  "server": "https://localhost:8443",
  "enroll_key": "ORG_KEY_DEMO",
  "interval": 600,
  "ca_file": "C:\\Program Files\\vt-agent\\ca.pem",
  "insecure_skip_verify": false
}
"@
$Cfg | Set-Content -NoNewline -Path (Join-Path $BuildDir "config.json") -Encoding ascii

Write-Host "==> 3) Build MSI with WiX v4"
# candle/light chạy ngay trong thư mục chứa Product.wxs
candle.exe -dBuildDir="$BuildDir" -arch x64 "Product.wxs"
# Nếu không dùng UI extension, không cần -ext WixToolset.UI.wixext
light.exe "Product.wixobj" -o (Join-Path $BuildDir "vt-agent-$Version-x64.msi")

Write-Host "MSI ready: $(Join-Path $BuildDir "vt-agent-$Version-x64.msi")"
