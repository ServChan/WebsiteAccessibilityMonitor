# Builds the release binary and packs the Windows archive into dist\.
#
#   powershell -File scripts\package.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$name = "WebsiteAccessibilityMonitor-$version-windows-x64"

Push-Location $root
try {
    cargo build --release --bin wam
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
} finally {
    Pop-Location
}

$stage = Join-Path $root "dist\$name"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force "$stage\docs" | Out-Null
Copy-Item "$root\target\release\wam.exe", "$root\README.md", "$root\CHANGELOG.md", "$root\LICENSE" $stage
Copy-Item "$root\docs\USER_GUIDE_RU.md", "$root\docs\USER_GUIDE_EN.md" "$stage\docs"
Copy-Item -Recurse "$root\docs\images" "$stage\docs\images"
Copy-Item -Recurse "$root\deploy" "$stage\deploy"

$archive = "$stage.zip"
if (Test-Path $archive) { Remove-Item -Force $archive }
Compress-Archive -Path "$stage\*" -DestinationPath $archive
Remove-Item -Recurse -Force $stage

$hash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLower()
$size = [math]::Round((Get-Item $archive).Length / 1MB, 1)
Write-Output "$archive"
Write-Output "$size MB, SHA-256 $hash"
