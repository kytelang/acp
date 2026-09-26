# Varman (ACP) workstation installer for Windows.
#
#   powershell -c "irm https://acpdocs.web.app/install.ps1 | iex"
#
# Installs the ACP workstation tools (acp-proxy, acp-intercept, acp-verify) into %USERPROFILE%\.acp\bin
# and adds that to your user PATH. For the control plane and gateway as services, use a Linux host and
# install-server.sh.
$ErrorActionPreference = 'Stop'

$Repo = if ($env:ACP_REPO) { $env:ACP_REPO } else { 'kytelang/acp' }
$Home_ = if ($env:ACP_HOME) { $env:ACP_HOME } else { Join-Path $env:USERPROFILE '.acp' }
$Bin = Join-Path $Home_ 'bin'

# CPU: only x86_64 is published for Windows.
$arch = 'x86_64'

$Version = $env:ACP_VERSION
if (-not $Version) {
  Write-Host 'Looking up the latest Varman (ACP) release...'
  $rel = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases/latest"
  $Version = $rel.tag_name
}
if (-not $Version) { throw 'could not determine the latest release; set $env:ACP_VERSION' }

$Asset = "acp-user-$Version-windows-$arch.zip"
$Base = "https://github.com/$Repo/releases/download/$Version"
Write-Host "Installing Varman (ACP) $Version (windows-$arch) into $Home_"

$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("acp-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
try {
  $zip = Join-Path $Tmp $Asset
  Write-Host "Downloading $Asset ..."
  Invoke-WebRequest -UseBasicParsing "$Base/$Asset" -OutFile $zip

  # Verify the checksum if the sidecar is published.
  try {
    $sums = (Invoke-WebRequest -UseBasicParsing "$Base/$Asset.sha256").Content
    if ($sums) {
      $expected = ($sums -split '\s+')[0].ToLower()
      $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
      if ($expected -ne $actual) { throw "checksum verification failed for $Asset" }
      Write-Host 'Checksum verified.'
    }
  } catch { Write-Host 'No checksum published; skipping verification.' }

  Write-Host 'Extracting ...'
  Expand-Archive -Path $zip -DestinationPath $Tmp -Force
  $src = Join-Path $Tmp "acp-user-$Version-windows-$arch"
  New-Item -ItemType Directory -Force -Path $Bin | Out-Null
  Copy-Item -Path (Join-Path $src 'bin\*') -Destination $Bin -Recurse -Force

  # Add ~\.acp\bin to the user PATH if it is not already there.
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ($userPath -notlike "*$Bin*") {
    [Environment]::SetEnvironmentVariable('Path', "$Bin;$userPath", 'User')
    Write-Host "Added $Bin to your user PATH. Open a new terminal for it to take effect."
  }
  Write-Host ''
  Write-Host "Varman (ACP) $Version is installed in $Home_."
  Write-Host 'Verify evidence independently:  acp-verify <ledger.db>'
  Write-Host 'Full runbook:   https://acpdocs.web.app/guide/16-setup'
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
