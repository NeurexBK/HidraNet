#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  HidraVPN phase 2: validate the Windows kill switch and, with -Full, the whole
  background service, against a real node.

.DESCRIPTION
  Run it in a PowerShell opened "as Administrator". By default it runs only the
  safe part: it arms the kill switch WITHOUT a tunnel, checks that the internet
  is then blocked, and lifts it again. The kill switch is the Windows Filtering
  Platform code; lifting it needs no network, so even if everything is blocked
  the script (and you) can always undo it with:

      hidravpn-service firewall off

  With -Full it then installs the service, connects through it, checks the exit
  address and that the kill switch is on, disconnects and uninstalls. Run the
  default first; only run -Full once the default part is green.

  Nothing here reads, shows or copies a private key or passphrase. ssh/scp are
  the ones installed with Windows, with your own key. The report masks your own
  public address.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [string]$SshUser = 'root',
  [string]$Name = $env:USERNAME,
  [string]$Dir = 'C:\HidraVPN',
  [string]$ServerSource = '/opt/hidranet-src',
  [string]$ClientHash = '9EC1496A6EB9ABE3D53E75DEA47567A6F0E19A51D5F6361BC7787ACC63B8FF9D',
  [string]$ServiceHash = 'C23B9A161B1232457FC0E8FED418F6E96362E7E3E8AE8177A0D3EDFEF92996D6',
  [string]$WintunUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip',
  [switch]$Full
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
if ($PSVersionTable.PSEdition -eq 'Desktop') {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
try { $Host.UI.RawUI.FlushInputBuffer() } catch {}
# Keep this console out of QuickEdit "Select" mode: a click inside the window
# would otherwise freeze the script at its next line of output until Esc.
try {
  $null = Add-Type -Namespace HidraVpnConsole -Name Mode -PassThru -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@
  $hIn = [HidraVpnConsole.Mode]::GetStdHandle(-10); $mode = [uint32]0
  if ([HidraVpnConsole.Mode]::GetConsoleMode($hIn, [ref]$mode)) {
    # clear ENABLE_QUICK_EDIT_MODE (0x40); ENABLE_EXTENDED_FLAGS (0x80) makes it stick
    [HidraVpnConsole.Mode]::SetConsoleMode($hIn, ($mode -band (-bnot [uint32]0x40)) -bor [uint32]0x80) | Out-Null
  }
} catch {}

$LogDir = Join-Path $Dir 'logs'
New-Item -ItemType Directory -Force -Path $Dir, $LogDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ReportPath = Join-Path $LogDir "phase2-$Stamp.txt"
$script:Checks = @()
$script:Facts = @()
$SvcExe = Join-Path $Dir 'hidravpn-service.exe'
$CliExe = Join-Path $Dir 'hidravpn.exe'

function Log([string]$m) { Write-Host $m; Add-Content -Path $ReportPath -Value $m }
function Step([string]$m) { Log ''; Log "== $m" }
function Fact([string]$m) { $script:Facts += $m; Log $m }
function Check([string]$r, [string]$n, [string]$d = '') {
  $script:Checks += [pscustomobject]@{ R = $r; N = $n; D = $d }
  $line = '{0,-5} {1}' -f $r, $n; if ($d) { $line += "  ($d)" }; Log $line
}
function Mask([string]$ip) {
  if (-not $ip) { return '(none)' }
  if ($ip -match '^(\d{1,3}\.){3}(\d{1,3})$') { return "*.*.*.$($Matches[2])" }
  return $ip
}
function Firewall-Off { try { & $SvcExe firewall off 2>&1 | Out-Null } catch {} }
function Service-Cleanup {
  if ($Full) {
    try { & $SvcExe down 2>&1 | Out-Null } catch {}
    try { & $SvcExe uninstall 2>&1 | Out-Null } catch {}
  }
  Firewall-Off
}
function Exit-Ip {
  foreach ($u in 'https://ifconfig.me/ip', 'https://icanhazip.com', 'https://api.ipify.org') {
    $ip = (& curl.exe -4 -s -m 12 $u 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -eq 0 -and $ip -match '^(\d{1,3}\.){3}\d{1,3}$') { return $ip }
  }
  return ''
}
function Http-Code([string]$url) {
  return ((& curl.exe -4 -s -m 10 -o NUL -w '%{http_code}' $url 2>$null | Out-String).Trim())
}
function Finish {
  $fails = @($script:Checks | Where-Object { $_.R -eq 'FAIL' }).Count
  $passes = @($script:Checks | Where-Object { $_.R -eq 'PASS' }).Count
  Log ''
  Log '================ HidraVPN phase 2 - Windows test ================'
  foreach ($f in $script:Facts) { Log $f }
  foreach ($c in $script:Checks) { $l = '{0,-5} {1}' -f $c.R, $c.N; if ($c.D) { $l += "  ($($c.D))" }; Log $l }
  if ($passes -eq 0 -and $fails -eq 0) { Log 'FAIL  no checks ran (the test stopped before it could test anything)'; $fails = 1 }
  $verdict = if ($fails -eq 0) { 'PASS' } else { 'FAIL' }
  Log ('RESULT: {0}  ({1} passed, {2} failed){3}' -f $verdict, $passes, $fails, $(if (-not $Full) { '  [kill-switch only; re-run with -Full for the service]' } else { '' }))
  Log '================================================================'
  Log "Saved to $ReportPath. Send the block above."
}
function Stop-Now([string]$why) { Log ''; Log "STOPPED: $why"; Log "Recovery if anything is blocked: run  hidravpn-service firewall off"; Firewall-Off; Log "Report: $ReportPath"; exit 2 }

Log "HidraVPN phase 2 Windows test, $(Get-Date -Format 'yyyy-MM-dd HH:mm')  (Full=$Full)"
Log "PowerShell $($PSVersionTable.PSVersion), $([Environment]::OSVersion.VersionString)"
foreach ($t in 'curl.exe', 'ssh.exe', 'scp.exe') {
  if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { Stop-Now "$t is not available" }
}

# -------------------------------------------------- the two executables ----
Step 'placing the executables'
function Place([string]$name, [string]$dest, [string]$wantHash) {
  if (Test-Path $dest) {
    if ((Get-FileHash $dest -Algorithm SHA256).Hash -ieq $wantHash) { return $true }
  }
  foreach ($d in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:OneDrive\Downloads")) {
    if (-not $d -or -not (Test-Path $d)) { continue }
    foreach ($c in Get-ChildItem -Path $d -Filter "$name" -File -Recurse -Depth 1 -ErrorAction SilentlyContinue) {
      if ((Get-FileHash $c.FullName -Algorithm SHA256).Hash -ieq $wantHash) { Copy-Item $c.FullName $dest -Force; return $true }
    }
  }
  Log ("  (no local $name with the expected hash in Downloads, Desktop, Documents or OneDrive)")
  return $false
}
$haveCli = Place 'hidravpn.exe' $CliExe $ClientHash
$haveSvc = Place 'hidravpn-service.exe' $SvcExe $ServiceHash
if (-not $haveSvc -or ($Full -and -not $haveCli)) {
  Log "building the executables on the node over ssh ($SshUser@$Server); a few minutes"
  $remote = "set -e; cd '$ServerSource'; git fetch -q origin main && git checkout -q main && git merge -q --ff-only origin/main; bash hidravpn/scripts/build-windows-client.sh '$ServerSource'"
  & ssh.exe -o ConnectTimeout=20 "$SshUser@$Server" $remote
  if ($LASTEXITCODE -ne 0) { Stop-Now "the build on the node failed (exit $LASTEXITCODE)" }
  & scp.exe -q -o ConnectTimeout=20 "${SshUser}@${Server}:/root/hidravpn-win/hidravpn-service.exe" $SvcExe
  if ($Full) { & scp.exe -q -o ConnectTimeout=20 "${SshUser}@${Server}:/root/hidravpn-win/hidravpn.exe" $CliExe }
}
Unblock-File $SvcExe -ErrorAction SilentlyContinue
if ($Full) { Unblock-File $CliExe -ErrorAction SilentlyContinue }
if (-not (Test-Path $SvcExe)) { Stop-Now 'hidravpn-service.exe is not in place' }
$sv = ''
try { $sv = (& $SvcExe --version 2>&1 | Out-String).Trim() } catch { $sv = "ERROR: $($_.Exception.Message)" }
if ($sv -notmatch 'hidravpn-service') {
  Stop-Now ("hidravpn-service.exe did not run. On Windows 11 this is usually Smart App Control blocking an unsigned binary. First line: " + (($sv -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1))
}
Fact "service  $SvcExe  $sv  sha256 $((Get-FileHash $SvcExe -Algorithm SHA256).Hash)"

try {
  # ======================================================= PART A: WFP ====
  Step 'kill switch on its own (no tunnel) - the safe check'
  Firewall-Off
  $base = Exit-Ip
  if (-not $base) { Stop-Now 'no internet right now: cannot learn the baseline public address' }
  Fact "before   exit IPv4 $(Mask $base)"
  $baseCode = Http-Code 'https://example.com'
  if ($baseCode -eq '000') { Stop-Now 'https://example.com did not load even before the kill switch; check the connection' }
  Check 'PASS' 'internet works before the kill switch' "example.com -> $baseCode"

  $armOut = (& $SvcExe firewall on --node "${Server}:51820" --dns 10.77.0.1 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) { Stop-Now "could not arm the kill switch: $armOut" }
  Check 'PASS' 'kill switch armed' 'WFP filters added'

  $c1 = Http-Code 'https://example.com'
  if ($c1 -eq '000') { Check 'PASS' 'internet is blocked by name' 'example.com no longer loads' } else { Check 'FAIL' 'internet should be blocked' "example.com -> $c1" }
  $c2 = Http-Code 'https://1.1.1.1'
  if ($c2 -eq '000') { Check 'PASS' 'egress to a raw IP is blocked' '1.1.1.1 unreachable (not just DNS)' } else { Check 'FAIL' 'egress to a raw IP should be blocked' "1.1.1.1 -> $c2" }
  $loop = Http-Code 'http://127.0.0.1:1'
  Check 'INFO' 'loopback note' 'loopback stays allowed by the rules; no local server to prove it here'

  $offOut = (& $SvcExe firewall off 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) { Check 'FAIL' 'kill switch lifts' $offOut } else { Check 'PASS' 'kill switch lifted' '' }
  Start-Sleep -Seconds 2
  $c3 = Http-Code 'https://example.com'
  if ($c3 -ne '000') { Check 'PASS' 'internet works again after the kill switch is off' "example.com -> $c3" } else { Check 'FAIL' 'internet should work again' "example.com -> $c3" }

  $partAok = @($script:Checks | Where-Object { $_.R -eq 'FAIL' }).Count -eq 0

  # ====================================================== PART B: service =
  if ($Full -and $partAok) {
    Step 'the whole service (install, connect, disconnect, uninstall)'
    if (-not (Test-Path $CliExe)) { Stop-Now 'hidravpn.exe is needed for -Full but is not in place' }
    # wintun.dll beside the exes
    $Dll = Join-Path $Dir 'wintun.dll'
    if (-not (Test-Path $Dll)) {
      $zip = Join-Path $LogDir 'wintun.zip'; $unz = Join-Path $LogDir 'wintun'
      try { Invoke-WebRequest -UseBasicParsing -Uri $WintunUrl -OutFile $zip } catch { Stop-Now "could not download Wintun: $($_.Exception.Message)" }
      Expand-Archive -Path $zip -DestinationPath $unz -Force
      Copy-Item (Join-Path $unz 'wintun\bin\amd64\wintun.dll') $Dll -Force
    }
    $sig = Get-AuthenticodeSignature $Dll
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') { Stop-Now "wintun.dll signature is '$($sig.Status)': refusing it" }
    Copy-Item $Dll (Join-Path (Split-Path $CliExe) 'wintun.dll') -Force -ErrorAction SilentlyContinue

    # client key + admission
    if (-not (Test-Path (Join-Path $env:ProgramData 'HidraVPN\client.key'))) { & $CliExe keygen 2>&1 | Out-Null }
    # The node is shown a key derived for it from the master key (phase 3):
    # its public key first, over ssh (needs hidravpn-node from this branch).
    $nodePub = ((& ssh.exe -o ConnectTimeout=20 "$SshUser@$Server" '/usr/local/bin/hidravpn-node pubkey') | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $nodePub -notmatch '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$') { Stop-Now "could not read the node's public key over ssh (the node needs hidravpn-node from this branch): $nodePub" }
    $pub = (& $CliExe pubkey --node $nodePub 2>$null | Out-String).Trim()
    $Name = ($Name -replace '[^A-Za-z0-9_-]', '-'); if (-not $Name) { $Name = 'windows' }
    $inviteText = ((& ssh.exe -o ConnectTimeout=20 "$SshUser@$Server" "/usr/local/bin/hidravpn-node admit --name '$Name' --pubkey '$pub'") | Out-String).Trim()
    $invite = $null; try { $invite = $inviteText | ConvertFrom-Json } catch {}
    if (-not $invite -or -not $invite.endpoint) { Stop-Now "the node did not return an invite:`n$inviteText" }
    $InvitePath = Join-Path $Dir 'invite.json'; Set-Content $InvitePath $inviteText -Encoding Ascii
    $nodeIp = ($invite.endpoint -split ':')[0]

    & $SvcExe install 2>&1 | Out-String | Out-Null
    Start-Sleep -Seconds 3
    $up = (& $SvcExe up $InvitePath 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0) { Check 'PASS' 'service connected' '' } else { Check 'FAIL' 'service connect' $up }
    Start-Sleep -Seconds 3
    $ip = Exit-Ip
    if ($ip -eq $nodeIp) { Check 'PASS' 'exit address is the node' $ip } else { Check 'FAIL' 'exit address is the node' "got $(Mask $ip), expected $nodeIp" }
    $st = (& $SvcExe status 2>&1 | Out-String).Trim()
    if ($st -match 'kill switch on') { Check 'PASS' 'service reports the kill switch on' '' } else { Check 'FAIL' 'kill switch should be on while connected' $st }

    $down = (& $SvcExe down 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0) { Check 'PASS' 'service disconnected' '' } else { Check 'FAIL' 'service disconnect' $down }
    Start-Sleep -Seconds 2
    $ipAfter = Exit-Ip
    if ($ipAfter -eq $base) { Check 'PASS' 'network back to normal' "exit $(Mask $ipAfter)" } else { Check 'FAIL' 'network back to normal' "exit $(Mask $ipAfter), was $(Mask $base)" }
    & $SvcExe uninstall 2>&1 | Out-String | Out-Null
    Check 'PASS' 'service uninstalled' ''
  }
}
finally {
  Service-Cleanup
}

Finish
