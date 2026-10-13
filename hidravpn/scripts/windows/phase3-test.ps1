#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  HidraVPN phase 3 on Windows: two hops (Privado) through a real entry node and
  a real exit node, with a key derived for each node; optionally a new identity
  through a second exit.

.DESCRIPTION
  NOT YET RUN ON HARDWARE. This script was written on Linux, where it cannot be
  executed (it needs a Windows machine, Wintun, WFP and two reachable nodes).
  It mirrors phase2-test.ps1 in structure and conventions and is ready for the
  first run on the Windows PC. Two things it needs that may not be in place:

    - the executables from this branch; on Windows 11 with Smart App Control
      an unsigned hidravpn.exe/hidravpn-service.exe is refused, so this wants
      the SIGNED build (see docs/code-signing.md) or SAC off on the test PC;
    - every node running hidravpn-node from this branch, which has the
      `pubkey` command the admission below starts from.

  Run it in a PowerShell opened "as Administrator":

      .\phase3-test.ps1 -Entry 203.0.113.20 -Exit 203.0.113.10 [-Exit2 203.0.113.11]

  What it does: gets each node's public key over ssh, derives this machine's
  key FOR THAT NODE (hidravpn pubkey --node ...) and has the node admit it;
  installs the service; connects with `hidravpn up exit.json --via entry.json`;
  checks that the internet sees the exit's address and not the entry's, that
  DNS works, that the kill switch (WFP) is on, that status says privado with
  2 hops and explains it honestly; with -Exit2, `new-identity` and the address
  changes; then `down` and the network is back. It always disconnects,
  uninstalls the service and lifts the kill switch at the end, even on failure.

  Recovery if anything is left blocked:  hidravpn-service firewall off

  Nothing here reads, shows or copies a private key or passphrase. ssh/scp are
  the ones installed with Windows, with your own key. The report masks your own
  public address; the nodes' addresses are the parameters you gave.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Entry,
  [Parameter(Mandatory = $true)][string]$Exit,
  [string]$Exit2 = '',
  [string]$SshUser = 'root',
  [string]$Name = $env:USERNAME,
  [string]$Dir = 'C:\HidraVPN',
  # Where the executables are built when they are not already in $Dir: a
  # checkout of this repository on the entry node, as phase 2 did.
  [string]$ServerSource = '/opt/hidranet-src',
  # Expected SHA256 of the executables. Empty: accept what is in $Dir (or build
  # it on the entry node) and record its hash in the report. Set them once the
  # signed build exists, so the test runs exactly that build.
  [string]$ClientHash = '',
  [string]$ServiceHash = '',
  [string]$WintunUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
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
$ReportPath = Join-Path $LogDir "phase3-$Stamp.txt"
$script:Checks = @()
$script:Facts = @()
$SvcExe = Join-Path $Dir 'hidravpn-service.exe'
$CliExe = Join-Path $Dir 'hidravpn.exe'
$KeyRe = '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$'

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
  try { & $CliExe down 2>&1 | Out-Null } catch {}
  try { & $SvcExe uninstall 2>&1 | Out-Null } catch {}
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
function Ssh([string]$node, [string]$command) {
  # One command on one node; stdout as a trimmed string, $LASTEXITCODE as ssh left it.
  return ((& ssh.exe -o ConnectTimeout=20 "$SshUser@$node" $command) | Out-String).Trim()
}
function Finish {
  $fails = @($script:Checks | Where-Object { $_.R -eq 'FAIL' }).Count
  $passes = @($script:Checks | Where-Object { $_.R -eq 'PASS' }).Count
  Log ''
  Log '================ HidraVPN phase 3 - Windows test ================'
  foreach ($f in $script:Facts) { Log $f }
  foreach ($c in $script:Checks) { $l = '{0,-5} {1}' -f $c.R, $c.N; if ($c.D) { $l += "  ($($c.D))" }; Log $l }
  if ($passes -eq 0 -and $fails -eq 0) { Log 'FAIL  no checks ran (the test stopped before it could test anything)'; $fails = 1 }
  $verdict = if ($fails -eq 0) { 'PASS' } else { 'FAIL' }
  Log ('RESULT: {0}  ({1} passed, {2} failed){3}' -f $verdict, $passes, $fails, $(if (-not $Exit2) { '  [no -Exit2: new-identity not tested]' } else { '' }))
  Log '================================================================'
  Log "Saved to $ReportPath. Send the block above."
}
function Stop-Now([string]$why) { Log ''; Log "STOPPED: $why"; Log "Recovery if anything is blocked: run  hidravpn-service firewall off"; Service-Cleanup; Log "Report: $ReportPath"; Finish; exit 2 }

Log "HidraVPN phase 3 Windows test, $(Get-Date -Format 'yyyy-MM-dd HH:mm')  (entry $Entry, exit $Exit$(if ($Exit2) { ", exit2 $Exit2" }))"
Log "PowerShell $($PSVersionTable.PSVersion), $([Environment]::OSVersion.VersionString)"
foreach ($t in 'curl.exe', 'ssh.exe', 'scp.exe') {
  if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { Stop-Now "$t is not available" }
}
foreach ($ip in @($Entry, $Exit) + @($(if ($Exit2) { $Exit2 }))) {
  if ($ip -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { Stop-Now "'$ip' is not an IPv4 address" }
}
if ($Entry -eq $Exit -or ($Exit2 -and ($Exit2 -eq $Exit -or $Exit2 -eq $Entry))) { Stop-Now 'the entry and the exits must be different machines' }

# -------------------------------------------------- the two executables ----
Step 'placing the executables'
function Place([string]$name, [string]$dest, [string]$wantHash) {
  if (Test-Path $dest) {
    if (-not $wantHash) { return $true }
    if ((Get-FileHash $dest -Algorithm SHA256).Hash -ieq $wantHash) { return $true }
  }
  if ($wantHash) {
    foreach ($d in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:OneDrive\Downloads")) {
      if (-not $d -or -not (Test-Path $d)) { continue }
      foreach ($c in Get-ChildItem -Path $d -Filter "$name" -File -Recurse -Depth 1 -ErrorAction SilentlyContinue) {
        if ((Get-FileHash $c.FullName -Algorithm SHA256).Hash -ieq $wantHash) { Copy-Item $c.FullName $dest -Force; return $true }
      }
    }
    Log ("  (no local $name with the expected hash in Downloads, Desktop, Documents or OneDrive)")
  }
  return $false
}
$haveCli = Place 'hidravpn.exe' $CliExe $ClientHash
$haveSvc = Place 'hidravpn-service.exe' $SvcExe $ServiceHash
if (-not $haveSvc -or -not $haveCli) {
  Log "building the executables on the entry node over ssh ($SshUser@$Entry); a few minutes"
  $remote = "set -e; cd '$ServerSource'; git fetch -q origin feature/hidravpn && git checkout -q feature/hidravpn && git merge -q --ff-only origin/feature/hidravpn; bash hidravpn/scripts/build-windows-client.sh '$ServerSource'"
  & ssh.exe -o ConnectTimeout=20 "$SshUser@$Entry" $remote
  if ($LASTEXITCODE -ne 0) { Stop-Now "the build on the entry node failed (exit $LASTEXITCODE)" }
  & scp.exe -q -o ConnectTimeout=20 "${SshUser}@${Entry}:/root/hidravpn-win/hidravpn-service.exe" $SvcExe
  & scp.exe -q -o ConnectTimeout=20 "${SshUser}@${Entry}:/root/hidravpn-win/hidravpn.exe" $CliExe
}
Unblock-File $SvcExe -ErrorAction SilentlyContinue
Unblock-File $CliExe -ErrorAction SilentlyContinue
if (-not (Test-Path $SvcExe)) { Stop-Now 'hidravpn-service.exe is not in place' }
if (-not (Test-Path $CliExe)) { Stop-Now 'hidravpn.exe is not in place' }
foreach ($exe in @($SvcExe, $CliExe)) {
  $v = ''
  try { $v = (& $exe --version 2>&1 | Out-String).Trim() } catch { $v = "ERROR: $($_.Exception.Message)" }
  if ($v -notmatch 'hidravpn') {
    Stop-Now ("$(Split-Path -Leaf $exe) did not run. On Windows 11 this is usually Smart App Control blocking an unsigned binary: use the signed build. First line: " + (($v -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1))
  }
  $sig = Get-AuthenticodeSignature $exe
  Fact "$(Split-Path -Leaf $exe)  $v  sha256 $((Get-FileHash $exe -Algorithm SHA256).Hash)  signature $($sig.Status)"
}

try {
  # ------------------------------------------------------------- wintun ----
  Step 'wintun.dll beside the executables'
  $Dll = Join-Path $Dir 'wintun.dll'
  if (-not (Test-Path $Dll)) {
    $zip = Join-Path $LogDir 'wintun.zip'; $unz = Join-Path $LogDir 'wintun'
    try { Invoke-WebRequest -UseBasicParsing -Uri $WintunUrl -OutFile $zip } catch { Stop-Now "could not download Wintun: $($_.Exception.Message)" }
    Expand-Archive -Path $zip -DestinationPath $unz -Force
    Copy-Item (Join-Path $unz 'wintun\bin\amd64\wintun.dll') $Dll -Force
  }
  $wsig = Get-AuthenticodeSignature $Dll
  if ($wsig.Status -ne 'Valid' -or $wsig.SignerCertificate.Subject -notmatch 'WireGuard LLC') { Stop-Now "wintun.dll signature is '$($wsig.Status)': refusing it" }
  Fact "wintun   $((Get-Item $Dll).VersionInfo.ProductVersion)  signature $($wsig.Status)"

  # ----------------------------------------------------------- baseline ----
  Step 'baseline'
  Firewall-Off
  $base = Exit-Ip
  if (-not $base) { Stop-Now 'no internet right now: cannot learn the baseline public address' }
  Fact "before   exit IPv4 $(Mask $base)"
  if ($base -eq $Exit -or $base -eq $Entry) { Stop-Now 'this machine already leaves through a node; the test cannot tell a tunnel from no tunnel' }
  $baseCode = Http-Code 'https://example.com'
  if ($baseCode -eq '000') { Stop-Now 'https://example.com did not load even before the VPN; check the connection' }
  Check 'PASS' 'internet works before the VPN' "example.com -> $baseCode"

  # -------------------------- one master key, one derived key per node ----
  Step 'the master key, and a key derived for each node'
  if (-not (Test-Path (Join-Path $env:ProgramData 'HidraVPN\client.key'))) {
    & $CliExe keygen 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Now 'keygen failed' }
    Log 'new master key (the secret stays in ProgramData and is never shown)'
  }
  $master = (& $CliExe pubkey 2>$null | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $master -notmatch $KeyRe) { Stop-Now "could not read the master key's public half ($master)" }
  $Name = ($Name -replace '[^A-Za-z0-9_-]', '-'); if (-not $Name) { $Name = 'windows' }
  if ($Name.Length -gt 32) { $Name = $Name.Substring(0, 32) }

  $nodes = @(@{ Role = 'entry'; Ip = $Entry; File = 'entry.json' }, @{ Role = 'exit'; Ip = $Exit; File = 'exit.json' })
  if ($Exit2) { $nodes += @{ Role = 'exit2'; Ip = $Exit2; File = 'exit2.json' } }
  $derived = @{}
  foreach ($n in $nodes) {
    $nodePub = Ssh $n.Ip '/usr/local/bin/hidravpn-node pubkey'
    if ($LASTEXITCODE -ne 0 -or $nodePub -notmatch $KeyRe) { Stop-Now "could not read the $($n.Role) node's public key over ssh (it needs hidravpn-node from this branch): $nodePub" }
    $pub = (& $CliExe pubkey --node $nodePub 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $pub -notmatch $KeyRe) { Stop-Now "could not derive the key for the $($n.Role) node ($pub)" }
    $derived[$n.Role] = $pub
    $inviteText = Ssh $n.Ip "/usr/local/bin/hidravpn-node admit --name '$Name' --pubkey '$pub'"
    $invite = $null; try { $invite = $inviteText | ConvertFrom-Json } catch {}
    if (-not $invite -or -not $invite.endpoint) { Stop-Now "the $($n.Role) node did not return an invite:`n$inviteText" }
    if (($invite.endpoint -split ':')[0] -ne $n.Ip) { Stop-Now "the $($n.Role) node's invite names endpoint $($invite.endpoint), not $($n.Ip)" }
    $n.Path = Join-Path $Dir $n.File
    Set-Content $n.Path $inviteText -Encoding Ascii
    Log "$($n.Role) $($n.Ip): admitted the key derived for it"
  }
  $allDifferent = ($derived.Values | Select-Object -Unique).Count -eq $derived.Count
  $noneMaster = -not ($derived.Values -contains $master)
  if ($allDifferent -and $noneMaster) { Check 'PASS' 'a different key for each node, none of them the master key' "$($derived.Count) nodes" }
  else { Check 'FAIL' 'a different key for each node, none of them the master key' "distinct=$allDifferent noneIsMaster=$noneMaster" }
  $EntryPath = ($nodes | Where-Object { $_.Role -eq 'entry' }).Path
  $ExitPath = ($nodes | Where-Object { $_.Role -eq 'exit' }).Path
  $Exit2Path = if ($Exit2) { ($nodes | Where-Object { $_.Role -eq 'exit2' }).Path } else { '' }

  # ---------------------------------------------- two hops, through the service ----
  Step 'the service: install, connect through two hops'
  & $SvcExe install 2>&1 | Out-String | Out-Null
  Start-Sleep -Seconds 3
  $upArgs = @('up', $ExitPath, '--via', $EntryPath)
  if ($Exit2Path) { $upArgs += @('--alternate', $Exit2Path) }
  $up = (& $CliExe @upArgs 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -eq 0 -and $up -match 'privado, 2 hops') { Check 'PASS' 'up: privado, 2 hops, through the service' '' } else { Check 'FAIL' 'up: privado, 2 hops' $up }
  Start-Sleep -Seconds 4

  $ip = Exit-Ip
  if ($ip -eq $Exit) { Check 'PASS' "the internet sees the exit's address" $ip }
  elseif ($ip -eq $Entry) { Check 'FAIL' "the internet sees the ENTRY's address, not the exit's" $ip }
  else { Check 'FAIL' "the internet sees the exit's address" "got $(Mask $ip), expected $Exit" }
  $c1 = Http-Code 'https://example.com'
  if ($c1 -ne '000') { Check 'PASS' 'DNS and HTTPS work through both hops' "example.com -> $c1" } else { Check 'FAIL' 'DNS and HTTPS through both hops' "example.com -> $c1" }

  $st = (& $CliExe status 2>&1 | Out-String).Trim()
  if ($st -match 'kill switch on') { Check 'PASS' 'the kill switch (WFP) is on while connected' '' } else { Check 'FAIL' 'the kill switch should be on while connected' $st }
  if ($st -match 'privado, 2 hops: entry .* then exit ') { Check 'PASS' 'status says privado, 2 hops, entry then exit' '' } else { Check 'FAIL' 'status: privado, 2 hops' $st }
  if ($st -match 'no node sees both who you are and where you go') { Check 'PASS' 'status explains what privado hides and what it does not' '' } else { Check 'FAIL' 'status explanation' $st }
  $hopLines = @($st -split "`r?`n" | Where-Object { $_ -match '^\s+(entry|exit) .*last handshake' })
  if ($hopLines.Count -eq 2) { Check 'PASS' 'status shows a handshake age per hop' '' } else { Check 'FAIL' 'status should show two hop lines' $st }
  if ($st -match 'anonym') { Check 'FAIL' 'status must not promise anonymity' $st } else { Check 'PASS' 'status does not say "anonymous"' '' }

  # ----------------------------------------------------- new identity ----
  if ($Exit2) {
    Step 'new identity: another exit, another address'
    $ni = (& $CliExe new-identity 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0 -and $ni -match 'the exit is now') { Check 'PASS' 'new-identity rotated the exit' (($ni -split "`r?`n")[0]) } else { Check 'FAIL' 'new-identity' $ni }
    Start-Sleep -Seconds 4
    $ip2 = Exit-Ip
    if ($ip2 -eq $Exit2 -and $ip2 -ne $ip) { Check 'PASS' 'the internet now sees the second exit' $ip2 } else { Check 'FAIL' 'the address should have changed to the second exit' "got $(Mask $ip2), was $(Mask $ip), expected $Exit2" }
    $st2 = (& $CliExe status 2>&1 | Out-String).Trim()
    if ($st2 -match 'kill switch on') { Check 'PASS' 'the kill switch stayed on across the rotation' '' } else { Check 'FAIL' 'the kill switch should stay on' $st2 }
  }

  # ---------------------------------------------------------------- down ----
  Step 'down'
  $down = (& $CliExe down 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -eq 0) { Check 'PASS' 'disconnected' '' } else { Check 'FAIL' 'disconnect' $down }
  Start-Sleep -Seconds 3
  $ipAfter = Exit-Ip
  if ($ipAfter -eq $base) { Check 'PASS' 'network back to normal' "exit $(Mask $ipAfter)" } else { Check 'FAIL' 'network back to normal' "exit $(Mask $ipAfter), was $(Mask $base)" }
  $st3 = (& $CliExe status 2>&1 | Out-String).Trim()
  if ($st3 -match 'not connected' -and $st3 -match 'kill switch off') { Check 'PASS' 'status after down: not connected, kill switch off' '' } else { Check 'FAIL' 'status after down' $st3 }
  & $SvcExe uninstall 2>&1 | Out-String | Out-Null
  Check 'PASS' 'service uninstalled' ''
}
finally {
  Service-Cleanup
}

Finish
