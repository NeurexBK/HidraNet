#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  HidraVPN phase 4 on Windows: what the browser does, done the same way and
  checked — install (and update) the service with the client beside it, drive
  it over the named pipe the browser uses, connect with and without the local
  network, the leak checks, and uninstall, then uninstall --purge.

.DESCRIPTION
  NOT YET RUN ON HARDWARE. Written on Linux, where it cannot run; it mirrors
  phase3-test.ps1. Phase 4's Windows half has only been compiled so far: the
  pipe, its access rules, the data folder's rights, the install, the update
  and the removal are all checked here for the first time on a real PC.

  Run it in a PowerShell opened "as Administrator", with hidravpn.exe,
  hidravpn-service.exe and wintun.dll in -Dir (the signed build, or Smart App
  Control off):

      .\phase4-test.ps1 -Exit 203.0.113.10

  -Exit is a node running hidravpn-node from this branch, reachable over ssh
  with your own key (it admits this machine's key, as in phase 3).

  It always disconnects, uninstalls and lifts the kill switch at the end, even
  on failure. Recovery if anything is left blocked:
      & 'C:\Program Files\HidraVPN\hidravpn-service.exe' firewall off

  Nothing here reads, shows or copies a private key. The report masks your own
  public address; the node's address is the parameter you gave.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Exit,
  [string]$SshUser = 'root',
  [string]$Name = $env:USERNAME,
  [string]$Dir = 'C:\HidraVPN'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
if ($PSVersionTable.PSEdition -eq 'Desktop') {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$LogDir = Join-Path $Dir 'logs'
New-Item -ItemType Directory -Force -Path $Dir, $LogDir | Out-Null
$ReportPath = Join-Path $LogDir ("phase4-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$script:Checks = @(); $script:Facts = @()
$SvcExe = Join-Path $Dir 'hidravpn-service.exe'
$CliExe = Join-Path $Dir 'hidravpn.exe'
$Installed = Join-Path $env:ProgramFiles 'HidraVPN'
$ISvc = Join-Path $Installed 'hidravpn-service.exe'
$ICli = Join-Path $Installed 'hidravpn.exe'
$Data = Join-Path $env:ProgramData 'HidraVPN'
$KeyFile = Join-Path $Data 'client.key'
$TokenFile = Join-Path $Data 'control.token'
$KeyRe = '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$'

function Log([string]$m) { Write-Host $m; Add-Content -Path $ReportPath -Value $m }
function Step([string]$m) { Log ''; Log "== $m" }
function Fact([string]$m) { $script:Facts += $m; Log $m }
function Check([string]$r, [string]$n, [string]$d = '') {
  $script:Checks += [pscustomobject]@{ R = $r; N = $n; D = $d }
  $line = '{0,-5} {1}' -f $r, $n; if ($d) { $line += "  ($d)" }; Log $line
}
function Expect([bool]$cond, [string]$n, [string]$d = '') { if ($cond) { Check 'PASS' $n $d } else { Check 'FAIL' $n $d } }
function Mask([string]$ip) { if ($ip -match '^(\d{1,3}\.){3}(\d{1,3})$') { return "*.*.*.$($Matches[2])" }; if ($ip) { return $ip }; return '(none)' }
function Ip4 { foreach ($u in 'https://api.ipify.org', 'https://ifconfig.me/ip') { $ip = (& curl.exe -4 -s -m 12 $u 2>$null | Out-String).Trim(); if ($LASTEXITCODE -eq 0 -and $ip -match '^(\d{1,3}\.){3}\d{1,3}$') { return $ip } }; return '' }
function Ip6 { $ip = (& curl.exe -6 -s -m 8 'https://api6.ipify.org' 2>$null | Out-String).Trim(); if ($LASTEXITCODE -eq 0 -and $ip -match ':') { return $ip }; return '' }
function Ssh([string]$command) { return ((& ssh.exe -o ConnectTimeout=20 "$SshUser@$Exit" $command) | Out-String).Trim() }

# The browser's own way in: one line of JSON over \\.\pipe\hidravpn, with the
# token from ProgramData, one answer back.
function Pipe([hashtable]$req) {
  try {
    $req.token = (Get-Content $TokenFile -Raw).Trim()
    $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'hidravpn', [System.IO.Pipes.PipeDirection]::InOut)
    $c.Connect(5000)
    $w = New-Object System.IO.StreamWriter($c); $w.AutoFlush = $true
    $r = New-Object System.IO.StreamReader($c)
    $w.WriteLine(($req | ConvertTo-Json -Compress))
    $line = $r.ReadLine(); $c.Dispose()
    return ($line | ConvertFrom-Json)
  } catch { return [pscustomobject]@{ ok = $false; error = $_.Exception.Message } }
}
function Wait-Pipe { for ($i = 0; $i -lt 20; $i++) { $s = Pipe @{ cmd = 'status' }; if ($s.ok) { return $s }; Start-Sleep -Milliseconds 500 }; return $s }
function Gateway { $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1; if ($r) { return $r.NextHop }; return '' }
function Reaches([string]$ip) { if (-not $ip) { return $false }; return [bool](Test-Connection -ComputerName $ip -Count 2 -Quiet -ErrorAction SilentlyContinue) }
# Whether the node gets a datagram through the tunnel to a program listening
# on every address of this machine, unasked. UDP, not TCP: the node's own
# firewall drops what comes back to it from the tunnel, so a TCP probe from
# the node could not complete either way. The kill switch must keep it out.
# Windows Firewall would drop it anyway (no rule allows the port, and the
# tunnel adapter is a Public network), so for the probe a rule of its own
# lets the port in on every profile: what keeps the datagram out is then the
# kill switch, and the control step (kill switch lifted) shows it arrives.
$ProbeRule = 'HidraVPN phase 4 test probe'
function Unasked-Reaches {
  $tun = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'hvpn0' -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
  if (-not $tun) { return $null }
  New-NetFirewallRule -DisplayName $ProbeRule -Direction Inbound -Protocol UDP -LocalPort 9902 -Action Allow -Profile Any | Out-Null
  $u = New-Object System.Net.Sockets.UdpClient(9902)
  try {
    Ssh "echo unasked > /dev/udp/$tun/9902" | Out-Null
    Start-Sleep -Seconds 2
    return ($u.Available -gt 0)
  } finally {
    $u.Close()
    Remove-NetFirewallRule -DisplayName $ProbeRule -ErrorAction SilentlyContinue
  }
}

function Cleanup {
  Remove-NetFirewallRule -DisplayName $ProbeRule -ErrorAction SilentlyContinue
  if (Test-Path $ISvc) { & $ISvc down 2>&1 | Out-Null; & $ISvc uninstall 2>&1 | Out-Null; & $ISvc firewall off 2>&1 | Out-Null }
  elseif (Test-Path $SvcExe) { & $SvcExe firewall off 2>&1 | Out-Null }
}
function Finish {
  $fails = @($script:Checks | Where-Object { $_.R -eq 'FAIL' }).Count
  $passes = @($script:Checks | Where-Object { $_.R -eq 'PASS' }).Count
  Log ''; Log '================ HidraVPN phase 4 - Windows test ================'
  foreach ($f in $script:Facts) { Log $f }
  foreach ($c in $script:Checks) { $l = '{0,-5} {1}' -f $c.R, $c.N; if ($c.D) { $l += "  ($($c.D))" }; Log $l }
  if ($passes -eq 0 -and $fails -eq 0) { Log 'FAIL  no checks ran'; $fails = 1 }
  Log ('RESULT: {0}  ({1} passed, {2} failed)' -f $(if ($fails -eq 0) { 'PASS' } else { 'FAIL' }), $passes, $fails)
  Log '================================================================'
  Log "Saved to $ReportPath. Send the block above."
}
function Stop-Now([string]$why) { Log ''; Log "STOPPED: $why"; Cleanup; Finish; exit 2 }

Log "HidraVPN phase 4 Windows test, $(Get-Date -Format 'yyyy-MM-dd HH:mm')  (exit $Exit)"
Log "PowerShell $($PSVersionTable.PSVersion), $([Environment]::OSVersion.VersionString)"
if ($Exit -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { Stop-Now "'$Exit' is not an IPv4 address" }
foreach ($f in $SvcExe, $CliExe, (Join-Path $Dir 'wintun.dll')) { if (-not (Test-Path $f)) { Stop-Now "$f is missing" }; Unblock-File $f -ErrorAction SilentlyContinue }
if ((Test-Path $ISvc) -or (Test-Path $KeyFile)) { Stop-Now "HidraVPN is already installed here ($Installed / $Data). Uninstall it with --purge first; this test starts from nothing." }
foreach ($exe in $SvcExe, $CliExe) {
  $v = (& $exe --version 2>&1 | Out-String).Trim()
  if ($v -notmatch 'hidravpn') { Stop-Now "$(Split-Path -Leaf $exe) did not run (Smart App Control? use the signed build): $v" }
  Fact "$(Split-Path -Leaf $exe)  $v  signature $((Get-AuthenticodeSignature $exe).Status)"
}

try {
  Step 'baseline'
  $base = Ip4; if (-not $base) { Stop-Now 'no internet right now' }
  if ($base -eq $Exit) { Stop-Now 'this machine already leaves through the node' }
  $gw = Gateway; $gwBefore = Reaches $gw
  Fact "before   IPv4 $(Mask $base); IPv6 $(if (Ip6) { 'yes' } else { 'none' }); gateway $(if ($gwBefore) { 'answers ping' } else { 'does not answer ping (local network checks skipped)' })"

  Step 'install, as the browser runs it: the service with the client beside it'
  $out = (& $SvcExe install --client $CliExe 2>&1 | Out-String).Trim()
  Expect ($LASTEXITCODE -eq 0) 'install --client succeeds' (($out -split "`r?`n")[-1])
  Expect ((Test-Path $ISvc) -and (Test-Path $ICli) -and (Test-Path (Join-Path $Installed 'wintun.dll'))) 'the service, the client and wintun.dll are in Program Files\HidraVPN'
  $svc = Get-CimInstance Win32_Service -Filter "Name='HidraVPN'" -ErrorAction SilentlyContinue
  Expect ($null -ne $svc -and $svc.StartName -match 'LocalSystem' -and $svc.StartMode -eq 'Auto') 'the service runs as LocalSystem at boot' "$($svc.StartName)/$($svc.StartMode)"
  Expect (Test-Path $KeyFile) "this machine's key was made at install"
  $acl = (Get-Acl $Data).Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }
  $open = @($acl | Where-Object { $_ -match 'Users|Everyone|Authenticated' -and $_ -match 'FullControl|Modify|Write' })
  Expect ($open.Count -eq 0) 'the data folder gives users no write or full control' ($acl -join '; ')
  $s = Wait-Pipe
  Expect ($s.ok -and $s.status.version) 'the pipe answers status, with the service version' "$($s.status.version) $($s.error)"
  $keyHash = (Get-FileHash $KeyFile -Algorithm SHA256).Hash

  Step 'update: install again over the running service'
  $out = (& $SvcExe install --client $CliExe 2>&1 | Out-String).Trim()
  Expect ($LASTEXITCODE -eq 0) 'installing over a running service succeeds (it is stopped and replaced)' (($out -split "`r?`n")[-1])
  Expect ((Get-FileHash $KeyFile -Algorithm SHA256).Hash -eq $keyHash) 'an update keeps the key'
  $s = Wait-Pipe; Expect ($s.ok) 'the updated service answers on the pipe' "$($s.error)"

  Step 'admission on the node (as in phase 3)'
  $nodePub = Ssh '/usr/local/bin/hidravpn-node pubkey'
  if ($nodePub -notmatch $KeyRe) { Stop-Now "could not read the node's key over ssh: $nodePub" }
  $pub = (& $ICli pubkey --node $nodePub 2>$null | Out-String).Trim()
  $Name = ($Name -replace '[^A-Za-z0-9_-]', '-'); if (-not $Name) { $Name = 'windows' }
  $inviteText = Ssh "/usr/local/bin/hidravpn-node admit --name '$Name' --pubkey '$pub'"
  $inv = Join-Path $Dir 'exit.json'; Set-Content $inv $inviteText -Encoding Ascii
  $out = (& $ICli nodes add --exit $inv 2>&1 | Out-String).Trim()
  Expect ($LASTEXITCODE -eq 0) 'the invite goes into the pocket' $out

  Step 'connect over the pipe, local network NOT allowed'
  $r = Pipe @{ cmd = 'connect'; mode = 'rapido'; allow_lan = $false; keep_ipv6 = $false }
  Expect ($r.ok) 'connect (rapido) over the pipe' "$($r.error)$($r.note)"
  Start-Sleep -Seconds 4
  $s = Pipe @{ cmd = 'status' }
  Expect ($s.status.connected -and $s.status.killswitch) 'status: connected, kill switch armed' "connected=$($s.status.connected) ks=$($s.status.killswitch)"
  $ip = Ip4; Expect ($ip -eq $Exit) 'leak test, IPv4: websites see the node' (Mask $ip)
  $v6 = Ip6; Expect (-not $v6) 'leak test, IPv6: nothing leaves' $v6
  $dns = $null; try { $dns = Resolve-DnsName example.com -Type A -ErrorAction Stop } catch {}
  Expect ($null -ne $dns) 'names still resolve (through the tunnel)'
  $in = Unasked-Reaches; Expect ($in -eq $false) 'a datagram the node sends this machine unasked does not arrive' "$(if ($null -eq $in) { 'no tunnel address' } else { "arrived=$in" })"
  if ($gwBefore) { Expect (-not (Reaches $gw)) 'the local network is NOT reachable when not allowed' }
  # The control: with the kill switch lifted (the tunnel stays up), the same
  # datagram arrives, so its absence above and below is the kill switch's
  # doing. The reconnect below arms it again.
  & $ISvc firewall off 2>&1 | Out-Null
  $in = Unasked-Reaches; Expect ($in -eq $true) 'control: with the kill switch lifted, that datagram does arrive (the probe measures the kill switch)' "$(if ($null -eq $in) { 'no tunnel address' } else { "arrived=$in" })"

  Step 'reconnect with the local network allowed'
  Pipe @{ cmd = 'down' } | Out-Null; Start-Sleep -Seconds 2
  $r = Pipe @{ cmd = 'connect'; mode = 'rapido'; allow_lan = $true; keep_ipv6 = $false }
  Expect ($r.ok) 'connect with allow_lan' "$($r.error)"
  Start-Sleep -Seconds 4
  if ($gwBefore) { Expect (Reaches $gw) 'the local network IS reachable when allowed' }
  $in = Unasked-Reaches; Expect ($in -eq $false) 'and still nothing arrives from the node unasked' "$(if ($null -eq $in) { 'no tunnel address' } else { "arrived=$in" })"
  $ip = Ip4; Expect ($ip -eq $Exit) 'and the internet still goes through the node' (Mask $ip)

  Step 'disconnect'
  $r = Pipe @{ cmd = 'down' }; Start-Sleep -Seconds 3
  $ip = Ip4; Expect ($ip -eq $base) 'after down the network is back' (Mask $ip)

  Step 'uninstall, then uninstall --purge'
  $out = (& $ISvc uninstall 2>&1 | Out-String).Trim()
  Expect ($LASTEXITCODE -eq 0 -and $null -eq (Get-CimInstance Win32_Service -Filter "Name='HidraVPN'" -ErrorAction SilentlyContinue)) 'uninstall removes the service' (($out -split "`r?`n")[-1])
  Expect ((Test-Path $KeyFile) -and (Test-Path $ICli)) 'without --purge the key and the programs stay'
  & $SvcExe install --client $CliExe 2>&1 | Out-Null
  $out = (& $ISvc uninstall --purge 2>&1 | Out-String).Trim()
  Start-Sleep -Seconds 8
  Expect (-not (Test-Path $Data)) '--purge removes ProgramData\HidraVPN (the key and the nodes)'
  Expect (-not (Test-Path $Installed)) '--purge removes Program Files\HidraVPN a few seconds later'
  $ip = Ip4; Expect ($ip -eq $base) 'and the network is as it was' (Mask $ip)
}
finally {
  Cleanup
  Finish
}
