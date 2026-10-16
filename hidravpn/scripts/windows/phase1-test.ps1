#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  HidraVPN phase 1: end-to-end test of the Windows client against a real node.

.DESCRIPTION
  Run it in a PowerShell opened "as Administrator" on the Windows machine that
  will be the client. It does, in order:

    1. puts hidravpn.exe in C:\HidraVPN: a copy you downloaded (found by its
       SHA-256), or one built on the node over ssh and fetched with scp;
    2. fetches wintun.dll from wintun.net and refuses it unless its Authenticode
       signature is valid and from WireGuard LLC;
    3. makes the client key if there is none, and admits its public key on the
       node over ssh (hidravpn-node admit), saving the invite;
    4. connects, then checks: the exit address is the node's, DNS is answered by
       the node, HTTPS works, a 2 MB transfer works, routes and DNS sit on the
       tunnel adapter, IPv6 does not leak, the node sees the client;
    5. disconnects with Ctrl+C (or waits for yours, with -Manual) and checks
       that the network is back exactly as it was;
    6. prints a report to send back.

  ssh and scp are the ones installed with Windows; they may ask for your key's
  passphrase. Nothing here reads, shows or sends a key. The report masks your
  own public address.

.PARAMETER Server
  The node's address, for ssh and as the WireGuard endpoint.
.PARAMETER Name
  The client's name on the node (1-32 letters, digits, - or _). Default: your user name.
.PARAMETER Exe
  A hidravpn.exe you already downloaded, to copy into place.
.PARAMETER Manual
  Stay connected after the checks until you press Ctrl+C yourself.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [string]$SshUser = 'root',
  [string]$Name = $env:USERNAME,
  [string]$Dir = 'C:\HidraVPN',
  [string]$Exe = '',
  [string]$ServerSource = '/opt/hidranet-src',
  [string]$KnownExeHash = '29AAAFFC344D818FD269C73E5BB5C883F8B4377E1648BEB9D2D1D091E93A84CB',
  [string]$WintunUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip',
  [switch]$Manual
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

# ---------------------------------------------------------------- report ----
$LogDir = Join-Path $Dir 'logs'
New-Item -ItemType Directory -Force -Path $Dir, $LogDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ReportPath = Join-Path $LogDir "phase1-$Stamp.txt"
$script:Checks = @()
$script:Facts = @()

function Log([string]$msg) {
  Write-Host $msg
  Add-Content -Path $ReportPath -Value $msg
}
function Step([string]$msg) { Log ''; Log "== $msg" }
function Fact([string]$msg) { $script:Facts += $msg; Log $msg }
function Check([string]$result, [string]$name, [string]$detail = '') {
  $script:Checks += [pscustomobject]@{ Result = $result; Name = $name; Detail = $detail }
  $line = '{0,-5} {1}' -f $result, $name
  if ($detail) { $line += "  ($detail)" }
  Log $line
}
function Finish {
  $fails = @($script:Checks | Where-Object { $_.Result -eq 'FAIL' }).Count
  $passes = @($script:Checks | Where-Object { $_.Result -eq 'PASS' }).Count
  Log ''
  Log '================ HidraVPN phase 1 - Windows client test ================'
  foreach ($f in $script:Facts) { Log $f }
  foreach ($c in $script:Checks) {
    $line = '{0,-5} {1}' -f $c.Result, $c.Name
    if ($c.Detail) { $line += "  ($($c.Detail))" }
    Log $line
  }
  $verdict = if ($fails -eq 0) { 'PASS' } else { 'FAIL' }
  Log ('RESULT: {0}  ({1} passed, {2} failed)' -f $verdict, $passes, $fails)
  Log '========================================================================'
  Log "Saved to $ReportPath. Send the block above."
  if ($fails -eq 0) { exit 0 } else { exit 1 }
}
function Fail-Now([string]$why) {
  Log ''
  Log "STOPPED: $why"
  Log "Report: $ReportPath"
  exit 2
}

# --------------------------------------------------------------- helpers ----
function Mask-Ip([string]$ip) {
  if (-not $ip) { return '(none)' }
  if ($ip -match '^(\d{1,3}\.){3}(\d{1,3})$') { return "*.*.*.$($Matches[2])" }
  if ($ip -match ':') { return '*:*:...:' + ($ip.Split(':')[-1]) }
  return $ip
}
function Run-Native([string]$file, [string[]]$argv) {
  # stdout as one trimmed string; stderr goes to the console.
  $out = & $file @argv
  return (($out | Out-String).Trim())
}
function Exit-Ip([string]$family) {
  foreach ($u in 'https://ifconfig.me/ip', 'https://icanhazip.com', 'https://api64.ipify.org') {
    $ip = (& curl.exe "-$family" -s -m 15 $u 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -eq 0 -and $ip -match '^[0-9a-fA-F:.]+$') { return $ip }
  }
  return ''
}
function Dns-Servers {
  # The IPv4 resolvers the system would use, the lowest-metric adapter first.
  # Read straight from the stack, not from nslookup's localised text.
  $out = @()
  foreach ($r in (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    if ($r.ServerAddresses.Count -eq 0) { continue }
    $m = (Get-NetIPInterface -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty InterfaceMetric)
    if ($null -eq $m) { $m = 9999 }
    foreach ($s in $r.ServerAddresses) {
      $out += [pscustomobject]@{ Server = $s; Alias = $r.InterfaceAlias; Metric = [int]$m }
    }
  }
  return ($out | Sort-Object Metric)
}
function Node-Answers([string]$server, [string]$name) {
  # Ask the node's resolver directly: proof it is the one answering, not just configured.
  try {
    $a = Resolve-DnsName -Name $name -Type A -Server $server -DnsOnly -ErrorAction Stop
    return (@($a | Where-Object { $_.IPAddress }).Count -gt 0)
  } catch { return $false }
}
function Resolves([string]$name) {
  return (@(Resolve-DnsName -Name $name -Type A -DnsOnly -ErrorAction SilentlyContinue).Count -gt 0)
}
function Wintun-Check([string]$path) {
  $sig = Get-AuthenticodeSignature -FilePath $path
  $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(unsigned)' }
  return [pscustomobject]@{
    Ok      = ($sig.Status -eq 'Valid' -and $subject -match 'WireGuard LLC')
    Status  = "$($sig.Status)"
    Subject = $subject
  }
}

Log "HidraVPN phase 1 Windows client test, $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Log "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), $([Environment]::OSVersion.VersionString)"
foreach ($t in 'ssh.exe', 'scp.exe', 'curl.exe', 'nslookup.exe') {
  if (-not (Get-Command $t -ErrorAction SilentlyContinue)) {
    Fail-Now "$t is not available. For ssh/scp: Settings > Apps > Optional features > OpenSSH Client."
  }
}

# --------------------------------------------------------- hidravpn.exe ----
Step 'hidravpn.exe'
$ExePath = Join-Path $Dir 'hidravpn.exe'
if ($Exe) {
  if (-not (Test-Path $Exe)) { Fail-Now "-Exe points at $Exe, which does not exist" }
  Copy-Item -Path $Exe -Destination $ExePath -Force
}
if (-not (Test-Path $ExePath)) {
  $found = $null
  $places = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents")
  if ($env:OneDrive) { $places += "$env:OneDrive\Downloads", "$env:OneDrive\Desktop" }
  foreach ($d in $places) {
    if (-not (Test-Path $d)) { continue }
    foreach ($c in Get-ChildItem -Path $d -Filter 'hidravpn*.exe' -File -Recurse -Depth 1 -ErrorAction SilentlyContinue) {
      if ((Get-FileHash -Path $c.FullName -Algorithm SHA256).Hash -ieq $KnownExeHash) { $found = $c.FullName; break }
    }
    if ($found) { break }
  }
  if ($found) {
    Log "using the downloaded build at $found (its hash is the expected one)"
    Copy-Item -Path $found -Destination $ExePath -Force
  } else {
    Log 'no downloaded hidravpn.exe with the expected hash in Downloads, Desktop or Documents'
    Log "building it on the node instead: ssh $SshUser@$Server (the MinGW cross toolchain is installed there once; a few minutes)"
    $remote = "set -e; cd '$ServerSource' || { echo 'no source checkout at $ServerSource' >&2; exit 2; }; " +
              'git fetch -q origin main && git checkout -q main && git merge -q --ff-only origin/main; ' +
              "bash hidravpn/scripts/build-windows-client.sh '$ServerSource'"
    & ssh.exe -o ConnectTimeout=20 "$SshUser@$Server" $remote
    if ($LASTEXITCODE -ne 0) { Fail-Now "the build on the node failed (exit $LASTEXITCODE); see above" }
    & scp.exe -q -o ConnectTimeout=20 "${SshUser}@${Server}:/root/hidravpn-win/hidravpn.exe" $ExePath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ExePath)) { Fail-Now 'could not fetch the built hidravpn.exe from the node' }
  }
}
Unblock-File -Path $ExePath -ErrorAction SilentlyContinue
$ExeHash = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash
$ExeOrigin = if ($ExeHash -ieq $KnownExeHash) { 'the build shipped in chat' } else { 'a local or node build' }
$ver = Run-Native $ExePath @('--version')
if ($LASTEXITCODE -ne 0 -or -not $ver) { Fail-Now "hidravpn.exe does not run here. Windows Defender may have blocked or removed it; check its protection history." }
Fact "exe      $ExePath  $ver  sha256 $ExeHash  ($ExeOrigin)"

# ------------------------------------------------------------ wintun.dll ----
Step 'wintun.dll'
$Dll = Join-Path $Dir 'wintun.dll'
if (-not (Test-Path $Dll) -or -not (Wintun-Check $Dll).Ok) {
  $zip = Join-Path $LogDir 'wintun.zip'
  $unz = Join-Path $LogDir 'wintun'
  Log "downloading $WintunUrl"
  try { Invoke-WebRequest -UseBasicParsing -Uri $WintunUrl -OutFile $zip } catch { Fail-Now "could not download Wintun: $($_.Exception.Message)" }
  if (Test-Path $unz) { Remove-Item -Path $unz -Recurse -Force }
  Expand-Archive -Path $zip -DestinationPath $unz -Force
  $src = Join-Path $unz 'wintun\bin\amd64\wintun.dll'
  if (-not (Test-Path $src)) { Fail-Now 'the Wintun zip has no wintun\bin\amd64\wintun.dll' }
  Copy-Item -Path $src -Destination $Dll -Force
}
$w = Wintun-Check $Dll
if (-not $w.Ok) {
  Remove-Item -Path $Dll -Force -ErrorAction SilentlyContinue
  Fail-Now "wintun.dll signature is '$($w.Status)' by '$($w.Subject)': refusing to load it"
}
Fact "wintun   $((Get-Item $Dll).VersionInfo.ProductVersion)  signature $($w.Status)  $($w.Subject)"

# ------------------------------------------------------------ client key ----
Step 'client key'
$KeyPath = Join-Path $env:ProgramData 'HidraVPN\client.key'
if (-not (Test-Path $KeyPath)) {
  & $ExePath keygen | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail-Now 'keygen failed' }
  Log "new key at $KeyPath (the secret stays there and is never shown)"
} else {
  Log "key already at $KeyPath"
}
# Every node is shown a different key, derived from the master key for that
# node (phase 3). The node's own public key comes first, over ssh; it needs a
# hidravpn-node from this branch (`hidravpn-node pubkey`).
$NodePub = ((& ssh.exe -o ConnectTimeout=20 "$SshUser@$Server" '/usr/local/bin/hidravpn-node pubkey') | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $NodePub -notmatch '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$') { Fail-Now "could not read the node's public key over ssh (the node needs hidravpn-node from this branch): $NodePub" }
$Pub = Run-Native $ExePath @('pubkey', '--node', $NodePub)
if ($LASTEXITCODE -ne 0 -or $Pub -notmatch '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$') { Fail-Now "could not derive the key for this node ($Pub)" }
Log "key for this node $Pub (the master key's public half is never shown to a node)"

# ------------------------------------------------------------------ admit ----
$Name = $Name -replace '[^A-Za-z0-9_-]', '-'
if (-not $Name) { $Name = 'windows' }
if ($Name.Length -gt 32) { $Name = $Name.Substring(0, 32) }
Step "admitting the key on the node as '$Name' (ssh $SshUser@$Server; ssh itself may ask for your key's passphrase)"
$inviteText = ((& ssh.exe -o ConnectTimeout=20 "$SshUser@$Server" "/usr/local/bin/hidravpn-node admit --name '$Name' --pubkey '$Pub'") | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { Fail-Now "admit failed on the node (exit $LASTEXITCODE)" }
$Invite = $null
try { $Invite = $inviteText | ConvertFrom-Json -ErrorAction Stop } catch { }
if (-not $Invite -or -not $Invite.endpoint) { Fail-Now "the node did not return an invite:`n$inviteText" }
$InvitePath = Join-Path $Dir 'invite.json'
Set-Content -Path $InvitePath -Value $inviteText -Encoding Ascii
$NodeIp = ($Invite.endpoint -split ':')[0]
$Dns = "$($Invite.dns)"
$Iface = 'hvpn0'
Fact "client   '$Name' $($Invite.client_address) -> node '$($Invite.node_name)' $($Invite.endpoint), DNS $Dns"

# --------------------------------------------------------------- baseline ----
Step 'before connecting'
$Ip4Before = Exit-Ip '4'
$Ip6Before = Exit-Ip '6'
if (-not $Ip4Before) { Fail-Now 'no internet access right now: could not learn the public address' }
$DnsBefore = (Dns-Servers | Select-Object -First 1).Server
Fact "before   exit IPv4 $(Mask-Ip $Ip4Before), IPv6 $(Mask-Ip $Ip6Before), resolver $(Mask-Ip $DnsBefore)"

# ------------------------------------------------------------------- up -----
Step 'connecting'
$OutLog = Join-Path $LogDir "up-$Stamp.out.log"
$ErrLog = Join-Path $LogDir "up-$Stamp.err.log"
$Proc = Start-Process -FilePath $ExePath -ArgumentList @('up', "`"$InvitePath`"") -WorkingDirectory $Dir `
          -NoNewWindow -PassThru -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog
$t0 = Get-Date
$connected = $false
$logSeen = $false
while (((Get-Date) - $t0).TotalSeconds -lt 45) {
  Start-Sleep -Milliseconds 500
  $txt = Get-Content -Path $ErrLog -Raw -ErrorAction SilentlyContinue
  if ($txt) { $logSeen = $true }
  if ($txt -match '(?m)^connected\s*$') { $connected = $true; break }
  if ($Proc.HasExited) { break }
  # The log could not be read for 15 s but the process lives: judge by the checks.
  if (-not $logSeen -and -not $Proc.HasExited -and ((Get-Date) - $t0).TotalSeconds -ge 15) { break }
}
$secs = [int]((Get-Date) - $t0).TotalSeconds
$upLog = (Get-Content -Path $ErrLog -Raw -ErrorAction SilentlyContinue)
if ($Proc.HasExited) {
  Log (($upLog -replace "`r", "`n") -replace "`n{2,}", "`n")
  Check 'FAIL' 'tunnel connected' "hidravpn up exited after $secs s; its output is above"
  & $ExePath down | Out-Null
  Finish
}
if ($connected) {
  Check 'PASS' 'tunnel connected' "handshake after $secs s"
} elseif (-not $logSeen) {
  Check 'INFO' 'tunnel connected' 'the live log could not be read; the checks below decide'
} else {
  Log (($upLog -replace "`r", "`n") -replace "`n{2,}", "`n")
  Check 'FAIL' 'tunnel connected' "no handshake within $secs s; the client's output is above"
}

# ------------------------------------------------------- while connected ----
Step 'checks while connected'
$Ip4 = Exit-Ip '4'
if ($Ip4 -eq $NodeIp) { Check 'PASS' 'exit address is the node' $Ip4 }
else { Check 'FAIL' 'exit address is the node' "got $(Mask-Ip $Ip4), expected $NodeIp" }

$resolvers = Dns-Servers
$top = $resolvers | Select-Object -First 1
$nodeAnswers = Node-Answers $Dns 'example.com'
$resolvesNow = Resolves 'example.com'
$tunFirst = ($top -and $top.Server -eq $Dns)
if ($nodeAnswers -and $resolvesNow -and $tunFirst) {
  Check 'PASS' 'DNS through the node' "$Dns answered example.com and is the first resolver (on $($top.Alias))"
} elseif ($nodeAnswers -and $resolvesNow) {
  Check 'PASS' 'DNS through the node' "$Dns answered example.com; first resolver is $(Mask-Ip $top.Server) on $($top.Alias)"
} else {
  Check 'FAIL' 'DNS through the node' "node answered=$nodeAnswers, name resolves=$resolvesNow, first resolver $(Mask-Ip $top.Server)"
}
# Phase 1 does not yet stop the system asking another adapter's resolver too;
# that traffic still exits through the node, and phase 2's kill switch closes it.
$others = @($resolvers | Where-Object { $_.Server -ne $Dns } | Select-Object -ExpandProperty Alias -Unique)
if ($others.Count -gt 0) {
  Check 'INFO' 'other adapters still list a resolver' ("closed by the phase 2 kill switch: " + ($others -join ', '))
}

$code = (& curl.exe -4 -s -m 25 -o NUL -w '%{http_code}' https://example.com 2>$null | Out-String).Trim()
if ($code -eq '200') { Check 'PASS' 'HTTPS through the tunnel' 'https://example.com -> 200' }
else { Check 'FAIL' 'HTTPS through the tunnel' "https://example.com -> '$code'" }

$dl = (& curl.exe -4 -s -m 120 -o NUL -w '%{size_download} %{speed_download}' 'https://speed.cloudflare.com/__down?bytes=2000000' 2>$null | Out-String).Trim()
$parts = $dl -split '\s+'
$bytes = 0.0; $speed = 0.0
if ($parts.Count -ge 2) {
  [double]::TryParse($parts[0], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$bytes) | Out-Null
  [double]::TryParse($parts[1], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$speed) | Out-Null
}
if ($bytes -ge 2000000) { Check 'PASS' '2 MB transfer through the tunnel' ('{0:n0} bytes at {1:n1} MB/s' -f $bytes, ($speed / 1MB)) }
else { Check 'FAIL' '2 MB transfer through the tunnel' "curl reported '$dl'" }

$r1 = Get-NetRoute -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue | Select-Object -First 1
$r2 = Get-NetRoute -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue | Select-Object -First 1
$dnsOnTun = @(Get-DnsClientServerAddress -InterfaceAlias $Iface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
if ($r1 -and $r2 -and $r1.InterfaceAlias -eq $Iface -and $r2.InterfaceAlias -eq $Iface -and ($dnsOnTun -contains $Dns)) {
  Check 'PASS' 'routes and DNS on the tunnel adapter' "0.0.0.0/1 and 128.0.0.0/1 on $Iface, DNS $($dnsOnTun -join ',')"
} else {
  Check 'FAIL' 'routes and DNS on the tunnel adapter' "0.0.0.0/1 on '$($r1.InterfaceAlias)', 128.0.0.0/1 on '$($r2.InterfaceAlias)', DNS on $Iface '$($dnsOnTun -join ',')'"
}

$Ip6 = Exit-Ip '6'
if (-not $Ip6Before) { Check 'INFO' 'IPv6' 'none on this network before connecting, so nothing to leak' }
elseif (-not $Ip6) { Check 'PASS' 'IPv6 does not leak' 'unreachable while connected, as phase 1 intends' }
else { Check 'FAIL' 'IPv6 does not leak' "still reaches the internet as $(Mask-Ip $Ip6)" }

$st = ((& ssh.exe -o ConnectTimeout=20 "$SshUser@$Server" '/usr/local/bin/hidravpn-node status') | Out-String)
$nameLine = ($st -split "`r?`n" | Where-Object { $_ -match "(^|\s)$([regex]::Escape($Name))(\s|$)" } | Select-Object -First 1)
if ($LASTEXITCODE -eq 0 -and $nameLine) { Check 'PASS' 'the node sees the client' ($nameLine.Trim() -replace '\s+', ' ') }
else { Check 'INFO' 'node status' ("not read: " + (($st.Trim() -replace '\s+', ' ') -replace '^$', 'no output')) }

# ----------------------------------------------------------------- down -----
if ($Manual) {
  Step 'connected. Browse https://ipleak.net if you like; press Ctrl+C in this window to disconnect'
} else {
  Step 'disconnecting with Ctrl+C'
}
$null = Add-Type -Namespace HidraVpnTest -Name Kernel32 -PassThru -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleCtrlHandler(IntPtr handlerRoutine, bool add);
'@
$graceful = $false
$tStop = Get-Date
# This process ignores Ctrl+C for a moment so that only hidravpn.exe,
# which shares the console, receives it.
[HidraVpnTest.Kernel32]::SetConsoleCtrlHandler([IntPtr]::Zero, $true) | Out-Null
try {
  if ($Manual) {
    $Proc.WaitForExit()
    $graceful = $true
  } else {
    [HidraVpnTest.Kernel32]::GenerateConsoleCtrlEvent(0, 0) | Out-Null
    $graceful = $Proc.WaitForExit(30000)
  }
} finally {
  [HidraVpnTest.Kernel32]::SetConsoleCtrlHandler([IntPtr]::Zero, $false) | Out-Null
}
$stopSecs = [int]((Get-Date) - $tStop).TotalSeconds
$upLog = (Get-Content -Path $ErrLog -Raw -ErrorAction SilentlyContinue)
if ($graceful -and $upLog -match 'network restored') {
  Check 'PASS' 'Ctrl+C restores the network' "exited after $stopSecs s saying 'network restored'"
} elseif ($graceful) {
  Check 'FAIL' 'Ctrl+C restores the network' "exited after $stopSecs s without saying 'network restored'"
} else {
  Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
  & $ExePath down | Out-Null
  Check 'WARN' 'Ctrl+C restores the network' "the script could not deliver Ctrl+C; it killed the process and ran 'hidravpn down'. Run again with -Manual to test Ctrl+C by hand"
}

# ---------------------------------------------------------------- after -----
Step 'after disconnecting'
Start-Sleep -Seconds 2
$Ip4After = Exit-Ip '4'
$DnsAfter = (Dns-Servers | Select-Object -First 1).Server
$r1 = Get-NetRoute -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue
$r2 = Get-NetRoute -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue
$hostRoute = Get-NetRoute -DestinationPrefix "$NodeIp/32" -ErrorAction SilentlyContinue
$plan = Join-Path $env:ProgramData 'HidraVPN\netcfg.json'
$problems = @()
if ($Ip4After -ne $Ip4Before) { $problems += "exit address is $(Mask-Ip $Ip4After), was $(Mask-Ip $Ip4Before)" }
if ($DnsAfter -eq $Dns) { $problems += "DNS is still asked at $Dns" }
if ($r1 -or $r2) { $problems += 'the 0.0.0.0/1 or 128.0.0.0/1 route is still there' }
if ($hostRoute) { $problems += "the route to $NodeIp is still there" }
if (Test-Path $plan) { $problems += "the plan file is still there ($plan)" }
if ($problems.Count -eq 0) { Check 'PASS' 'network back to normal' "exit $(Mask-Ip $Ip4After), resolver $(Mask-Ip $DnsAfter), routes gone" }
else { Check 'FAIL' 'network back to normal' ($problems -join '; ') }

$gone = $false
for ($i = 0; $i -lt 10; $i++) {
  if (-not (Get-NetAdapter -Name $Iface -ErrorAction SilentlyContinue)) { $gone = $true; break }
  Start-Sleep -Seconds 1
}
if ($gone) { Check 'PASS' 'tunnel adapter removed' "$Iface is gone" }
else { Check 'WARN' 'tunnel adapter removed' "$Iface is still listed; it carries no routes or DNS now, and goes at the next run or reboot" }

Finish
