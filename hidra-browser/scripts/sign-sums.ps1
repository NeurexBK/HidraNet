# HidraNet - sign landing/SHA256SUMS.txt with the release key, offline.
#
# The browser believes the record at the top of the checksum table (the
# latest version, the minimum safe version, how long the record is valid)
# only when SHA256SUMS.txt.sig is the release key's signature of it. The
# signature is made over the label "hidranet-browser-sums-v1", a zero byte,
# then the file, so it can never pass for the signature of a HidraVPN
# manifest or of anything else the same key signs. This script builds those
# bytes, has hidravpn-sign sign them with the key, checks the result against
# the public key the browser embeds, and writes SHA256SUMS.txt.sig.
#
# Run it on the machine that holds the release key, from the repository
# root, in PowerShell:
#
#   .\hidra-browser\scripts\sign-sums.ps1 -Key E:\hidravpn-release.key
#   .\hidra-browser\scripts\sign-sums.ps1 -Key E:\hidravpn-release.key -Sign C:\HidraVPN\hidravpn-sign.exe
#
# Any hidravpn-sign works: the label is added here, not by the tool. The key
# file is only read by hidravpn-sign; it is never copied, printed or kept.
# Then commit landing/SHA256SUMS.txt and landing/SHA256SUMS.txt.sig together.

param(
  [Parameter(Mandatory = $true)][string]$Key,
  [string]$Sums = "landing\SHA256SUMS.txt",
  [string]$Sign = "hidravpn-sign"
)

$ErrorActionPreference = "Stop"

function Fail($msg) {
  Write-Host "  $msg" -ForegroundColor Red
  exit 1
}

if (-not (Test-Path -LiteralPath $Sums -PathType Leaf)) { Fail "no $Sums here: run this from the repository root" }
if (-not (Test-Path -LiteralPath $Key -PathType Leaf)) { Fail "no key file at $Key" }
$repo = (Resolve-Path ".").Path
$keyPath = (Resolve-Path -LiteralPath $Key).Path
if ($keyPath.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) {
  Fail "the key is inside the repository ($keyPath). Keep it outside, on the offline medium."
}

# The public key the browser checks with, from the browser's own source.
$verifySrc = Get-Content -Raw -LiteralPath "hidra-browser\src\main\release-verify.js"
$m = [regex]::Match($verifySrc, "const RELEASE_PUBLIC_KEY = '([A-Za-z0-9+/=]{44})';")
if (-not $m.Success) { Fail "cannot read RELEASE_PUBLIC_KEY from hidra-browser\src\main\release-verify.js" }
$pubkey = $m.Groups[1].Value

$sumsPath = (Resolve-Path -LiteralPath $Sums).Path
[byte[]]$table = [System.IO.File]::ReadAllBytes($sumsPath)
# A Windows checkout can turn LF into CRLF; the site serves LF, and the
# signature has to be over the bytes the site serves.
if ($table -contains [byte]13) {
  Fail "$Sums has CRLF line endings. Run: git rm --cached -q $Sums; git checkout -- $Sums  (.gitattributes keeps it LF)"
}

# What is about to be signed, for the person signing to read.
$text = [System.Text.Encoding]::UTF8.GetString($table)
$fields = @{}
foreach ($name in @("latest-version", "minimum-safe-version", "valid-until")) {
  $found = [regex]::Matches($text, "(?m)^  " + [regex]::Escape($name) + ":[ \t]+(\S+)[ \t]*$")
  if ($found.Count -ne 1) { Fail "the record must have exactly one '${name}:' line" }
  $fields[$name] = $found[0].Groups[1].Value
}
$until = [datetime]::MinValue
if (-not [datetime]::TryParseExact($fields["valid-until"], "yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$until)) { Fail "valid-until is not a date (YYYY-MM-DD)" }
$days = ($until.ToUniversalTime() - [datetime]::UtcNow).TotalDays
if ($days -lt 1) { Fail "valid-until ($($fields["valid-until"])) has passed: set a later date first" }
if ($days -gt 400) { Fail "valid-until ($($fields["valid-until"])) is more than 400 days away: a record valid that long can be replayed that long" }

$sha = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256).Hash.ToLower()
Write-Host ""
Write-Host "  $Sums"
Write-Host "  sha256                $sha"
Write-Host "  latest-version        $($fields["latest-version"])"
Write-Host "  minimum-safe-version  $($fields["minimum-safe-version"])"
Write-Host "  valid-until           $($fields["valid-until"])"
Write-Host ""
$answer = Read-Host "  Sign this with the release key? Type yes"
if ($answer -ne "yes") { Fail "not signed" }

# The label, a zero byte, the file: the same bytes release-verify.js checks.
$label = [System.Text.Encoding]::ASCII.GetBytes("hidranet-browser-sums-v1")
$message = New-Object byte[] ($label.Length + 1 + $table.Length)
[Array]::Copy($label, 0, $message, 0, $label.Length)
$message[$label.Length] = 0
[Array]::Copy($table, 0, $message, $label.Length + 1, $table.Length)

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("hidranet-sums-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $msgPath = Join-Path $work "SHA256SUMS.msg"
  [System.IO.File]::WriteAllBytes($msgPath, $message)
  & $Sign sign --key $keyPath $msgPath | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "hidravpn-sign could not sign" }
  & $Sign verify --pubkey $pubkey $msgPath
  if ($LASTEXITCODE -ne 0) {
    Fail "the signature does not check out against the browser's release key: is $Key the release key (not the list key)?"
  }
  Copy-Item -LiteralPath ($msgPath + ".sig") -Destination ($sumsPath + ".sig") -Force
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "  wrote $Sums.sig" -ForegroundColor Green
Write-Host "  Check it as CI will:  node hidra-browser\scripts\verify-sums.js"
Write-Host "  Then commit $Sums and $Sums.sig together."
