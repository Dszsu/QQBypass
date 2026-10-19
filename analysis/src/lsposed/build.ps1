# QQ self-check bypass - LSPosed module builder (fully offline, ASCII only)
#
# Two aapt2 quirks on this machine, both worked around below:
#   1. aapt2 --dir / -A fails on non-ASCII paths (it opens the directory
#      through an ANSI API). -> link the bare manifest, inject assets via zip.
#   2. aapt2 link needs one fix per run; res/ is not needed at all because
#      xposedscope is expressed as a literal meta-data value.

$ErrorActionPreference = 'Continue'

$here = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Locate the toolchain without hardcoding the non-ASCII drive path.
$tool = $null
Get-ChildItem ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady } |
              ForEach-Object { $_.RootDirectory.FullName }) -Directory -ErrorAction SilentlyContinue |
    ForEach-Object {
        $cand = Join-Path $_.FullName 'android-re-tools'
        if (-not $tool -and (Test-Path (Join-Path $cand 'sdk\build-tools'))) { $tool = $cand }
    }
if (-not $tool) { throw 'android-re-tools not found' }

$jdk     = Get-ChildItem (Join-Path $tool 'jdk') -Directory | Select-Object -First 1
$jdk     = $jdk.FullName
$bt      = Get-ChildItem (Join-Path $tool 'sdk\build-tools') -Directory | Sort-Object Name -Descending | Select-Object -First 1
$bt      = $bt.FullName
$android = Get-ChildItem (Join-Path $tool 'sdk\platforms') -Directory |
           Where-Object { Test-Path (Join-Path $_.FullName 'android.jar') } |
           Sort-Object Name | Select-Object -First 1
$android = Join-Path $android.FullName 'android.jar'

Write-Host "jdk     = $jdk"
Write-Host "bt      = $bt"
Write-Host "android = $android"

$build = Join-Path $here 'build'
$out   = Join-Path $build 'QQClean.apk'

function Step($n, $msg) { Write-Host ''; Write-Host "[$n] $msg" -ForegroundColor Cyan }
function Die($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; exit 1 }

Step 0 'clean'
if (Test-Path $build) { Remove-Item $build -Recurse -Force }
foreach ($p in 'stub', 'classes', 'dex') {
    New-Item -ItemType Directory -Force -Path (Join-Path $build $p) | Out-Null
}

Step 1 'compile Xposed API stubs'
$stubFiles = (Get-ChildItem (Join-Path $here 'stub') -Recurse -Filter *.java | ForEach-Object { $_.FullName })
& (Join-Path $jdk 'bin\javac.exe') -encoding UTF-8 --release 8 -Xlint:-options `
    -cp $android -d (Join-Path $build 'stub') @stubFiles
if ($LASTEXITCODE -ne 0) { Die 'stub compile failed' }
Write-Host ('  {0} class files' -f (Get-ChildItem (Join-Path $build 'stub') -Recurse -Filter *.class).Count)

Step 2 'compile module sources'
$cp = (Join-Path $build 'stub') + ';' + $android
$srcFiles = (Get-ChildItem (Join-Path $here 'src') -Recurse -Filter *.java | ForEach-Object { $_.FullName })
Write-Host ('  {0} source files' -f $srcFiles.Count)
& (Join-Path $jdk 'bin\javac.exe') -encoding UTF-8 --release 8 -Xlint:-options `
    -cp $cp -d (Join-Path $build 'classes') @srcFiles
if ($LASTEXITCODE -ne 0) { Die 'module compile failed' }
Write-Host ('  {0} class files' -f (Get-ChildItem (Join-Path $build 'classes') -Recurse -Filter *.class).Count)

Step 3 'd8 -> dex'
$stage = Join-Path $build 'stage'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item (Join-Path $build 'classes\*') $stage -Recurse -Force
$jar = Join-Path $build 'classes.jar'
Push-Location $stage
& (Join-Path $jdk 'bin\jar.exe') cf $jar .
Pop-Location
& (Join-Path $bt 'd8.bat') --release --min-api 23 --lib $android --output (Join-Path $build 'dex') $jar 2>&1 | Out-String | Out-Null

$dex = Join-Path $build 'dex\classes.dex'
if (-not (Test-Path $dex)) { Die 'd8 failed' }
Write-Host ('  classes.dex {0:N0} bytes' -f (Get-Item $dex).Length)

Step 4 'aapt2 link (manifest only)'
$baseApk = Join-Path $build 'base.apk'
& (Join-Path $bt 'aapt2.exe') link -o $baseApk -I $android `
    --manifest (Join-Path $here 'AndroidManifest.xml') `
    --min-sdk-version 23 --target-sdk-version 34
if (-not (Test-Path $baseApk)) { Die 'aapt2 link failed' }
Write-Host ('  base.apk {0:N0} bytes' -f (Get-Item $baseApk).Length)

Step 5 'inject classes.dex + assets/xposed_init'
$unsigned = Join-Path $build 'unsigned.apk'
Copy-Item $baseApk $unsigned -Force

# Guard: xposed_init MUST be plain ASCII without a BOM.
# A UTF-8 BOM makes LSPosed read the class name as "\ufeffcom.qqclean.bypass.MainHook"
# and fail with ClassNotFoundException. This bit us once already.
$initPath = Join-Path $here 'assets\xposed_init'
$initBytes = [System.IO.File]::ReadAllBytes($initPath)
if ($initBytes.Length -ge 3 -and $initBytes[0] -eq 0xEF -and $initBytes[1] -eq 0xBB -and $initBytes[2] -eq 0xBF) {
    Write-Host '  [FIX] xposed_init had a UTF-8 BOM - rewriting without it' -ForegroundColor Yellow
    $txt = [System.Text.Encoding]::UTF8.GetString($initBytes).TrimStart([char]0xFEFF)
    [System.IO.File]::WriteAllText($initPath, $txt, (New-Object System.Text.UTF8Encoding($false)))
    $initBytes = [System.IO.File]::ReadAllBytes($initPath)
}
if ($initBytes | Where-Object { $_ -gt 127 }) {
    Die 'xposed_init contains non-ASCII bytes'
}
Write-Host ('  xposed_init = "{0}"' -f ([System.Text.Encoding]::ASCII.GetString($initBytes).Trim()))

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($unsigned, 'Update')
foreach ($name in 'classes.dex', 'assets/xposed_init') {
    $old = $zip.GetEntry($name)
    if ($old) { $old.Delete() }
}
[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
    $zip, $dex, 'classes.dex', 'Optimal') | Out-Null
[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
    $zip, $initPath, 'assets/xposed_init', 'Optimal') | Out-Null
$zip.Dispose()
Write-Host '  ok'

Step 6 'zipalign'
$aligned = Join-Path $build 'aligned.apk'
& (Join-Path $bt 'zipalign.exe') -f 4 $unsigned $aligned
if ($LASTEXITCODE -ne 0) { Die 'zipalign failed' }

Step 7 'sign'
$ks = Join-Path $here 'debug.keystore'
if (-not (Test-Path $ks)) {
    & (Join-Path $jdk 'bin\keytool.exe') -genkeypair -keystore $ks `
        -storepass android -keypass android -alias qqclean `
        -keyalg RSA -keysize 2048 -validity 10000 `
        -dname 'CN=QQClean, OU=dev, O=dev, L=NA, S=NA, C=CN'
    if (-not (Test-Path $ks)) { Die 'keystore generation failed' }
}
& (Join-Path $bt 'apksigner.bat') sign --ks $ks `
    --ks-pass 'pass:android' --key-pass 'pass:android' `
    --out $out $aligned
if (-not (Test-Path $out)) { Die 'signing failed' }

Step 8 'verify'
& (Join-Path $bt 'apksigner.bat') verify --print-certs $out 2>&1 | Out-String | Write-Host
Write-Host ''
Write-Host ('  {0}  ({1:N0} bytes)' -f $out, (Get-Item $out).Length)
Write-Host '  contents:'
$z = [System.IO.Compression.ZipFile]::OpenRead($out)
$z.Entries | Sort-Object FullName | ForEach-Object { Write-Host ('    {0,-24} {1,8:N0}' -f $_.FullName, $_.Length) }
$z.Dispose()

Write-Host ''
Write-Host '==== BUILD OK ====' -ForegroundColor Green
Write-Host ('adb install -r "{0}"' -f $out)
Write-Host 'then enable in LSPosed, scope com.tencent.mobileqq, force-stop QQ'
Write-Host 'logs: adb logcat -s QQClean'
