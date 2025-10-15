<#
.SYNOPSIS
  내부/외부 대상 자동 보안 스캔 (Windows PowerShell)
.DESCRIPTION
  - nmap (포트/서비스), trivy (fs & image), YARA, 조사 모드를 실행하고 결과를 수집/요약합니다.
  - 대상 목록은 C:\sec\scan_targets.txt 에 IP/도메인/경로 라인별로 기재
  - 이미지 목록은 C:\sec\scan_images.txt 에 이미지명 라인별로 기재 (예: myrepo/myapp:latest)
  - 출력은 C:\sec_reports\<YYYY-MM-DD>\ 에 저장됩니다.
.NOTES
  실행: 관리자 권한 필요
#>

param(
    [switch]$Investigate,
    [switch]$RunYara
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 환경변수/경로
$today = (Get-Date).ToString("yyyy-MM-dd")
$outRoot = "C:\sec_reports"
$outDir = Join-Path $outRoot $today
$targetsFile = "C:\sec\scan_targets.txt"
$imagesFile = "C:\sec\scan_images.txt"

# 툴 경로(기본 PATH에 설치했다고 가정)
$nmapExe  = "nmap.exe"
$trivyExe = "trivy.exe"

# 준비
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# 파일 존재 확인 및 기본 샘플 생성
if (!(Test-Path $targetsFile)) {
    Write-Host "Targets file not found. Creating sample at $targetsFile"
    New-Item -ItemType File -Path $targetsFile -Force -Value "127.0.0.1" | Out-Null
}
if (!(Test-Path $imagesFile)) {
    New-Item -ItemType File -Path $imagesFile -Force -Value "" | Out-Null
}

# -----------------------------
# 함수: 실행 가능 여부 검사
# -----------------------------
function Test-CommandExists {
    param([string]$exe)
    $which = Get-Command $exe -ErrorAction SilentlyContinue
    return $which -ne $null
}

# YARA 실행 파일 자동 탐지 (yara.exe / yara64.exe / 일반 경로 / choco 경로)
function Get-YaraExe {
    $candidates = @()

    # PATH 우선
    if (Get-Command yara.exe  -ErrorAction SilentlyContinue) { return "yara.exe" }
    if (Get-Command yara64.exe -ErrorAction SilentlyContinue) { return "yara64.exe" }

    # 일반 설치 경로들
    $candidates += "C:\Program Files\yara\yara64.exe"
    $candidates += "C:\Program Files\yara\yara.exe"
    $candidates += "C:\Program Files (x86)\yara\yara64.exe"
    $candidates += "C:\Program Files (x86)\yara\yara.exe"

    # Chocolatey 경로들 (shim/bin 및 tools)
    $candidates += "C:\ProgramData\chocolatey\bin\yara64.exe"
    $candidates += "C:\ProgramData\chocolatey\bin\yara.exe"
    $candidates += "C:\ProgramData\chocolatey\lib\yara\tools\yara64.exe"
    $candidates += "C:\ProgramData\chocolatey\lib\yara\tools\yara.exe"

    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# Osquery 실행 파일 자동 탐지
function Get-OsqueryExe {
    if (Get-Command osqueryi.exe -ErrorAction SilentlyContinue) { return "osqueryi.exe" }
    $candidates = @(
        "C:\Program Files\osquery\osqueryi.exe",
        "C:\ProgramData\chocolatey\lib\osquery\tools\osqueryi.exe"
    )
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    return $null
}

# -----------------------------
# 함수: 조사(증거수집)
# -----------------------------
function Collect-InvestigationEvidence {
    param([string]$OutBase)
    Write-Host "== Investigation: collecting evidence to $OutBase =="

    if (!(Test-Path $OutBase)) { New-Item -ItemType Directory -Path $OutBase -Force | Out-Null }

    Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress,LocalPort,OwningProcess,State |
        Sort-Object LocalPort | Out-File (Join-Path $OutBase "listening_ports.txt") -Encoding utf8

    Get-Process | Select-Object Id,ProcessName,Path,StartTime |
        Out-File (Join-Path $OutBase "processes.txt") -Encoding utf8

    Get-CimInstance Win32_Service |
        Select-Object Name,DisplayName,State,StartMode,ProcessId |
        Out-File (Join-Path $OutBase "services.txt") -Encoding utf8

    schtasks /query /fo LIST /v |
        Out-File (Join-Path $OutBase "scheduled_tasks.txt") -Encoding utf8

    Get-WinEvent -LogName System -MaxEvents 200 |
        Export-Clixml (Join-Path $OutBase "evt_system.xml")

    Get-WinEvent -LogName Application -MaxEvents 200 |
        Export-Clixml (Join-Path $OutBase "evt_app.xml")

    Write-Host "Investigation evidence collected."
}

# -----------------------------
# 함수: YARA 스캔 (안전 실행, stderr/exitcode 캡처)
# -----------------------------
function Run-YARAScan {
    param([string]$RulesFile, [string[]]$Targets, [string]$OutDir)

    $yaraExe = Get-YaraExe
    if (-not $yaraExe) {
        Write-Warning "YARA executable not found. Skipping YARA."
        return
    }
    if (-not (Test-Path $RulesFile)) {
        Write-Warning "Rules file not found: $RulesFile"
        return
    }
    if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

    Write-Host "YARA engine: $yaraExe"

    foreach ($t in $Targets) {
        if (-not (Test-Path $t)) {
            Write-Host "YARA target not found or not local path, skipping: $t"
            continue
        }
        $safe = ($t -replace '[:/\\]', '_')
        $outTxt = Join-Path $OutDir ("yara_" + $safe + ".txt")
        $errTxt = Join-Path $OutDir ("yara_" + $safe + ".err.txt")
        Write-Host "Running YARA on $t -> $outTxt (err -> $errTxt)"

        $args = @("-r", $RulesFile, $t)

        try {
            $proc = Start-Process -FilePath $yaraExe -ArgumentList $args -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $outTxt -RedirectStandardError $errTxt
            $exit = $proc.ExitCode
        } catch {
            Write-Warning "Failed to start YARA process for target $t : $_"
            $exit = 1
        }

        if ($exit -ne 0) {
            Write-Warning ("YARA returned exit code {0} for {1}. See {2} for stderr." -f $exit, $t, $errTxt)
            # 필요하면 stderr 내용 요약해서 출력
            if (Test-Path $errTxt) {
                $errSample = Get-Content $errTxt -ErrorAction SilentlyContinue | Select-Object -First 20
                Write-Host "YARA stderr (first lines):"
                $errSample | ForEach-Object { Write-Host "  $_" }
            }
        } else {
            Write-Host "YARA scan completed for $t (exit 0)."
        }
    }
}

# -----------------------------
# 1) nmap 네트워크 스캔
# -----------------------------
if (Test-CommandExists $nmapExe) {
    Write-Host "[*] Running nmap with smart profile (LAN=full, WAN=top-ports)..."
    $nmapOutDir = Join-Path $outDir "nmap_$($today)"
    if (-not (Test-Path $nmapOutDir)) { New-Item -Path $nmapOutDir -ItemType Directory | Out-Null }

    $nmapCommon = @('-T4','-n','-Pn','--max-retries','1','--host-timeout','3m')

    $rawTargets = @()
    try {
        $rawTargets = Get-Content $targetsFile -ErrorAction Stop |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne "" -and -not ($_ -like "#*") }
    } catch {
        Write-Warning "Failed to read targets file: $targetsFile ($_)"
        $rawTargets = @()
    }

    $hosts = @()
    foreach ($t in $rawTargets) {
        if ($t -match '^https?://') {
            try { $u = [uri] $t; if ($u.Host) { $hosts += $u.Host } } catch { Write-Warning "Invalid URL in targets: $t" }
        } else { $hosts += $t }
    }
    $hosts = $hosts | Sort-Object -Unique
    $hosts = @($hosts)

    if ($hosts.Count -eq 0) {
        Write-Host "No valid hosts found for nmap. Check $targetsFile"
    } else {
        foreach ($target in $hosts) {
            if ($target -match '(^|\.)example\.com$') { Write-Host "-> Skip sample domain: $target"; continue }

            $isPrivateIPv4 = ($target -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')
            $isIPv4        = ($target -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
            $useTopPorts   = -not $isPrivateIPv4 -and (-not $isIPv4)

            $targetSafe   = ($target -replace '[:/\\]', '_')
            $discoveryXml = Join-Path $nmapOutDir "discovery_${targetSafe}_$($today).xml"
            $serviceXml   = Join-Path $nmapOutDir "services_${targetSafe}_$($today).xml"

            $profile = if ($useTopPorts) { 'top-ports' } else { 'full-ports' }
            Write-Host ("-> Discovery scan for {0} ({1})..." -f $target, $profile)

            if ($useTopPorts) {
                & $nmapExe --top-ports 1000 @nmapCommon -oX $discoveryXml $target
            } else {
                & $nmapExe -p- --min-rate 60 @nmapCommon -oX $discoveryXml $target
            }

            if (-not (Test-Path $discoveryXml)) { Write-Warning ("Discovery output missing for {0}" -f $target); continue }

            try {
                $raw = Get-Content $discoveryXml -Raw -ErrorAction Stop
                [xml]$xml = $raw
                $openPortNodes = Select-Xml -Xml $xml -XPath "//port[state/@state='open']"
                $openPorts = @()
                if ($openPortNodes) { $openPorts = $openPortNodes | ForEach-Object { $_.Node.portid } | Sort-Object -Unique }

                if ($openPorts -and $openPorts.Count -gt 0) {
                    $portList = ($openPorts -join ",")
                    Write-Host ("   Open ports on {0}: {1}" -f $target, $portList)
                    Write-Host  "   Running service/version scan on those ports..."
                    $versionArgs = @('-sV','--version-light','--version-intensity','2','--script-timeout','5s')
                    & $nmapExe @versionArgs @nmapCommon -p $portList -oX $serviceXml $target
                    Write-Host ("   Service scan saved: {0}" -f $serviceXml)
                } else {
                    Write-Host ("   No open ports detected on {0} (discovery)." -f $target)
                }
            } catch {
                Write-Warning ("   Failed to parse discovery results for {0}: {1}" -f $target, $_)
            }
        }
    }
} else {
    Write-Warning "nmap not found in PATH. Skipping nmap."
}

# -----------------------------
# 2) Trivy FS 스캔
# -----------------------------
if (Test-CommandExists $trivyExe) {
    Write-Host "[*] Running trivy filesystem scan (vuln only, faster)..."
    $fsTarget = "C:\inetpub\wwwroot"
    $trivyFsOut = Join-Path $outDir "trivy_fs_$($today).json"
    try {
        & $trivyExe fs --scanners vuln --format json -o $trivyFsOut $fsTarget
        Write-Host "Trivy FS report: $trivyFsOut"
    } catch {
        Write-Warning "Trivy FS scan failed: $_"
    }
} else {
    Write-Warning "trivy not found in PATH. Skipping trivy fs scan."
}

# -----------------------------
# 3) Trivy 이미지 스캔
# -----------------------------
if (Test-CommandExists $trivyExe) {
    $images = Get-Content $imagesFile -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" }
    if ($images -and $images.Count -gt 0) {
        Write-Host "[*] Scanning docker images..."
        foreach ($img in $images) {
            $safeName = $img -replace '[:/\\]', '_'
            $imgOut = Join-Path $outDir "trivy_image_${safeName}_$($today).json"
            try {
                & $trivyExe image --format json -o $imgOut $img
                Write-Host "Trivy image report: $imgOut"
            } catch {
                Write-Warning "Trivy image scan failed for $img : $_"
            }
        }
    } else {
        Write-Host "No images listed in $imagesFile. Skipping image scans."
    }
}

# -----------------------------
# 4) ZAP baseline 스캔
# -----------------------------
if (Get-Command "zap-baseline.py" -ErrorAction SilentlyContinue) {
    Write-Host "[*] Running ZAP baseline scans for HTTP targets..."
    $targets = Get-Content $targetsFile | Where-Object { $_.Trim() -ne "" }
    foreach ($t in $targets) {
        $url = if ($t -match '^https?://') { $t } else { "http://$t" }
        $zapOut = Join-Path $outDir ("zap_" + ($t -replace '[:/\\]', '_') + "_$($today).html")
        try {
            & zap-baseline.py -t $url -r $zapOut
            Write-Host "ZAP report: $zapOut"
        } catch {
            Write-Warning "ZAP baseline failed for $url : $_"
        }
    }
} else {
    Write-Host "ZAP baseline not available (zap-baseline.py). Skipping ZAP."
}

# -----------------------------
# 5) Trivy 요약
# -----------------------------
$summaryFile = Join-Path $outDir "critical_summary_$($today).txt"
if (Test-Path $trivyFsOut) {
    try {
        $raw = Get-Content $trivyFsOut -Raw
        $json = $null
        try { $json = $raw | ConvertFrom-Json } catch { $json = $null }

        $findings = @()

        if ($null -ne $json) {
            $candidates = @()
            if ($json -is [System.Collections.IEnumerable]) { $candidates += $json } else { $candidates += ,$json }

            foreach ($node in $candidates) {
                if ($null -eq $node) { continue }

                if ($node.PSObject.Properties.Name -contains 'Results' -and $node.Results) {
                    foreach ($r in $node.Results) {
                        if ($r.Vulnerabilities) { foreach ($v in $r.Vulnerabilities) { $findings += $v } }
                    }
                }
                if ($node.PSObject.Properties.Name -contains 'Vulnerabilities' -and $node.Vulnerabilities) {
                    foreach ($v in $node.Vulnerabilities) { $findings += $v }
                }
                if ($node -is [System.Collections.IDictionary] -and $node.ContainsKey('results')) {
                    foreach ($r in $node.results) {
                        if ($r.vulnerabilities) { foreach ($v in $r.vulnerabilities) { $findings += $v } }
                    }
                }
            }
        }

        $lines = @()
        foreach ($v in $findings) {
            $sev = $v.Severity; if ($null -eq $sev) { $sev = $v.severity }
            if ($sev -in @('CRITICAL','HIGH')) {
                $id  = $v.VulnerabilityID; if (-not $id) { $id = $v.vulnerabilityID }
                $pkg = $v.PkgName;         if (-not $pkg){ $pkg = $v.pkgName }
                $fix = $v.FixVersion;      if (-not $fix){ $fix = $v.fixVersion }
                if ($fix -is [System.Collections.IEnumerable] -and -not ($fix -is [string])) { $fix = ($fix -join ',') }
                $lines += ("{0} | {1} | {2} -> {3}" -f $id, $pkg, $sev, $fix)
            }
        }

        if ($lines.Count -gt 0) {
            $lines | Out-File -FilePath $summaryFile -Encoding utf8
            Write-Host "Critical/High summary saved to $summaryFile"
        } else {
            "No CRITICAL/HIGH found in trivy fs scan." | Out-File $summaryFile
            Write-Host "No CRITICAL/HIGH findings in trivy fs."
        }
    } catch {
        Write-Warning "Failed to parse trivy fs json: $_"
    }
} else {
    Write-Host "No trivy fs report present to summarize."
}

# -----------------------------
# 6) Investigate & YARA
# -----------------------------
if ($Investigate) {
    $invOut = Join-Path $outDir ($env:COMPUTERNAME + "_investigation")
    Collect-InvestigationEvidence -OutBase $invOut
}

# --- Normalize YARA rule encoding (UTF16 -> UTF8/ASCII) ---
if (Test-Path "C:\sec\yara_rules.yar") {
    try {
        $raw = Get-Content "C:\sec\yara_rules.yar" -Raw -ErrorAction Stop
        # ASCII 인코딩으로 강제 변환
        $raw | Set-Content -Path "C:\sec\yara_rules.yar" -Encoding ascii
        Write-Host "YARA rules file encoding normalized to ASCII."
    } catch {
        Write-Warning "Failed to normalize YARA rules encoding: $_"
    }
}

# --- Optional: Compile YARA rule (성능 향상, PowerShell 5 호환) ---
$compiled = "C:\sec\yara_rules.yarc"
try {
    $cmd = Get-Command yarac64.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        $yarac = $cmd.Source
    } else {
        # chocolatey 설치 경로 대체 시도
        if ($env:ChocolateyInstall) {
            $possible = Join-Path $env:ChocolateyInstall 'lib\yara\tools\yarac64.exe'
            if (Test-Path $possible) { $yarac = $possible }
        }
    }

    if ($yarac) {
        & $yarac "C:\sec\yara_rules.yar" $compiled 2>$null
        Write-Host "yarac compiled rules -> $compiled"
    } else {
        Write-Host "yarac not found. Skipping compile."
    }
} catch {
    Write-Host "yarac compile skipped: $_"
}
if (Test-Path $compiled) { $rules = $compiled }

if ($RunYara) {
    $rules = "C:\sec\yara_rules.yar"
    $localTargets = @("C:\Windows\System32")
    $yaraOut = Join-Path $outDir "yara"
    Run-YARAScan -RulesFile $rules -Targets $localTargets -OutDir $yaraOut
}

# -----------------------------
# (NEW) 6.5) Osquery System Audit (경량 모드)
# -----------------------------
$osqExe = Get-OsqueryExe
if ($osqExe) {
    Write-Host "[*] Running osquery lightweight audit ($osqExe)..."
    $osqOutDir = Join-Path $outDir "osquery_$($today)"
    if (-not (Test-Path $osqOutDir)) { New-Item -ItemType Directory -Path $osqOutDir -Force | Out-Null }

    $queries = @{
        "users"        = "SELECT username, uid, description, last_login FROM users;"
        "listening"    = "SELECT pid, name, port, protocol, address FROM listening_ports;"
        "patches"      = "SELECT hotfix_id, installed_on FROM patches WHERE installed_on IS NOT NULL;"
        "startup"      = "SELECT name, path, source FROM startup_items;"
        "drivers"      = "SELECT name, path, type, service_key FROM drivers WHERE type != '';"
        "processes"    = "SELECT pid, name, path, start_time FROM processes WHERE on_disk = 1 LIMIT 50;"
    }

    foreach ($q in $queries.GetEnumerator()) {
        $outFile = Join-Path $osqOutDir ("osq_" + $q.Key + ".json")
        try {
            & $osqExe --json $q.Value | Out-File $outFile -Encoding utf8
            Write-Host "   -> osquery result saved: $($outFile)"
        } catch {
            Write-Warning "   osquery query failed for $($q.Key): $_"
        }
    }

    Write-Host "[+] Osquery lightweight audit complete."
} else {
    Write-Host "osqueryi.exe not found in PATH. (Optional audit skipped)"
}

# -----------------------------
# 7) 압축 결과
# -----------------------------
try {
    $zipPath = Join-Path $outRoot ("sec_reports_$($today).zip")
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($outDir, $zipPath)
    Write-Host "Reports archived: $zipPath"
} catch {
    Write-Warning "Failed to archive results: $_"
}

Write-Host "[+] Scan run complete. Check $outDir for raw reports and $summaryFile for critical summary."