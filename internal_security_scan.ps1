<# 
.SYNOPSIS
  내부/외부 대상 자동 보안 스캔 (Windows PowerShell, Safe 모드/드라이런/메일 첨부 지원)
.DESCRIPTION
  - nmap(포트/서비스), trivy(fs & image), YARA, 조사 모드, osquery 경량 감사 실행
  - JSON 결과(Trivy, osquery)는 그대로 유지 (절대 XML 변환 안 함)
  - nmap은 도구 특성상 XML로 저장되지만 변환하지 않음
  - 안전 모드(Safe) 기본, 드라이런(DryRun) 지원, 메일 첨부 전송(Office365 SMTP)
.NOTES
  관리자 권장
#>

param(
    [switch]$Investigate,
    [switch]$RunYara,
    [switch]$Register9AMDaily,     # ← 스케줄(매일 09:00) 등록용 일회성 스위치
    [string]$RunAsUser,             # ← 작업 스케줄러 실행 계정 (예: 'DOMAIN\User' 또는 '.\LocalUser')

    # --- 실행 정책 ---
    [ValidateSet('Safe','Aggressive')]
    [string]$Mode = 'Safe',
    [switch]$DryRun,
    [int]$MaxHosts = 10,
    [int]$NmapMinRate = 30,
    [int]$ZapTimeoutSec = 600,
    [int]$RetentionDays = 14
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===== Mail (Office365) Config =====
$SendMail      = $true
$MailSmtp      = 'smtp.office365.com'
$MailPort      = 587
$MailUseSsl    = $true
$MailFrom      = 'dy.park@tracxlogis.com'   # From 은 실제 로그인 계정과 동일해야 함
#$MailTo        = 'dy.park@tracxlogis.com; jeonsh@tracxlogis.com; eb.jeon@tracxlogis.com;'
$MailTo        = 'cloudinfra.team@tracxlogis.com;'
$MailCc        = ''     # optional
$MailBcc       = ''     # optional
# TLS 1.2 강제
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------ 공용 헬퍼 ------------
function Invoke-OrDryRun {
    param([string]$FilePath,[string[]]$ArgumentList)
    if ($DryRun) { Write-Host "[DRYRUN] $FilePath $($ArgumentList -join ' ')"; return $null }
    else { return & $FilePath @ArgumentList }
}
function Safe-WriteUtf8NoBom { param([string]$Path,[string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}
function Start-Proc-Capture {
    param(
        [Parameter(Mandatory)] [string]$Exe,
        [Parameter(Mandatory)] [string[]]$Args,
        [Parameter(Mandatory)] [string]$StdOutPath,
        [Parameter(Mandatory)] [string]$StdErrPath
    )
    if ($DryRun) { Write-Host "[DRYRUN] $Exe $($Args -join ' ')"; return 0 }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($Args -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $out | Set-Content -Encoding utf8 -Path $StdOutPath
    $err | Set-Content -Encoding utf8 -Path $StdErrPath
    return $p.ExitCode
}
function Register-ScanTask9AM {
    param(
        [string]$RunAsUser  # 비워두면 현재 토큰의 DOMAIN\Name로 자동 설정
    )

    # 1) 실행 인자 구성 (등록 이후 매일 실행 때는 -Register9AMDaily 제외)
    $baseArgs = @(
        '-NoProfile','-ExecutionPolicy','Bypass',
        '-File', ('"{0}"' -f $PSCommandPath),
        '-Mode', $Mode,
        '-MaxHosts', $MaxHosts,
        '-NmapMinRate', $NmapMinRate,
        '-ZapTimeoutSec', $ZapTimeoutSec,
        '-RetentionDays', $RetentionDays
    )
    if ($Investigate) { $baseArgs += '-Investigate' }
    if ($RunYara)     { $baseArgs += '-RunYara'   }
    $argLine = $baseArgs -join ' '

    $action   = New-ScheduledTaskAction  -Execute 'powershell.exe' -Argument $argLine
    $trigger  = New-ScheduledTaskTrigger -Daily -At 9:00
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
                  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                  -WakeToRun -MultipleInstances IgnoreNew

    # 2) 계정명 자동 해결 (DOMAIN\Name 형식)
    if ([string]::IsNullOrWhiteSpace($RunAsUser)) {
        $RunAsUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        # 예: 'AzureAD\dy.park_tracxlogis.com#EXT#' 또는 'TRACX\dy.park'
    }

    $taskName = 'Security Scan Report 9AM'
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
    }

    # 3) 1차 시도: 입력(또는 자동해결) 계정 그대로
    try {
        $principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Password -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
        Write-Host "[+] 작업 스케줄러 등록 완료(1차): $taskName / $RunAsUser"
        return
    } catch {
        if ($_.Exception.HResult -ne -2147023564) {  # 0x80070534
            throw
        }
        Write-Warning "계정 매핑 실패(0x80070534): '$RunAsUser' → 대안 포맷 시도"
    }

    # 4) 2차 시도: AzureAD 환경에서 자주 통하는 포맷 자동 변환
    $candidates = @()
    if ($RunAsUser -match '@') {
        # 'AzureAD\upn' 포맷
        $candidates += ('AzureAD\' + $RunAsUser)
        # 'AzureAD\sam' 포맷(UPN 앞부분)
        $candidates += ('AzureAD\' + ($RunAsUser.Split('@')[0]))
    } elseif ($RunAsUser -notmatch '\\' -and $env:USERDOMAIN -match 'AzureAD') {
        # 'AzureAD\username' 추정
        $candidates += ('AzureAD\' + $RunAsUser)
    }

    foreach ($cand in $candidates | Select-Object -Unique) {
        try {
            $principal = New-ScheduledTaskPrincipal -UserId $cand -LogonType Password -RunLevel Highest
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
            Write-Host "[+] 작업 스케줄러 등록 완료(대안): $taskName / $cand"
            return
        } catch {
            if ($_.Exception.HResult -eq -2147023564) {
                Write-Warning "매핑 실패 계속됨: '$cand'"
            } else { throw }
        }
    }
 # --- Fallback: schtasks.exe로 생성(암호 프롬프트) ---
    Write-Warning "Register-ScheduledTask 인증 실패 → schtasks.exe로 대체 생성합니다."

    # 작업 이름/실행 커맨드 재사용
    $taskName = 'Security Scan Report 9AM'
    # $argLine 은 함수 상단에 이미 구성된 실행 인자 문자열입니다.
    $trLine   = "powershell.exe $argLine"

    # 기존 동일 이름 작업 제거 (있으면)
    schtasks /Delete /TN "$taskName" /F 2>$null | Out-Null

    # /RP * 로 암호 프롬프트 띄움, /RL HIGHEST = 관리자 권한으로 실행
    $proc = Start-Process -FilePath schtasks.exe -ArgumentList @(
      '/Create','/TN',"$taskName",
      '/SC','DAILY','/ST','09:00',
      '/TR',"$trLine",
      '/RU',"$RunAsUser",
      '/RP','*',
      '/RL','HIGHEST',
      '/F'
    ) -Wait -PassThru

    if ($proc.ExitCode -ne 0) {
      throw "schtasks.exe 생성 실패 (ExitCode=$($proc.ExitCode)). 계정/암호를 확인하세요: $RunAsUser"
    } else {
      Write-Host "[+] 작업 스케줄러 등록 완료(schtasks): $taskName / $RunAsUser"
    }
    return

    throw "계정 매핑 실패로 작업 등록 불가. whoami 결과와 동일한 '도메인\이름'을 -RunAsUser로 명시하세요."
}

# ------------ 경로/환경 ------------
$today = (Get-Date).ToString("yyyy-MM-dd")
$outRoot = "C:\sec_reports"
$outDir = Join-Path $outRoot $today
$targetsFile = "C:\sec\scan_targets"
$imagesFile = "C:\sec\scan_images.txt"
$nmapExe  = "nmap.exe"
$trivyExe = "trivy.exe"

if (!(Test-Path $outDir)) { if(-not $DryRun){ New-Item -ItemType Directory -Path $outDir -Force | Out-Null } }

if (!(Test-Path $targetsFile)) {
    Write-Host "Targets file not found. Creating sample at $targetsFile"
    if(-not $DryRun){ New-Item -ItemType File -Path $targetsFile -Force -Value "127.0.0.1" | Out-Null }
}
if (!(Test-Path $imagesFile)) {
    if(-not $DryRun){ New-Item -ItemType File -Path $imagesFile -Force -Value "" | Out-Null }
}

# ------------ 실행 가능 여부 검사 ------------
function Test-CommandExists { param([string]$exe) return (Get-Command $exe -ErrorAction SilentlyContinue) -ne $null }

# ------------ YARA/Osquery 경로 탐지 ------------
function Get-YaraExe {
    if (Get-Command yara.exe  -ErrorAction SilentlyContinue) { return "yara.exe" }
    if (Get-Command yara64.exe -ErrorAction SilentlyContinue) { return "yara64.exe" }
    $c = @(
        "C:\Program Files\yara\yara64.exe","C:\Program Files\yara\yara.exe",
        "C:\Program Files (x86)\yara\yara64.exe","C:\Program Files (x86)\yara\yara.exe",
        "C:\ProgramData\chocolatey\bin\yara64.exe","C:\ProgramData\chocolatey\bin\yara.exe",
        "C:\ProgramData\chocolatey\lib\yara\tools\yara64.exe","C:\ProgramData\chocolatey\lib\yara\tools\yara.exe"
    )
    foreach ($p in $c){ if (Test-Path $p){ return $p } }
    return $null
}
function Get-OsqueryExe {
    if (Get-Command osqueryi.exe -ErrorAction SilentlyContinue) { return "osqueryi.exe" }
    $c = @("C:\Program Files\osquery\osqueryi.exe","C:\ProgramData\chocolatey\lib\osquery\tools\osqueryi.exe")
    foreach ($p in $c){ if (Test-Path $p){ return $p } }
    return $null
}

# ------------ 조사(증거수집) ------------
function Collect-InvestigationEvidence { param([string]$OutBase)
    Write-Host "== Investigation: collecting evidence to $OutBase =="
    if(-not $DryRun){ if (!(Test-Path $OutBase)) { New-Item -ItemType Directory -Path $OutBase -Force | Out-Null } }
    $lp = Join-Path $OutBase "listening_ports.txt"
    $ps = Join-Path $OutBase "processes.txt"
    $sv = Join-Path $OutBase "services.txt"
    $st = Join-Path $OutBase "scheduled_tasks.txt"
    $es = Join-Path $OutBase "evt_system.xml"
    $ea = Join-Path $OutBase "evt_app.xml"
    if ($DryRun) {
        Write-Host "[DRYRUN] collect -> $lp,$ps,$sv,$st,$es,$ea"
    } else {
        Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess,State | Sort LocalPort | Out-File $lp -Encoding utf8
        Get-Process | Select Id,ProcessName,Path,StartTime | Out-File $ps -Encoding utf8
        Get-CimInstance Win32_Service | Select Name,DisplayName,State,StartMode,ProcessId | Out-File $sv -Encoding utf8
        schtasks /query /fo LIST /v | Out-File $st -Encoding utf8
        Get-WinEvent -LogName System -MaxEvents 200 | Export-Clixml $es
        Get-WinEvent -LogName Application -MaxEvents 200 | Export-Clixml $ea
    }
    Write-Host "Investigation evidence collected."
}

# ------------ YARA 실행 ------------
function Run-YARAScan { param([string]$RulesFile,[string[]]$Targets,[string]$OutDir)
    $yaraExe = Get-YaraExe
    if (-not $yaraExe) { Write-Warning "YARA not found. Skipping."; return }
    if (-not (Test-Path $RulesFile)) { Write-Warning "Rules file not found: $RulesFile"; return }
    if(-not $DryRun){ if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null } }
    Write-Host "YARA engine: $yaraExe"
    foreach ($t in $Targets) {
        if (-not (Test-Path $t)) { Write-Host "YARA target not local path, skip: $t"; continue }
        $safe = ($t -replace '[:/\\]', '_')
        $outTxt = Join-Path $OutDir ("yara_" + $safe + ".txt")
        $errTxt = Join-Path $OutDir ("yara_" + $safe + ".err.txt")
        $args = @("-r",$RulesFile,$t)
        if ($DryRun) {
            Write-Host "[DRYRUN] $yaraExe $($args -join ' ') -> $outTxt"
        } else {
            try {
                $proc = Start-Process -FilePath $yaraExe -ArgumentList $args -NoNewWindow -Wait -PassThru `
                    -RedirectStandardOutput $outTxt -RedirectStandardError $errTxt
                if ($proc.ExitCode -ne 0) {
                    Write-Warning ("YARA exit {0} for {1}. See {2}" -f $proc.ExitCode,$t,$errTxt)
                } else { Write-Host "YARA done: $t" }
            } catch { Write-Warning "YARA failed for $t : $_" }
        }
    }
}

# ------------ 1) nmap ------------
if (Test-CommandExists $nmapExe) {
    Write-Host "[*] Running nmap..."
    $nmapOutDir = Join-Path $outDir "nmap_$($today)"
    if (-not $DryRun) {
        if (-not (Test-Path $nmapOutDir)) { New-Item -Path $nmapOutDir -ItemType Directory | Out-Null }
    }

    $nmapCommon = if ($Mode -eq 'Safe') { @('-T3','-n','--max-retries','1','--host-timeout','2m') } else { @('-T4','-n','-Pn','--max-retries','1','--host-timeout','3m') }

    # 대상 로드
    $rawTargets = @()
    try {
        $rawTargets = Get-Content $targetsFile -ErrorAction Stop |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne "" -and -not ($_ -like "#*") }
    } catch {
        Write-Warning "Failed to read targets: $targetsFile ($_)"
        $rawTargets = @()
    }

    # URL → 호스트 변환
    $hosts = @()
    foreach ($t in $rawTargets) {
        if ($t -match '^https?://') {
            try { $u = [uri] $t; if ($u.Host) { $hosts += $u.Host } } catch { Write-Warning "Invalid URL: $t" }
        } else { $hosts += $t }
    }

    # 중복 제거 + 배열 강제화 + 개수 제한
    $hosts = $hosts | Sort-Object -Unique
    $hosts = @($hosts)
    if ($MaxHosts -gt 0) { $hosts = @($hosts | Select-Object -First $MaxHosts) }

    # 방어적 체크
    $hostCount = @($hosts).Count
    if ($hostCount -eq 0) {
        Write-Host "No valid hosts. Check $targetsFile"
    } else {
        Write-Host "Targets parsed ($hostCount): $(@($hosts) -join ', ')"

        foreach ($target in @($hosts)) {
            if ($target -match '(^|\.)example\.com$') { Write-Host "-> Skip sample domain: $target"; continue }

            $isPrivateIPv4 = ($target -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')
            $isIPv4        = ($target -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')

            # Safe: 항상 top-ports / Aggressive: 내부 IPv4는 full-ports 허용 가능
            $useTopPorts = if ($Mode -eq 'Safe') { $true } else { -not $isPrivateIPv4 -and (-not $isIPv4) -or $false }

            $targetSafe   = ($target -replace '[:/\\]', '_')
            $discoveryXml = Join-Path $nmapOutDir "discovery_${targetSafe}_$($today).xml"
            $serviceXml   = Join-Path $nmapOutDir "services_${targetSafe}_$($today).xml"
            $profile = if ($useTopPorts) { 'top-ports' } else { 'full-ports' }
            Write-Host ("-> Discovery scan for {0} ({1})..." -f $target, $profile)

            #if ($useTopPorts) {
                #Invoke-OrDryRun -FilePath $nmapExe -ArgumentList @('--top-ports','1000','--min-rate',"$NmapMinRate") + $nmapCommon + @('-oX',$discoveryXml,$target)
            #} else {
                #Invoke-OrDryRun -FilePath $nmapExe -ArgumentList @('-p-','--min-rate',"$NmapMinRate") + $nmapCommon + @('-oX',$discoveryXml,$target)
            #}
	    

# stdout/stderr 로그 경로
$discoStdOut = Join-Path $nmapOutDir ("stdout_discovery_${targetSafe}_$today.log")
$discoStdErr = Join-Path $nmapOutDir ("stderr_discovery_${targetSafe}_$today.log")

# 인자 구성
if ($useTopPorts) {
    $argsDisco = @('--top-ports','1000','--min-rate',"$NmapMinRate") + $nmapCommon + @('-oX',$discoveryXml,$target)
} else {
    $argsDisco = @('-p-','--min-rate',"$NmapMinRate") + $nmapCommon + @('-oX',$discoveryXml,$target)
}

# 실행 + 캡처
$ec1 = Start-Proc-Capture -Exe $nmapExe -Args $argsDisco -StdOutPath $discoStdOut -StdErrPath $discoStdErr
if ($ec1 -ne 0) { Write-Warning "nmap discovery exit code $ec1 for $target (see $discoStdErr)" }
	   	


            if ($DryRun -or -not (Test-Path $discoveryXml)) { continue }

            try {
                [xml]$xml = Get-Content $discoveryXml -Raw
                $openPortNodes = Select-Xml -Xml $xml -XPath "//port[state/@state='open']"
                $openPorts = @()
                if ($openPortNodes) { $openPorts = $openPortNodes | ForEach-Object { $_.Node.portid } | Sort-Object -Unique }

                if (@($openPorts).Count -gt 0) {
                    $portList = ($openPorts -join ",")
                    Write-Host ("   Open ports on {0}: {1}" -f $target, $portList)
                    Write-Host  "   Running service/version scan..."
                    Invoke-OrDryRun -FilePath $nmapExe -ArgumentList @('-sV','--version-light','--version-intensity','2','--script-timeout','5s') + $nmapCommon + @('-p',$portList,'-oX',$serviceXml,$target)
                } else {
                    Write-Host ("   No open ports on {0} (discovery)." -f $target)
                }
            } catch {
                Write-Warning ("   Failed to parse discovery results for {0}: {1}" -f $target, $_)
            }
        }
    }
} else {
    Write-Warning "nmap not found in PATH. Skipping nmap."
}

# ------------ 2) Trivy FS ------------
if (Test-CommandExists $trivyExe) {
    Write-Host "[*] Running trivy filesystem scan (JSON 유지)..."
    $fsTarget = "C:\inetpub\wwwroot"
    $trivyFsOut = Join-Path $outDir "trivy_fs_$($today).json"
    $trivyArgs  = @('fs','--scanners','vuln','--format','json','-o',$trivyFsOut,$fsTarget,'--timeout','5m','--ignore-unfixed')
    if ($DryRun) { Write-Host "[DRYRUN] trivy $($trivyArgs -join ' ')" } else {
        try { & $trivyExe @trivyArgs; Write-Host "Trivy FS report: $trivyFsOut" } catch { Write-Warning "Trivy FS failed: $_" }
    }
} else { Write-Warning "trivy not found in PATH. Skipping trivy fs scan." }

# ------------ 3) Trivy 이미지 ------------
if (Test-CommandExists $trivyExe) {
    $images = Get-Content $imagesFile -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" }
    if ($images) {
        Write-Host "[*] Scanning docker images..."
        foreach ($img in $images) {
            $safeName = $img -replace '[:/\\]', '_'
            $imgOut = Join-Path $outDir "trivy_image_${safeName}_$($today).json"
            $args = @('image','--format','json','-o',$imgOut,$img)
            if ($DryRun) { Write-Host "[DRYRUN] trivy $($args -join ' ')" } else {
                try { & $trivyExe @args; Write-Host "Trivy image report: $imgOut" } catch { Write-Warning "Trivy image failed ($img): $_" }
            }
        }
    } else { Write-Host "No images listed in $imagesFile. Skipping image scans." }
}

# ------------ 4) ZAP baseline ------------
if (Get-Command "zap-baseline.py" -ErrorAction SilentlyContinue) {
    Write-Host "[*] Running ZAP baseline (안전/패시브 중심)..."
    $targets = Get-Content $targetsFile -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" }
    foreach ($t in $targets) {
        $url = if ($t -match '^https?://') { $t } else { "http://$t" }
        $zapOut = Join-Path $outDir ("zap_" + ($t -replace '[:/\\]', '_') + "_$($today).html")
        $zapArgs = @('-t',$url,'-r',$zapOut,'-m','5','-z',("timeout={0}" -f $ZapTimeoutSec))
        if ($DryRun) { Write-Host "[DRYRUN] zap-baseline.py $($zapArgs -join ' ')" } else {
            try { & zap-baseline.py @zapArgs; Write-Host "ZAP report: $zapOut" } catch { Write-Warning "ZAP failed ($url): $_" }
        }
    }
} else { Write-Host "ZAP baseline not available (zap-baseline.py). Skipping ZAP." }

# ------------ 5) Trivy 요약 텍스트(그대로 유지, JSON 변환 금지) ------------
$summaryFile = Join-Path $outDir "critical_summary_$($today).txt"
if ((Test-Path $trivyFsOut) -and (-not $DryRun)) {
    try {
        $raw = Get-Content $trivyFsOut -Raw
        $json = $null; try { $json = $raw | ConvertFrom-Json } catch {}
        $findings = @()
        if ($null -ne $json) {
            $candidates = @(); if ($json -is [System.Collections.IEnumerable]) { $candidates += $json } else { $candidates += ,$json }
            foreach ($node in $candidates) {
                if ($node -and $node.PSObject.Properties.Name -contains 'Results' -and $node.Results) {
                    foreach ($r in $node.Results) { if ($r.Vulnerabilities) { $findings += $r.Vulnerabilities } }
                }
                if ($node -and $node.PSObject.Properties.Name -contains 'Vulnerabilities' -and $node.Vulnerabilities) { $findings += $node.Vulnerabilities }
                if ($node -is [System.Collections.IDictionary] -and $node.ContainsKey('results')) {
                    foreach ($r in $node.results) { if ($r.vulnerabilities) { $findings += $r.vulnerabilities } }
                }
            }
        }
        $lines = @()
        foreach ($v in $findings) {
            $sev = $v.Severity; if (-not $sev) { $sev = $v.severity }
            if ($sev -in @('CRITICAL','HIGH')) {
                $id  = $v.VulnerabilityID; if (-not $id) { $id = $v.vulnerabilityID }
                $pkg = $v.PkgName;         if (-not $pkg){ $pkg = $v.pkgName }
                $fix = $v.FixVersion;      if (-not $fix){ $fix = $v.fixVersion }
                if ($fix -and ($fix -isnot [string])) { $fix = ($fix -join ',') }
                $lines += ("{0} | {1} | {2} -> {3}" -f $id, $pkg, $sev, $fix)
            }
        }
        if ($lines.Count -gt 0) { $lines | Out-File -FilePath $summaryFile -Encoding utf8; Write-Host "Critical/High summary saved: $summaryFile" }
        else { "No CRITICAL/HIGH found in trivy fs scan." | Out-File $summaryFile; Write-Host "No CRITICAL/HIGH findings in trivy fs." }
    } catch { Write-Warning "Failed to parse trivy fs json: $_" }
} elseif (-not $DryRun) { Write-Host "No trivy fs report present to summarize." }

# ------------ 6) Investigate & YARA ------------
if ($Investigate) {
    $invOut = Join-Path $outDir ($env:COMPUTERNAME + "_investigation")
    Collect-InvestigationEvidence -OutBase $invOut
}

# YARA 룰 인코딩: UTF-8(No BOM) 정규화
if (Test-Path "C:\sec\yara_rules.yar") {
    try { $raw = Get-Content "C:\sec\yara_rules.yar" -Raw -ErrorAction Stop; if(-not $DryRun){ Safe-WriteUtf8NoBom -Path "C:\sec\yara_rules.yar" -Content $raw }; Write-Host "YARA rules normalized to UTF-8 (no BOM)." }
    catch { Write-Warning "Failed to normalize YARA rules: $_" }
}

# yarac(선택)
$compiled = "C:\sec\yara_rules.yarc"
try {
    $cmd = Get-Command yarac64.exe -ErrorAction SilentlyContinue
    if (-not $cmd -and $env:ChocolateyInstall) {
        $possible = Join-Path $env:ChocolateyInstall 'lib\yara\tools\yarac64.exe'
        if (Test-Path $possible) { $cmd = Get-Item $possible }
    }
    if ($cmd) {
        if ($DryRun) { Write-Host "[DRYRUN] $($cmd.Source) C:\sec\yara_rules.yar $compiled" }
        else { & $cmd.Source "C:\sec\yara_rules.yar" $compiled 2>$null; Write-Host "yarac compiled -> $compiled" }
    } else { Write-Host "yarac not found. Skipping compile." }
} catch { Write-Host "yarac compile skipped: $_" }
if (Test-Path $compiled) { $rules = $compiled }

if ($RunYara) {
    #$rules = if (Test-Path $compiled) { $compiled } else { "C:\sec\yara_rules.yar" }
    #$localTargets = @("C:\Windows\System32")
    #$yaraOut = Join-Path $outDir "yara"
    #Run-YARAScan -RulesFile $rules -Targets $localTargets -OutDir $yaraOut
    # 무조건 소스 룰(yar)만 사용
    $rules = "C:\sec\yara_rules.yar"
    $localTargets = @("C:\Windows\System32")
    $yaraOut = Join-Path $outDir "yara"
    Run-YARAScan -RulesFile $rules -Targets $localTargets -OutDir $yaraOut
}

# ------------ (NEW) 6.5) Osquery 경량 감사 ------------
$osqExe = Get-OsqueryExe
if ($osqExe) {
    Write-Host "[*] Running osquery lightweight audit ($osqExe)..."
    $osqOutDir = Join-Path $outDir "osquery_$($today)"
    if (-not $DryRun) {
        if (-not (Test-Path $osqOutDir)) {
            New-Item -ItemType Directory -Path $osqOutDir -Force | Out-Null
        }
    }

    $queries = @{
"users" = @"
SELECT username, uid, description
FROM users;
"@

"listening" = @"
SELECT lp.pid,
       p.name,
       lp.port,
       lp.protocol,
       lp.address,
       lp.family
FROM listening_ports AS lp
LEFT JOIN processes AS p
  ON lp.pid = p.pid;
"@

"patches" = @"
SELECT hotfix_id, installed_on
FROM patches
WHERE installed_on IS NOT NULL;
"@

"startup" = @"
SELECT name, path, source
FROM startup_items;
"@

# 안정 컬럼만 사용
"drivers" = @"
SELECT image AS path,
       type,
       service_key
FROM drivers
WHERE type != '';
"@

"processes" = @"
SELECT pid, name, path, start_time
FROM processes
WHERE on_disk = 1
LIMIT 50;
"@
    }

    foreach ($q in $queries.GetEnumerator()) {
        $outFile = Join-Path $osqOutDir ("osq_" + $q.Key + ".json")
        try {
            & $osqExe --json $q.Value | Out-File $outFile -Encoding utf8
            Write-Host "   -> $outFile"
        } catch {
            Write-Warning "   osquery query failed for $($q.Key): $_"
        }
    }

    Write-Host "[+] Osquery lightweight audit complete."
} else {
    Write-Host "osqueryi.exe not found in PATH. (Optional audit skipped)"
}

# ------------ 7) 압축/정리(+보존기간) ------------
# (교체) 타임스탬프 파일명 + 재시도(백오프) + 임시→최종 이동
$stamp  = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
$tmpZip = Join-Path $outRoot ("sec_reports_${stamp}.zip.tmp")
$zipPath = Join-Path $outRoot ("sec_reports_${stamp}.zip")

function Invoke-WithRetry {
    param([scriptblock]$Action,[int]$Max=5,[int]$DelayMs=800)
    for($i=1; $i -le $Max; $i++){
        try { & $Action; return $true } catch {
            if ($i -eq $Max) { throw }
            Start-Sleep -Milliseconds ($DelayMs * $i)  # 점진 백오프
        }
    }
}

try {
    if ($DryRun) {
        Write-Host "[DRYRUN] Zip $outDir -> $zipPath"
    } else {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        Invoke-WithRetry { [System.IO.Compression.ZipFile]::CreateFromDirectory($outDir, $tmpZip) } | Out-Null
        Invoke-WithRetry { Move-Item -LiteralPath $tmpZip -Destination $zipPath -Force } | Out-Null
        Write-Host "Reports archived: $zipPath"
    }
} catch {
    Write-Warning "Failed to archive results: $_"
}

# ========== 8) 메일 전송 (Office365 SmtpClient) ==========
# 본문/제목
$MailSubject = "[보안 자동화 보고서] $today"
$MailBodyHtml = @"
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body>
  <p>보안 점검이 완료되었습니다.</p>
  <p>첨부된 보고서를 확인해 주세요.</p>
  <hr>
  <p>보고서 경로: $outDir</p>
  <p>점검 일자: $today</p>
  <p style='color:gray;font-size:12px;'>※ 본 메일은 자동 발송되었습니다.</p>
</body>
</html>
"@

# (권장) 자격증명 파일 ? 최초 1회:
#   $cred = Get-Credential dy.park@tracxlogis.com
#   $cred | Export-Clixml C:\sec\mail_cred.xml
$MailCredentialFile = 'C:\sec\mail_cred.xml'
$MailCredential = $null
if (Test-Path $MailCredentialFile) {
  try { $MailCredential = Import-Clixml -Path $MailCredentialFile } catch { $MailCredential = $null }
}
if (-not $MailCredential) {
  Write-Warning "SMTP credential not loaded. Prompting for credential..."
  $MailCredential = Get-Credential -Message "Enter Office365 SMTP credential (UPN must match From)"
}

function Send-ReportMail {
  param([Parameter(Mandatory)][string]$FilePath)

  if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
    Write-Warning "Attachment not found: $FilePath"
    return
  }

  $smtp = New-Object System.Net.Mail.SmtpClient($MailSmtp, $MailPort)
  $smtp.EnableSsl = [bool]$MailUseSsl
  $smtp.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
  $smtp.UseDefaultCredentials = $false

  if ($MailCredential) {
    $netCred = New-Object System.Net.NetworkCredential(
      $MailCredential.UserName,
      $MailCredential.GetNetworkCredential().Password
    )
    $smtp.Credentials = $netCred
  } else {
    Write-Warning "No SMTP credential. Mail may fail."
  }

  $msg = New-Object System.Net.Mail.MailMessage
  $msg.From = New-Object System.Net.Mail.MailAddress($MailFrom.Trim())

  foreach ($addr in ($MailTo -split '[;,]')) { $a = $addr.Trim(); if ($a) { [void]$msg.To.Add($a) } }
  foreach ($addr in ($MailCc -split '[;,]')) { $a = $addr.Trim(); if ($a) { [void]$msg.CC.Add($a) } }
  foreach ($addr in ($MailBcc -split '[;,]')) { $a = $addr.Trim(); if ($a) { [void]$msg.Bcc.Add($a) } }

  $msg.Subject         = $MailSubject
  $msg.SubjectEncoding = [System.Text.Encoding]::UTF8
  $msg.Body            = $MailBodyHtml
  $msg.IsBodyHtml      = $true
  $msg.BodyEncoding    = [System.Text.Encoding]::UTF8

  $att = New-Object System.Net.Mail.Attachment($FilePath)
  $att.NameEncoding = [System.Text.Encoding]::UTF8
  [void]$msg.Attachments.Add($att)

  try {
    Write-Host "[*] Sending mail via $($MailSmtp):$($MailPort) (SSL=$MailUseSsl) ..."
    $smtp.Send($msg)
    Write-Host "[+] Mail sent successfully with attachment: $FilePath"
  }
  catch {
    Write-Error "[-] Failed to send mail: $($_.Exception.Message)"
    "$((Get-Date).ToString('s')) - MailError - $($_.Exception.Message)" |
      Out-File -FilePath (Join-Path $outDir 'mail_error.log') -Append -Encoding utf8
  }
  finally {
    $att.Dispose(); $msg.Dispose(); $smtp.Dispose()
  }
}

# 첨부 선택: zip 우선, 없으면 summary
$attachment = $null
if (Test-Path $zipPath) { $attachment = $zipPath }
elseif (Test-Path $summaryFile) { $attachment = $summaryFile }

if ($SendMail -and $attachment) {
  Start-Sleep -Seconds 3
  Send-ReportMail -FilePath $attachment
} elseif ($SendMail) {
  Write-Warning "No attachment found to send."
}

# --- 스케줄 등록(옵션) ---
if ($Register9AMDaily) {
    if (-not $RunAsUser) {
        Write-Error "스케줄 실행 계정(-RunAsUser)이 필요합니다. 예) -RunAsUser 'DOMAIN\User' 또는 '.\LocalUser'"
    } else {
        Register-ScanTask9AM -RunAsUser $RunAsUser
        Write-Host "[Tip] 처음 한 번만 -Register9AMDaily 옵션으로 실행하세요. 그 후에는 스케줄러가 매일 09:00에 자동 실행합니다."
    }
}

Write-Host "[+] Scan run complete. Check $outDir for raw reports and $summaryFile for critical summary."