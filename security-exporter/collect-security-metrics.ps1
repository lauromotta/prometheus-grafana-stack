# ==============================================================
# collect-security-metrics.ps1  -  Canario de seguranca de rede
#
# O QUE FAZ: coleta sinais de seguranca da maquina e escreve
# metricas Prometheus (formato textfile) em:
#   D:\monitoring\security-exporter\textfile\security-metrics.prom
# que sao expostas por uma instancia dedicada do windows_exporter
# na porta 9183 (job "security_exporter" no Prometheus).
#
# COMO RODA: Agendador de Tarefas ("CanarioSegurancaPrometheus")
# dispara a cada 60s via invisible-runner.vbs (sem janela piscando).
# Nao exige administrador. E auto-suficiente: se a instancia do
# exporter cair, ela mesmo sobe de novo.
#
# FALSOS POSITIVOS: um processo novo legitimo (jogo/app novo) gera
# alerta "ProcessoDesconhecidoConectado". Para silenciar, add o nome
# do processo (sem .exe, minusculo ou nao) em $KnownProcesses abaixo.
# ==============================================================

# ---------------- Config ----------------
$TextFileDir  = 'D:\monitoring\security-exporter\textfile'
$OutFile      = Join-Path $TextFileDir 'security-metrics.prom'
$LogFile      = 'D:\monitoring\security-exporter\coleta.log'
# Caminho portatil: resolve %LOCALAPPDATA% em runtime (funciona em qualquer usuario)
$ExporterExe  = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages\Prometheus.WindowsExporter_Microsoft.Winget.Source_8wekyb3d8bbwe\windows_exporter.exe'
$ExporterPort = 9183

# Whitelist de processos autorizados a ter conexoes TCP com a internet.
# Vem de whitelist.ps1 (arquivo PESSOAL, nao versionado; modelo em
# whitelist.example.ps1). Fallback minimo caso o arquivo nao exista.
$KnownProcesses = @(
    'svchost','system','lsass','services','wininit','winlogon','explorer','dwm',
    'msmpeng','searchindexer','searchhost','spoolsv','securityhealthservice'
)
$whitelistFile = Join-Path $PSScriptRoot 'whitelist.ps1'
if (Test-Path $whitelistFile) { . $whitelistFile }

$KnownProcesses = $KnownProcesses | ForEach-Object { $_.Trim().ToLower() }

# ---------------- Funcoes ----------------
function Esc([string]$v) {
    # Escapa valor de label no formato textfile do Prometheus
    ($v -replace '\\','\\' -replace '"','\"' -replace "`r",' ' -replace "`n",' ')
}

function AddLine([System.Collections.Generic.List[string]]$L, [string]$s) { $L.Add($s) }

# Log simples (mantem ultimas 400 linhas)
function WriteLog([string]$msg) {
    try {
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line = "$stamp  $msg"
        Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
        if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 64KB)) {
            $keep = Get-Content $LogFile -Tail 200
            Set-Content -Path $LogFile -Value $keep -ErrorAction SilentlyContinue
        }
    } catch { }
}

# ---------------- Instancia dedicada do exporter (porta 9183) ----------------
# Auto-healing: se nao responde, sobe uma nova silenciosamente.
$exporterOk = $false
try {
    $null = Invoke-WebRequest "http://127.0.0.1:$ExporterPort/metrics" -TimeoutSec 3 -UseBasicParsing
    $exporterOk = $true
} catch {
    if (Test-Path $ExporterExe) {
        try {
            Start-Process -FilePath $ExporterExe -WindowStyle Hidden -ArgumentList @(
                "--web.listen-address=:$ExporterPort",
                "--collectors.enabled=textfile",
                "--collector.textfile.directories=$TextFileDir"
            )
            WriteLog "Instance do exporter (:$ExporterPort) iniciada por auto-healing."
        } catch { WriteLog "ERRO ao subir exporter: $($_.Exception.Message)" }
    } else {
        WriteLog "ERRO: exporter nao encontrado em $ExporterExe"
    }
}

# ---------------- Coleta ----------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$success = 1
$seclogReadable = 1
$L = New-Object System.Collections.Generic.List[string]

# ---- 1) Conexoes TCP estabelecidas com IPs externos (internet) ----
$privateRe = '^(127\.|::1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|fe80|fc|fd)'
$nExternal = 0; $nUnknown = 0
try {
    $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object {
        $ip = ($_.RemoteAddress -replace '^::ffff:','')
        ($ip -notmatch $privateRe) -and ($ip -ne '') -and ($ip -ne '*')
    })
    $nExternal = $conns.Count
    $byProc = $conns | Group-Object OwningProcess
    $unknownNames = @()
    AddLine $L '# HELP windows_security_external_connections Conexoes TCP estabelecidas com IPs da internet, por processo.'
    AddLine $L '# TYPE windows_security_external_connections gauge'
    foreach ($g in $byProc) {
        $pname = (Get-Process -Id $g.Name -ErrorAction SilentlyContinue).ProcessName
        if (-not $pname) { $pname = "pid_" + $g.Name }
        $known = $KnownProcesses -contains $pname.ToLower()
        $k = 'true'; if (-not $known) { $k = 'false'; $nUnknown += $g.Count; $unknownNames += $pname }
        AddLine $L ('windows_security_external_connections{process="' + (Esc $pname) + '",known="' + $k + '"} ' + $g.Count)
    }
    AddLine $L '# HELP windows_security_external_connections_all Total de conexoes TCP com a internet.'
    AddLine $L '# TYPE windows_security_external_connections_all gauge'
    AddLine $L ('windows_security_external_connections_all ' + $nExternal)
    AddLine $L '# HELP windows_security_external_connections_unknown_total Conexoes com a internet de processos FORA da whitelist.'
    AddLine $L '# TYPE windows_security_external_connections_unknown_total gauge'
    AddLine $L ('windows_security_external_connections_unknown_total ' + $nUnknown)
    if ($unknownNames.Count -gt 0) {
        AddLine $L '# HELP windows_security_unknown_process_info Ultimos processos fora da whitelist com conexoes ativas (label so p/ exibicao).'
        AddLine $L '# TYPE windows_security_unknown_process_info gauge'
        foreach ($u in ($unknownNames | Select-Object -Unique)) {
            AddLine $L ('windows_security_unknown_process_info{process="' + (Esc $u) + '"} 1')
        }
    }
} catch {
    $success = 0
    WriteLog "ERRO coletando conexoes: $($_.Exception.Message)"
}

# ---- 2) Log de eventos de seguranca (4625 falhas / 4624 logons) ----
$since = (Get-Date).AddMinutes(-5)
$nFailAll = 0; $nFailNet = 0; $nRdp = 0; $nNetLogon = 0
$failByIp = @{}

try {
    $fails = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} -ErrorAction Stop)
} catch {
    $fails = @()
    if ($_.Exception.Message -notmatch 'encontrado|No events|not found') { $seclogReadable = 0 }
}
$nFailAll = $fails.Count
foreach ($f in $fails) {
    $lt = 0
    try { $lt = [int]$f.Properties[10].Value } catch { }
    $ip = ''
    try { $ip = [string]$f.Properties[19].Value } catch { }
    if ($ip -and $ip -ne '-' -and $ip -ne '::1' -and $ip -notmatch '^127\.') {
        if ($failByIp.ContainsKey($ip)) { $failByIp[$ip]++ } else { $failByIp[$ip] = 1 }
    }
    # tipos de rede: 3=Network,4=Batch,8=NetworkCleartext,9=NewCleartext,10=RDP
    if ($lt -in 3,4,8,9,10) { $nFailNet++ }
}

try {
    $succ = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$since} -ErrorAction Stop)
    foreach ($s in $succ) {
        $lt = 0
        try { $lt = [int]$s.Properties[8].Value } catch { }
        if ($lt -eq 10) { $nRdp++ }
        elseif ($lt -in 3,4,8,9) { $nNetLogon++ }
    }
} catch {
    if ($_.Exception.Message -notmatch 'encontrado|No events|not found') { $seclogReadable = 0 }
}

AddLine $L '# HELP windows_security_failed_logins_5m Tentativas de login FALHAS nos ultimos 5 min (todas).'
AddLine $L '# TYPE windows_security_failed_logins_5m gauge'
AddLine $L ('windows_security_failed_logins_5m ' + $nFailAll)
AddLine $L '# HELP windows_security_failed_network_logins_5m Falhas vindas da REDE (tipos 3/4/8/9/10) nos ultimos 5 min.'
AddLine $L '# TYPE windows_security_failed_network_logins_5m gauge'
AddLine $L ('windows_security_failed_network_logins_5m ' + $nFailNet)
AddLine $L '# HELP windows_security_rdp_logons_5m Logons RDP remotos bem-sucedidos (4624 tipo 10) nos ultimos 5 min.'
AddLine $L '# TYPE windows_security_rdp_logons_5m gauge'
AddLine $L ('windows_security_rdp_logons_5m ' + $nRdp)
AddLine $L '# HELP windows_security_network_logons_5m Outros logons remotos bem-sucedidos (tipo 3/4/8/9) nos ultimos 5 min.'
AddLine $L '# TYPE windows_security_network_logons_5m gauge'
AddLine $L ('windows_security_network_logons_5m ' + $nNetLogon)

AddLine $L '# HELP windows_security_failed_login_source_ip Falhas por IP de origem nos ultimos 5 min (top 10).'
AddLine $L '# TYPE windows_security_failed_login_source_ip gauge'
if ($failByIp.Count -gt 0) {
    foreach ($kv in ($failByIp.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)) {
        AddLine $L ('windows_security_failed_login_source_ip{ip="' + (Esc $kv.Key) + '"} ' + $kv.Value)
    }
}

# ---- 3) Portas TCP ouvindo fora do loopback ----
try {
    $listens = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {
        $_.LocalAddress -notmatch '^(127\.|::1)'
    })
    $seen = @{}
    AddLine $L '# HELP windows_security_listen_ports Portas TCP ouvindo fora do loopback (1 = aberta).'
    AddLine $L '# TYPE windows_security_listen_ports gauge'
    foreach ($c in $listens) {
        $pname = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        if (-not $pname) { $pname = 'pid_' + $c.OwningProcess }
        $key = "$($c.LocalPort)|$pname"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = 1
            AddLine $L ('windows_security_listen_ports{process="' + (Esc $pname) + '",port="' + $c.LocalPort + '"} 1')
        }
    }
} catch {
    WriteLog "ERRO coletando portas: $($_.Exception.Message)"
}

# ---- 4) Windows Defender ----
$rtp = -1; $sigAge = -1; $threats = 0
try {
    $mp = Get-MpComputerStatus
    if ($mp.RealTimeProtectionEnabled) { $rtp = 1 } else { $rtp = 0 }
    if ($mp.AntivirusSignatureLastUpdated) {
        $sigAge = [math]::Round(((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays, 2)
        if ($sigAge -lt 0) { $sigAge = 0 }
    }
} catch { $rtp = -1 }
try { $threats = @(Get-MpThreat -ErrorAction SilentlyContinue).Count } catch { $threats = 0 }

AddLine $L '# HELP windows_security_defender_rtp_enabled Protecao em tempo real (1=on, 0=off, -1=erro leitura).'
AddLine $L '# TYPE windows_security_defender_rtp_enabled gauge'
AddLine $L ('windows_security_defender_rtp_enabled ' + $rtp)
AddLine $L '# HELP windows_security_defender_signature_age_days Idade em dias da assinatura de virus.'
AddLine $L '# TYPE windows_security_defender_signature_age_days gauge'
AddLine $L ('windows_security_defender_signature_age_days ' + $sigAge)
AddLine $L '# HELP windows_security_defender_threats_total Ameacas registradas pelo Defender.'
AddLine $L '# TYPE windows_security_defender_threats_total gauge'
AddLine $L ('windows_security_defender_threats_total ' + $threats)

# ---- 5) Metadados do coletor (canary / heartbeat) ----
AddLine $L '# HELP windows_security_eventlog_readable 1 se o log de eventos de seguranca foi legivel nesta coleta.'
AddLine $L '# TYPE windows_security_eventlog_readable gauge'
AddLine $L ('windows_security_eventlog_readable ' + $seclogReadable)
AddLine $L '# HELP windows_security_collector_success 1 se a coleta rodou sem erro.'
AddLine $L '# TYPE windows_security_collector_success gauge'
AddLine $L ('windows_security_collector_success ' + $success)
$epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
AddLine $L '# HELP windows_security_collector_last_run_timestamp_seconds Unix time da ultima coleta com sucesso.'
AddLine $L '# TYPE windows_security_collector_last_run_timestamp_seconds gauge'
AddLine $L ('windows_security_collector_last_run_timestamp_seconds ' + $epoch)

$sw.Stop()
AddLine $L '# HELP windows_security_collector_duration_seconds Duracao da coleta.'
AddLine $L '# TYPE windows_security_collector_duration_seconds gauge'
AddLine $L ('windows_security_collector_duration_seconds ' + [math]::Round($sw.Elapsed.TotalSeconds, 2))

# ---------------- Escrita atomica do .prom ----------------
try {
    New-Item -ItemType Directory -Path $TextFileDir -Force | Out-Null
    # tmp com PID: se dois coletores rodarem juntos (manual + tarefa
    # agendada), nenhum corrompe o arquivo do outro.
    $tmp = "$OutFile.$PID.tmp"
    [System.IO.File]::WriteAllLines($tmp, $L.ToArray())
    Move-Item -Path $tmp -Destination $OutFile -Force
    # limpa tmps orfaos de runs antigos (>2 min)
    Get-ChildItem "$TextFileDir" -Filter '*.tmp' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddMinutes(-2) } |
        Remove-Item -ErrorAction SilentlyContinue
} catch {
    $success = 0
    WriteLog "ERRO gravando .prom: $($_.Exception.Message)"
}

WriteLog "connsExt=$nExternal unknown=$nUnknown falhas5m=$nFailAll falhaRede=$nFailNet rdp=$nRdp logonRede=$nNetLogon rtp=$rtp sigAge=$sigAge threats=$threats seclogOk=$seclogReadable ok=$success dur=$([math]::Round($sw.Elapsed.TotalSeconds,2))s"
