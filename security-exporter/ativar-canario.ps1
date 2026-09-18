# =====================================================================
# ativar-canario.ps1 - ATIVACAO UNICA do canario de seguranca de rede
# Nota: arquivo em ASCII puro + BOM UTF-8. O Windows PowerShell 5.1 le
#       arquivos .ps1 sem BOM como ANSI, e caracteres UTF-8 (travessao,
#       acentos, aspas curvas) corrompem o parser.
#
# Passos:
#  1. Roda o coletor pela 1a vez (e sobe o exporter dedicado :9183)
#  2. Confirma metricas de seguranca servidas em :9183
#  3. Garante Docker Desktop ligado
#  4. Sobe a stack via docker compose
#  5. Confere job 'security_exporter' e grupo 'seguranca-rede' no Prometheus
#  6. Cria datasource e importa o dashboard no Grafana
#  7. Registra tarefa agendada (60s, invisivel) e dispara agora
#
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File .\ativar-canario.ps1
# =====================================================================
param([string]$GrafanaPass = $null)

$ErrorActionPreference = 'Continue'
$Sec   = 'D:\monitoring\security-exporter'
$Mon   = 'D:\monitoring'
$pass  = @(); $fail = @()

function Step($m){ Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m){ $script:pass += $m; Write-Host "  [OK] $m" -ForegroundColor Green }
function Bad($m){ $script:fail += $m; Write-Host "  [FALHOU] $m" -ForegroundColor Red }
function HttpGet($u,$hdr=$null){
    $p = @{ Uri=$u; TimeoutSec=5; UseBasicParsing=$true }
    if ($hdr) { $p.Headers = $hdr }
    try { (Invoke-WebRequest @p).Content } catch { $null }
}

# ---------------- 1) Primeira coleta ----------------
Step "1/7 Primeira execucao do coletor (sobe exporter :9183 se precisar)"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$Sec\collect-security-metrics.ps1" *> $null
$promFile = Join-Path $Sec 'textfile\security-metrics.prom'
if (Test-Path $promFile) { Ok "Arquivo .prom gerado ($((Get-Item $promFile).Length) bytes)" }
else { Bad "coletor nao gerou o .prom - veja $Sec\coleta.log" }

# ---------------- 2) Exporter dedicado :9183 ----------------
Step "2/7 Exporter dedicado :9183"
$mounted = $false
for ($i=0; $i -lt 15 -and -not $mounted; $i++) {
    $body = HttpGet 'http://127.0.0.1:9183/metrics'
    if ($body -and $body -match 'windows_security_collector_success') { $mounted = $true; break }
    Start-Sleep 2
}
if ($mounted) { Ok 'metricas windows_security_* servidas em :9183' }
else { Bad 'exporter :9183 nao responde com metricas de seguranca' }

# ---------------- 3) Docker ----------------
Step "3/7 Docker Desktop / engine"
for ($i=0; $i -lt 60; $i++) {
    docker info *> $null
    if ($LASTEXITCODE -eq 0) { break }
    if (-not (Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue)) {
        Start-Process (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe')
    }
    Start-Sleep 5
}
if ($LASTEXITCODE -eq 0) { Ok 'Docker engine pronto' }
else { Bad 'Docker engine nao subiu (abriu? espere e rode de novo)' }

# ---------------- 4) Stack ----------------
Step "4/7 docker compose up -d"
Push-Location $Mon
docker compose up -d 2>&1 | ForEach-Object { Write-Host "    $_" }
Pop-Location
docker compose -f "$Mon\docker-compose.yml" ps --format '{{.Name}}: {{.Status}}' 2>&1 | ForEach-Object { Write-Host "    $_" }

# ---------------- 5) Prometheus: alvo + regras ----------------
Step "5/7 Prometheus (alvo security_exporter + grupo seguranca-rede)"
$targetOk = $false
for ($i=0; $i -lt 30 -and -not $targetOk; $i++) {
    $tj = HttpGet 'http://localhost:9090/api/v1/targets'
    if ($tj) {
        try {
            $targets = (ConvertFrom-Json $tj).data.activeTargets
            $secTgts = @($targets | Where-Object { $_.labels.job -eq 'security_exporter' })
            if ($secTgts.Count -gt 0 -and @($secTgts | Where-Object { $_.health -eq 'up' }).Count -gt 0) { $targetOk = $true; break }
        } catch { }
    }
    Start-Sleep 4
}
if ($targetOk) { Ok 'job security_exporter UP no Prometheus' }
else { Bad 'job security_exporter nao esta up (veja Prometheus > Targets)' }

$rulesOk = $false
for ($i=0; $i -lt 30 -and -not $rulesOk; $i++) {
    $rj = HttpGet 'http://localhost:9090/api/v1/rules'
    if ($rj) {
        try {
            $groups = (ConvertFrom-Json $rj).data.groups
            if (@($groups | Where-Object { $_.name -eq 'seguranca-rede' }).Count -gt 0) { $rulesOk = $true; break }
        } catch { }
    }
    Start-Sleep 4
}
if ($rulesOk) { Ok 'grupo de alertas "seguranca-rede" carregado' }
else { Bad 'grupo seguranca-rede nao carregou (security-alerts.yml montado no compose?)' }

# ---------------- 6) Grafana ----------------
Step "6/7 Grafana (datasource + dashboard)"
$grafanaUp = $false
for ($i=0; $i -lt 30; $i++) {
    if (HttpGet 'http://localhost:3000/api/health') { $grafanaUp = $true; break }
    Start-Sleep 4
}
if (-not $grafanaUp) {
    Bad 'Grafana nao respondeu em :3000'
}
else {
    # Candidatos de senha, em ordem: parametro -GrafanaPass > grafana-pass.txt > .env > admin
    # Motivo: a senha real do Grafana vive no VOLUME do container (definida no
    # primeiro boot), nao necessariamente no .env de hoje.
    $cands = @()
    if ($GrafanaPass) { $cands += $GrafanaPass }
    $passFile = "$Sec\grafana-pass.txt"
    if (Test-Path $passFile) {
        $fp = ([IO.File]::ReadAllText($passFile)).Trim()
        if ($fp) { $cands += $fp }
    }
    if (Test-Path "$Mon\.env") {
        $line = Get-Content "$Mon\.env" | Where-Object { $_ -match '^\s*GF_SECURITY_ADMIN_PASSWORD\s*=' } | Select-Object -First 1
        if ($line) {
            $p2 = ($line -replace '^\s*GF_SECURITY_ADMIN_PASSWORD\s*=\s*','').Trim(' "')
            if ($p2) { $cands += $p2 }
        }
    }
    $cands += 'admin'
    $cands = @($cands | Where-Object { $_ } | Select-Object -Unique)
    Write-Host ("    [debug] passFile=" + $passFile + " | existe=" + (Test-Path $passFile) + " | cands=" + $cands.Count)

    $auth = $null; $me = $null; $usedIdx = -1
    for ($ci=0; $ci -lt $cands.Count; $ci++) {
        $a = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('admin:' + $cands[$ci])) }
        $me = HttpGet 'http://localhost:3000/api/user' $a
        if ($me) { $auth = $a; $usedIdx = $ci; break }
    }
    if (-not $me) {
        Bad ('login do Grafana falhou testando ' + $cands.Count + ' candidatos de senha. Coloque a senha correta em D:\monitoring\security-exporter\grafana-pass.txt (uma linha) e rode este script de novo.')
    }
    else {
        Ok ('autenticado no Grafana (senha do candidato #' + ($usedIdx + 1) + ')')
        $dsUid = $null
        $dsex = HttpGet 'http://localhost:3000/api/datasources/name/Prometheus' $auth
        if ($dsex) {
            try { $dsUid = (ConvertFrom-Json $dsex).uid } catch { }
            Ok "datasource Prometheus ja existia (uid=$dsUid)"
        } else {
            $payload = @{ name='Prometheus'; type='prometheus'; url='http://prometheus:9090'; access='proxy'; isDefault=$true; uid='prometheus' } | ConvertTo-Json
            try { $null = Invoke-RestMethod -Uri 'http://localhost:3000/api/datasources' -Method Post -Headers $auth -ContentType 'application/json' -Body $payload } catch { }
            $dsex2 = HttpGet 'http://localhost:3000/api/datasources/name/Prometheus' $auth
            if ($dsex2) {
                try { $dsUid = (ConvertFrom-Json $dsex2).uid } catch { }
                Ok 'datasource Prometheus criado (uid=prometheus)'
            } else {
                Bad 'falha ao criar datasource Prometheus'
            }
        }
        if ($dsUid) {
            $dj = [IO.File]::ReadAllText("$Mon\grafana\dashboards\seguranca-da-rede.json")
            $dj = $dj -replace '__PROMUID__', $dsUid
            try {
                $null = Invoke-RestMethod -Uri 'http://localhost:3000/api/dashboards/db' -Method Post -Headers $auth -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($dj))
                Ok 'dashboard "Seguranca da Rede (Canario)" importado (uid=seguranca-rede)'
                Write-Host '    abre em: http://localhost:3000/d/seguranca-rede' -ForegroundColor Yellow
            } catch { Bad ('importacao do dashboard falhou: ' + $_.Exception.Message) }
        }
    }
}

# ---------------- 7) Tarefa agendada ----------------
Step "7/7 Tarefa agendada (60s, invisivel) + disparo imediato"
$action = 'wscript.exe "D:\monitoring\security-exporter\invisible-runner.vbs"'
schtasks /Create /F /SC MINUTE /MO 1 /TN "CanarioSegurancaPrometheus" /TR $action | Out-Null
$task = schtasks /Query /TN "CanarioSegurancaPrometheus" 2>&1
if ($LASTEXITCODE -eq 0) {
    Ok 'tarefa "CanarioSegurancaPrometheus" registrada (a cada 1 min)'
    schtasks /Run /TN "CanarioSegurancaPrometheus" | Out-Null
    Ok 'primeira execucao automatica disparada'
} else {
    Bad ("cadastro da tarefa falhou: $task")
}

# ---------------- Resumo ----------------
Write-Host "`n==================== RESUMO ====================" -ForegroundColor Cyan
$pass | ForEach-Object { Write-Host " [OK]  $_" -ForegroundColor Green }
$fail | ForEach-Object { Write-Host " [X]   $_" -ForegroundColor Red }
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ' Grafana:     http://localhost:3000/d/seguranca-rede'
Write-Host ' Prometheus:  http://localhost:9090/query   (query: windows_security_*)'
Write-Host ' Alertas -> Alertmanager -> Telegram.'
Write-Host ' Prova-real: desligue a protecao em tempo real do Defender por 6 min'
Write-Host ' -> deve chegar alerta critico DefenderProtecaoTempoRealDesligada no Telegram.' -ForegroundColor Yellow
if ($fail.Count -gt 0) { Write-Host "`nHOUVE FALHAS - ver acima." -ForegroundColor Red; exit 1 }
Write-Host "`nCANARIO DE SEGURANCA ATIVO." -ForegroundColor Green
