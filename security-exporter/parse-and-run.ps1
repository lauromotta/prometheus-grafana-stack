# =====================================================================
# parse-and-run.ps1 - valida a sintaxe dos scripts e so entao ativa
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File .\parse-and-run.ps1
# =====================================================================
$files = @(
    'D:\monitoring\security-exporter\ativar-canario.ps1',
    'D:\monitoring\security-exporter\collect-security-metrics.ps1'
)
$bad = $false
foreach ($f in $files) {
    $errs = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count -gt 0) {
        Write-Host "PARSE ERRO em $f :" -ForegroundColor Red
        $errs | ForEach-Object { Write-Host ("  linha {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) }
        $bad = $true
    } else {
        Write-Host "parse OK: $f" -ForegroundColor Green
    }
}
if ($bad) { Write-Host 'Corrija os erros antes de ativar.' -ForegroundColor Red; exit 1 }
Write-Host "`nATIVANDO CANARIO..." -ForegroundColor Cyan
& 'D:\monitoring\security-exporter\ativar-canario.ps1'
