# api-keys.example.ps1 - modelo de chaves de threat intelligence
# COPIE para api-keys.ps1 e preencha com suas chaves reais (o api-keys.ps1
# NAO e versionado - ver .gitignore).
#
# VirusTotal  (hash de arquivos contra ~70 antiviruses)
#   1. https://www.virustotal.com -> Sign in -> Register (conta Google ok)
#   2. Avatar/perfil (canto sup. direito) -> "API key" -> copiar
#   Free: 4 req/min, 500/dia
#
# AbuseIPDB  (score de reputacao de IPs)
#   1. https://www.abuseipdb.com -> Register -> confirmar email
#   2. Avatar -> API -> Create Key -> copiar
#   Free: 1.000 checks/dia

$VirusTotalApiKey = 'SUA_CHAVE_VIRUSTOTAL'
$AbuseIpdbApiKey = 'SUA_CHAVE_ABUSEIPDB'
