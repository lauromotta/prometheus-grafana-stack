# Monitoramento com Prometheus + Grafana — Documentação

> Stack de monitoramento local para estudo e implementação em rede própria.
> Autor: Lauro Motta · Início: setembro/2026

## Sobre esta documentação

Documentação do stack de observabilidade montado para estudo, com o objetivo de
aplicar esse conhecimento em ambiente corporativo. Cada seção registra não só o
*como*, mas o *porquê* e os **erros reais** encontrados no caminho.

### Índice

1. [Conceitos e comparativo](#1-conceitos-e-comparativo)
2. [Arquitetura do stack](#2-arquitetura-do-stack)
3. [Setup e instalação](#3-setup-e-instalação)
4. [PromQL — a linguagem de query](#4-promql--a-linguagem-de-query)
5. [Dashboards no Grafana](#5-dashboards-no-grafana)
6. [Windows Exporter](#6-windows-exporter)
7. [Troubleshooting (erros reais encontrados)](#7-troubleshooting-erros-reais-encontrados)
8. [Alertas e notificações (Alertmanager + Telegram)](#8-alertas-e-notificações-alertmanager--telegram)

---

## 1. Conceitos e comparativo

### O problema que resolvemos

Precisamos observar a saúde de máquinas e aplicações em tempo real: CPU, memória,
disco, rede, disponibilidade. A ferramenta escolhida precisa coletar métricas,
armazená-las, mostrá-las em gráficos e alertar quando algo sai do esperado.

### Comparativo entre as principais ferramentas

| Característica | Zabbix | Prometheus + Grafana | Nagios |
|---|---|---|---|
| Licença | GPL v2 (grátis) | Apache 2.0 (grátis) | GPL (grátis) |
| Melhor em | Infra clássica (VMs, rede, HW) | Métricas de apps/containers/K8s | Checks "up/down" simples |
| Modelo de coleta | Push via agent (também SNMP) | **Pull** (scrape HTTP) | Push + pull (NRPE) |
| Curva de aprendizado | Média-alta | Média | Alta e datada |
| Dashboards | Embutido (ok) | **Grafana = excelente** | Fraco |
| Alertas | Ótimo, nativo | Alertmanager (bom) | Bom, mas arcaico |
| Configuração | Via UI, templates | Arquivos YAML | Arquivos texto (manual) |
| Armazenamento | SQL (MySQL/Postgres) | TSDB próprio | Flat files / RRD |
| Estado no mercado | Muito usado em empresas | **Padrão da indústria moderna** | Legado/em declínio |

### Por que escolhemos Prometheus + Grafana

- **Padrão de mercado** em DevOps/SRE, SaaS e cloud-native.
- **Integração nativa com Docker** — monitora containers como caso de uso principal.
- **Modelo pull**: o Prometheus *vai até* cada alvo e coleta via HTTP (`/metrics`),
  em vez de esperar um agente enviar dados.
- Ecossistema completo: Prometheus (coleta) + Grafana (visualização) +
  Alertmanager (alertas) + Exporters (coletores específicos).

### Modelo pull vs push (a diferença fundamental)

```
PULL (Prometheus / este stack):
  Prometheus ──HTTP GET──▶ http://alvo:porta/metrics
                            ◀── devolve texto com todas as métricas

PUSH (Zabbix/Nagios):
  Agent ──envia dados──▶ Server de monitoramento
```

No modelo pull, quem define **o que** e **quando** coletar é o Prometheus, por meio
do arquivo `prometheus.yml`.

---

## 2. Arquitetura do stack

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Grafana    │────▶│  Prometheus  │────▶│  Exporters   │
│  (dashboards)│     │  (coleta +   │     │  (coletam    │
│   :3000      │     │   storage)   │     │   métricas)  │
└──────────────┘     │   :9090      │     └──────────────┘
                     └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Alertmanager │
                     │  (alertas)   │
                     │   :9093      │
                     └──────────────┘
```

### Componentes e portas

| Componente | Função | Porta | URL |
|---|---|---|---|
| **Prometheus** | Coleta e armazena métricas (time-series) | 9090 | http://localhost:9090 |
| **Grafana** | Dashboards e visualização | 3000 | http://localhost:3000 |
| **cAdvisor** | Métricas dos containers Docker | 8080 | http://localhost:8080 |
| **Node Exporter** | Métricas do SO Linux (host) | 9100 | http://localhost:9100 |
| **Windows Exporter** | Métricas do SO Windows (host físico) | 9182 | http://localhost:9182 |
| **Alertmanager** | Roteamento de alertas | 9093 | http://localhost:9093 |

> **Nota importante:** o "Node Exporter" coleta métricas do *host Linux*. No nosso
> cenário (Docker Desktop no Windows), ele só enxerga o próprio container. Para o
> **Windows físico**, usamos o **Windows Exporter** (processo nativo, porta 9182).

---

## 3. Setup e instalação

### 3.1 Estrutura de arquivos

```
D:\monitoring\
├── docker-compose.yml
├── prometheus\
│   ├── prometheus.yml      # config de coleta (scrape configs)
│   └── alertrules.yml      # regras de alerta
└── alertmanager\
    └── alertmanager.yml    # roteamento de notificações
```

### 3.2 docker-compose.yml

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'   # permite recarregar config sem reiniciar
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - "GF_SECURITY_ADMIN_PASSWORD=admin"
      # Secret key FIXA (hash de senha estável entre reinícios)
      - GF_SECURITY_SECRET_KEY=chave_fixa_de_estudo_nao_usar_em_producao
      # Brute-force off (só estudo local; NUNCA em produção)
      - GF_SECURITY_DISABLE_BRUTE_FORCE_LOGIN_PROTECTION=true
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_ANALYTICS_CHECK_FOR_UPDATES=false
    volumes:
      - grafana_data:/var/lib/grafana
    ports:
      - "3000:3000"
    networks:
      - monitoring
    depends_on:
      - prometheus

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    ports:
      - "9100:9100"
    networks:
      - monitoring

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    restart: unless-stopped
    privileged: true
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    ports:
      - "8080:8080"
    networks:
      - monitoring

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    restart: unless-stopped
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
    ports:
      - "9093:9093"
    networks:
      - monitoring

volumes:
  prometheus_data:
  grafana_data:

networks:
  monitoring:
    driver: bridge
```

### 3.3 prometheus.yml (config de coleta)

```yaml
global:
  scrape_interval: 15s      # coleta a cada 15 segundos
  evaluation_interval: 15s  # avalia alertas a cada 15 segundos

alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - alertmanager:9093

rule_files:
  - "alertrules.yml"

scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "node_exporter"
    static_configs:
      - targets: ["node-exporter:9100"]

  - job_name: "cadvisor"
    static_configs:
      - targets: ["cadvisor:8080"]

  # Windows Exporter = métricas REAIS do Windows (host físico)
  # host.docker.internal resolve pro host a partir de container Linux no Docker Desktop
  - job_name: "windows_exporter"
    static_configs:
      - targets: ["host.docker.internal:9182"]

  - job_name: "alertmanager"
    static_configs:
      - targets: ["alertmanager:9093"]
```

### 3.4 comandos de subida

```bash
# Subir todo o stack
docker compose up -d

# Ver estado
docker compose ps

# Ver logs de um serviço
docker logs prometheus

# Derrubar tudo
docker compose down
```

### 3.5 Recarregar config do Prometheus sem reiniciar

Graças à flag `--web.enable-lifecycle`:

```bash
curl -X POST http://localhost:9090/-/reload
```

---

## 4. PromQL — a linguagem de query

### 4.1 Métrica

Uma **métrica** é um número nomeado que muda ao longo do tempo. Cada medição tem
um timestamp associado.

```promql
windows_memory_available_bytes        # → 7515602944 (RAM livre em bytes)
windows_cpu_time_total{mode="idle"}    # → 142503.71875 (tempo de CPU ocioso)
```

### 4.2 Série temporal

Quando consultamos uma métrica, o Prometheus devolve uma **série temporal**: uma
lista de valores ao longo do tempo — é isso que vira a linha do gráfico.

### 4.3 Labels (o coração do Prometheus)

Cada métrica carrega pares `chave=valor` que descrevem aquele número:

```promql
windows_cpu_time_total{core="0,0", mode="idle"}
windows_cpu_time_total{core="0,0", mode="user"}
windows_cpu_time_total{core="0,1", mode="idle"}
#                     ↑       ↑
#                   label   label
```

O **mesmo nome** de métrica existe em múltiplas versões — uma por combinação de
labels. Cada combinação = **uma série temporal separada**.

### 4.4 Seletores (filtrar por label)

| Sintaxe | Significado |
|---|---|
| `windows_cpu_time_total` | todas as séries com esse nome |
| `windows_cpu_time_total{mode="idle"}` | só onde `mode` é `idle` |
| `windows_cpu_time_total{mode!="idle"}` | tudo **menos** idle |
| `windows_cpu_time_total{core=~"0,0"}` | `core` casa com regex (o `=~` é regex, `=` é exato) |

### 4.5 Tipos de métrica: counter vs gauge

- **Counter** — só cresce (ex: `windows_cpu_time_total`, bytes de rede, requisições).
- **Gauge** — sobe e desce (ex: `windows_memory_available_bytes`, temperatura).

### 4.6 `rate()` — contador em taxa por segundo

Um contador que só sobe não diz "quanto agora". O `rate()` resolve calculando a
**variação por segundo** numa janela de tempo:

```promql
rate(windows_cpu_time_total{mode="idle"}[5m])
```

> `[5m]` é o **range vector**: "olhe 5 minutos de dados". Use janela ≥ 4× o
> intervalo de scrape (nosso scrape é 15s → 1m já serve; 5m suaviza o gráfico).

Resultado: em vez de valores enormes que crescem, vemos **taxas por segundo**
(~0 a 1.0 no caso de CPU).

### 4.7 Agregadores: `sum`, `avg`, `by`

```promql
# Soma todos os cores, agrupando por instância (1 linha por máquina)
sum(rate(windows_cpu_time_total{mode="idle"}[5m])) by (instance)
```

- `sum(...) by (instance)` → soma tudo mas mantém a separação por `instance`.
- Sem `by (...)`, o `sum` agrupa *tudo* numa única série.

### 4.8 A query canônica de % de CPU

O padrão "gold standard" presente em praticamente todo dashboard de CPU:

```promql
100 * (1 - sum(rate(windows_cpu_time_total{mode="idle"}[5m])) by (instance) / sum(rate(windows_cpu_time_total[5m])) by (instance))
```

Decompondo cada trecho:

| Trecho | O que faz |
|---|---|
| `rate(…[5m])` | contador → taxa por segundo |
| `{mode="idle"}` | pega só o tempo ocioso |
| `sum(…) by (instance)` | soma os cores, agrupando por máquina |
| `sum(rate(..._total[5m]))` (sem `{mode}`) | soma **todo** o tempo de CPU |
| `1 - (idle / total)` | fração **não-ociosa** = fração ocupada |
| `100 * …` | fração → percentual |

Resultado: **um único número** = % de CPU em uso.

### 4.9 O padrão universal de PromQL

```
contador → rate() → sum/avg (by label) → operação aritmética → percentual
```

Quem entende essa cadeia entende a maioria das queries reais de dashboards.

---

## 5. Dashboards no Grafana

### 5.1 Conectar o Prometheus como data source

1. Menu lateral ☰ → **Connections** → **Data sources**
2. **Add data source** → **Prometheus**
3. Campo **Prometheus server URL** → `http://prometheus:9090`
4. **Save & test** (deve aparecer verde)

### 5.2 Criar um dashboard e o primeiro painel

Fluxo no Grafana v13 (os nomes de botão mudaram vs. versões antigas):

```
"New dashboard" → botão "Panel" (menu "Add") → "Edit visualization"
→ trocar p/ modo "Code" → colar PromQL → "Run queries" → Apply → Save
```

Nota da versão v13: o botão de criar painel chama-se **"Panel"** (não "Add
visualization"). O caminho é: ícone `+` (canto superior direito, à esquerda do
Save) → menu "Add" → card "Panel". O editor de query abre via **"Edit
visualization"** no painel lateral direito.

### 5.3 Dashboard "Saúde do Windows" — 4 painéis

| Painel | Query PromQL | Tipo de visualização |
|---|---|---|
| CPU - % de uso | (ver 5.4) | Stat com sparkline |
| Memória - % de uso | (ver 5.4) | Gauge (semicircular) |
| Disco - % usado | (ver 5.4) | Stat (lista por volume) |
| Rede - bytes/s | (ver 5.4) | Gauge / Time series |

### 5.4 As 4 queries (validadas em produção local)

#### CPU — % de uso

```promql
100 * (1 - sum(rate(windows_cpu_time_total{mode="idle"}[5m])) by (instance) / sum(rate(windows_cpu_time_total[5m])) by (instance))
```

*Título:* `CPU - % de uso`
*Descrição:* Percentual de utilização da CPU, calculado como `100 − (fração ociosa)`.

#### Memória — % de uso

```promql
100 * (1 - (windows_memory_available_bytes / windows_memory_physical_total_bytes))
```

*Título:* `Memória - % de uso`
*Descrição:* Percentual de RAM em uso. Usa gauges diretos (sem `rate()`), pois são
valores instantâneos. Valores altos indicam risco de falta de memória.

#### Disco — % usado

```promql
100 * (1 - (windows_logical_disk_free_bytes / windows_logical_disk_size_bytes))
```

*Título:* `Disco - % usado`
*Descrição:* Percentual ocupado por volume (C:, D:, etc.). Uma série por volume.
Acima de 90% dispara o alerta `DiscoQuaseCheio`.

#### Rede — bytes/s

Duas queries no mesmo painel:

```promql
rate(windows_net_bytes_received_total[5m])
rate(windows_net_bytes_sent_total[5m])
```

*Título:* `Rede - bytes/s`
*Descrição:* Tráfego de rede em bytes/s. `received` = download, `sent` = upload.

### 5.5 Legendas claras com `Legend` format

O campo **Legend** (na config da query) aceita texto fixo e templates:

| Template | Resultado |
|---|---|
| `{{volume}}` | mostra só o volume (C:, D:) |
| `{{instance}}` | mostra só o host |
| `{{nic}}` | mostra só a interface de rede |
| `Download ({{nic}})` | texto + template combinados |

Exemplo aplicado no painel de Rede:
- Query received → Legend `Download ({{nic}})`
- Query sent → Legend `Upload ({{nic}})`

Resultado: legenda encurtada de
`{instance="...", job="...", nic="Realtek..."}` para
`Download (Realtek PCIe GbE Family Controller)`.

### 5.6 Tipos de visualização (quando usar qual)

| Tipo | Bom para |
|---|---|
| **Time series** | tendências ao longo do tempo (CPU, rede) |
| **Stat** | valor único em destaque (uso atual, disco) |
| **Gauge** | valor vs. limite (memória, disco) |
| **Bar gauge** | comparar várias entidades (filas, interfaces) |

### 5.7 Renomear o dashboard

O nome do dashboard **não** se edita na lista (`Dashboards`). O caminho é:
abrir o dashboard → ícone de engrenagem ⚙️ (canto sup. direito) → **General** →
campo **Name** → salvar.

(Atalho: dentro do dashboard, `D`+`S` abre as settings.)

---

## 6. Windows Exporter

### 6.1 Por que um exporter separado

O "Node Exporter" (no docker-compose) coleta métricas do *host Linux*. No Docker
Desktop no Windows, ele só enxerga o próprio container. Para o **Windows físico**
(CPU, RAM, disco e rede reais), usa-se o **Windows Exporter** — processo/serviço
nativo do Windows na porta **9182**.

### 6.2 Instalação via winget

```powershell
winget install --id Prometheus.WindowsExporter --silent --accept-package-agreements --accept-source-agreements
```

> O winget instala o binário, mas **não** registra o serviço. O executável fica em
> `%LOCALAPPDATA%\Microsoft\WinGet\Packages\Prometheus.WindowsExporter_...\windows_exporter.exe`.

### 6.3 Registrar como serviço (requer PowerShell como Admin)

```powershell
sc.exe create windows_exporter binPath= "`"C:\Users\lauro\AppData\Local\Microsoft\WinGet\Packages\Prometheus.WindowsExporter_Microsoft.Winget.Source_8wekyb3d8bbwe\windows_exporter.exe`" --web.listen-address=:9182" start= auto DisplayName= "Windows Exporter (Prometheus)"

sc.exe start windows_exporter
sc.exe query windows_exporter   # deve mostrar STATE: 4 RUNNING
```

> Atenção: o caminho tem espaços, então as aspas internas precisam ser escapadas
> com backtick `` ` `` no PowerShell.

### 6.4 Nomes de métricas (versão 0.31)

Na v0.31, o collector de memória **mudou de nome**:

| Conceito | Nome antigo | Nome v0.31 |
|---|---|---|
| RAM total | `windows_os_visible_memory_bytes` | `windows_memory_physical_total_bytes` |
| RAM disponível | — | `windows_memory_available_bytes` |
| CPU (contador) | `windows_cpu_time_total` | `windows_cpu_time_total` (idem) |
| Disco livre | `windows_logical_disk_free_bytes` | idem |
| Rede | `windows_net_bytes_*_total` | idem |

### 6.5 Registrar o job no Prometheus

No `prometheus.yml`, dentro de `scrape_configs`:

```yaml
  - job_name: "windows_exporter"
    static_configs:
      - targets: ["host.docker.internal:9182"]
```

`host.docker.internal` resolve para o host (Windows) a partir de um container
Linux no Docker Desktop. Depois, recarregar sem reiniciar:

```bash
curl -X POST http://localhost:9090/-/reload
```

---

## 7. Troubleshooting (erros reais encontrados)

Registro dos percalços reais deste projeto, com a causa e a solução de cada um.

### 7.1 Login do Grafana dá 401 no `/api/login`

**Sintoma:** testar login com `curl -X POST http://localhost:3000/api/login`
retorna `401 Unauthorized` mesmo com senha correta.

**Causa:** no Grafana v13, o endpoint de login da API mudou. O correto é
`POST /login` (sem o prefixo `/api`), não `/api/login`.

**Solução:** usar `POST http://localhost:3000/login` com JSON
`{"user":"admin","password":"..."}`. Resposta 200 `{"message":"Logged in"}`.

### 7.2 Senha do admin não bate com o que foi configurado

**Sintoma:** mesmo definindo `GF_SECURITY_ADMIN_PASSWORD`, o hash no banco não
corresponde à senha.

**Causas (duas):**
1. `GF_SECURITY_ADMIN_PASSWORD` só é aplicada na **primeira subida** com o volume
   limpo. Se o container foi criado antes (ou num `up` que falhou no meio), a
   senha fica "suja".
2. O **YAML come caracteres especiais** — `Admin12345!` vira `Admin12345` porque
   o `!` é tag do YAML.

**Solução:** derrubar, limpar o volume (`docker volume rm monitoring_grafana_data`),
definir a senha **entre aspas** no compose, e adicionar
`GF_SECURITY_SECRET_KEY=<valor fixo>` (garante hash estável entre reinícios).

### 7.3 O hash de senha do Grafana (algoritmo exato)

Para quem precisar validar/recuperar a senha direto no banco SQLite:

```python
import hashlib, sqlite3
# password = pbkdf2_sha256(senha, salt_COMO_STRING_CRUA, 10000 iterações, 50 bytes)
```

- O campo `salt` no banco é usado **literalmente** (string crua), **não**
  base64-decodado. Foi o erro que causou a maior investigação.
- Algoritmo: `PBKDF2-HMAC-SHA256`, 10000 iterações, chave de 50 bytes (100 hex).
- `rand` (outro campo) não entra no hash da senha.

### 7.4 A URL da UI do Prometheus mudou (`/graph` → `/query`)

**Sintoma:** abrir `http://localhost:9090/graph` redireciona ou dá 404.

**Causa:** Prometheus 3.x trocou a página "Graph" pela nova página `/query`.

**Solução:** usar `http://localhost:9090/query`.

### 7.5 Node Exporter não monta `/:` no Docker Desktop

**Sintoma:** `docker compose up` falha com
`path / is mounted on / but it is not a shared or slave mount`.

**Causa:** o mount do filesystem raiz (`/:/host:ro`) não funciona no Docker
Desktop/Windows (WSL2).

**Solução:** remover o mount. O Node Exporter passa a monitorar só o próprio
container (conceito). Para o **Windows físico**, usa-se o Windows Exporter.

### 7.6 SDK do `docker.exe` fora do PATH no bash (Windows)

`docker` não está no PATH do bash (Git Bash/MSYS). O executável fica em:

```
C:\Users\lauro\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe
```

Exportar antes de usar:
```bash
export PATH="/c/Users/lauro/AppData/Local/Programs/DockerDesktop/resources/bin:$PATH"
```

### 7.7 `--reload` não aplica volume novo no Prometheus

O `curl -X POST /-/reload` recarrega a *config*, mas **não** monta um volume novo.
Quando adicionar um arquivo que não era montado antes (`alertrules.yml`), é preciso
recriar o container:

```bash
docker compose up -d prometheus
```

---

## 8. Alertas e notificações (Alertmanager + Telegram)

### 8.1 O fluxo de alerta

```
Regra avalia (PromQL) → firing → Prometheus → Alertmanager → Telegram
```

### 8.2 Regras de alerta (alertrules.yml)

Regras reais do projeto (métricas do Windows Exporter):

```yaml
groups:
  - name: "alerts-basicos"
    rules:
      - alert: "InstanciaForaDoAr"
        expr: up == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Monitoramento fora do ar ({{ $labels.instance }})"

      - alert: "CPUAlta"
        expr: 100 * (1 - sum(rate(windows_cpu_time_total{mode="idle"}[5m])) by (instance) / sum(rate(windows_cpu_time_total[5m])) by (instance)) > 80
        for: 5m
        labels: { severity: warning }

      - alert: "MemoriaQuaseCheia"
        expr: 100 * (1 - (windows_memory_available_bytes / windows_memory_physical_total_bytes)) > 90
        for: 5m
        labels: { severity: warning }

      - alert: "DiscoQuaseCheio"
        expr: 100 * (1 - (windows_logical_disk_free_bytes{volume=~"[A-Z]:"} / windows_logical_disk_size_bytes{volume=~"[A-Z]:"})) > 90
        for: 5m
        labels: { severity: warning }
```

Padrão de cada regra:
- `expr:` a condição (PromQL que retorna valor quando o problema existe)
- `for:` por quanto tempo a condição deve persistir antes de disparar (evita "flapping")
- `labels.severity:` para filtrar/rotear por severidade
- `annotations.summary/description:` o texto da notificação

### 8.3 Filtrar volumes de sistema no disco

`windows_logical_disk_free_bytes` retorna todos os volumes, incluindo partições
de sistema (`HarddiskVolume1`, `HarddiskVolume4`) que não são discos "reais".

Filtro por regex para pegar só letras de drive:

```promql
windows_logical_disk_free_bytes{volume=~"[A-Z]:"}
```

`[A-Z]:` casa com `C:` e `D:`, mas não com `HarddiskVolume1`.

### 8.4 Configuração do Alertmanager (alertmanager.yml)

```yaml
route:
  group_by: ["alertname"]
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: "telegram"

receivers:
  - name: "telegram"
    telegram_configs:
      - api_url: "https://api.telegram.org"
        bot_token: "<BOT_TOKEN>"
        chat_id: <CHAT_ID>
        parse_mode: "HTML"
        message: |
          🚨 <b>{{ .GroupLabels.alertname }}</b>
          {{ range .Alerts }}
          <b>Alerta:</b> {{ .Annotations.summary }}
          {{ .Annotations.description }}
          <b>Severidade:</b> {{ .Labels.severity }}
          {{ end }}
```

### 8.5 Criar o bot no Telegram

1. No Telegram, falar com **@BotFather** → comando `/newbot`
2. Dar nome e username (termina em `bot`)
3. BotFather devolve o **token** (guarde)
4. Mandar qualquer mensagem pro seu bot
5. Descobrir o **chat_id** via:
   ```
   https://api.telegram.org/bot<TOKEN>/getUpdates
   ```
   (procurar `"chat":{"id":...}` no JSON)

### 8.6 Testar o envio direto (sem Alertmanager)

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/sendMessage" \
  -H "Content-Type: application/json" \
  --data-binary '{"chat_id": <CHAT_ID>, "text": "teste"}'
```

> No Windows/MSYS, o curl envia bytes em latin-1 por padrão; emoji e acentos dão
> erro `text must be encoded in UTF-8`. Use `--data-binary` + texto simples, ou
> confie no Alertmanager (container Linux, UTF-8 nativo).

### 8.7 Recarregar as mudanças

```bash
# Prometheus: recarrega config (regras) sem reiniciar
curl -X POST http://localhost:9090/-/reload

# Alertmanager: recarregar config
docker restart alertmanager
```