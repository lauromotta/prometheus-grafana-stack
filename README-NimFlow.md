# NimFlow — Observabilidade (como subir + métricas)

> Stack Prometheus + Grafana + Alertmanager + exporters, e a instrumentação
> `/metrics` do NimFlow (proxy FastAPI). Esta página é o resumo operacional;
> o estudo completo está em `Documento-Grafana/README.md`.

## Estado atual (verificado)

| Componente | Porta | Status |
|---|---|---|
| Prometheus | 9090 | up |
| Grafana | 3000 | up (admin) |
| Alertmanager | 9093 | up |
| Node Exporter | 9100 | up |
| cAdvisor | 8080 | up |
| Windows Exporter | 9182 | up (serviço nativo Windows) |
| Windows Exporter (segurança) | 9183 | up (textfile do canário, auto-healing) |
| NimFlow `/metrics` | — | **desativado** (ver abaixo) |

> **NimFlow (17/09/2026):** o proxy local (localhost:3106) **não existe mais**.
> A produção é ****`<SEU_DOMINIO_NIMFLOW>`** (mascarado; ver config local)** (VM OCI) e **ainda não expõe
> `/metrics`** — a rota precisaria ser criada lá. O job `nimflow` está
> comentado no `prometheus/prometheus.yml` com o bloco pronto pra reabilitar
> (alvo `<SEU_DOMINIO_NIMFLOW>`, scheme https, token de autorização). Até lá,
> o dashboard "NimFlow — Observabilidade" fica sem dados por falta de fonte.

## Como subir a stack

```bash
cd /d/monitoring
docker compose up -d        # Windows: usar o CLI do Docker Desktop (PowerShell)
docker compose ps           # conferir se subiu
```

Observações:

- A stack roda via **Docker Desktop (WSL2)**. O CLI `docker` não fica em PATH
  no git-bash; invoque pelo PowerShell ou pelo `Docker Desktop`.
- `windows_exporter` é um **serviço nativo do Windows** (porta 9182), não um
  container — por isso o scrape usa `host.docker.internal:9182`.
- Credenciais ficam no `.env` (fora do versionamento)
  (`GF_SECURITY_ADMIN_PASSWORD`); health check: `curl 127.0.0.1:3000/api/health`.

## Como o NimFlow é instrumentado

Feito em `lib/observability.py` (função `setup_observability(app, enable_prometheus=True)`),
ativado em `api/index.py`. O endpoint `/metrics` fica aberto (não exige auth) e é
scrapeado pelo job `nimflow` no `prometheus/prometheus.yml` a cada 10s via
`host.docker.internal:3106/metrics`.

## Métricas e o que significam

| Métrica | Tipo | Rótulos | Significado |
|---|---|---|---|
| `http_requests_total` | counter | method, endpoint, status_code | Total de requests HTTP que passaram pelo proxy |
| `http_request_duration_seconds` | histogram | method, endpoint | Latência; use `histogram_quantile(0.95, rate(...))` para p95 |
| `http_requests_in_flight` | gauge | method | Concorrência atual (requests em voo) = "uso" |
| `nim_upstream_errors_total` | counter | nim_status | Erros NÃO-retentáveis do NIM upstream, pelo status HTTP REAL (distingue 404 = transiente vs 410 = EOL permanente) |
| `nim_stream_upstream_errors_total` | counter | nim_status | Mesma coisa, mas no caminho de streaming (SSE), onde o HTTP final fica 200 |

Importante sobre erro: o middleware só enxerga o status "embrulhado" do proxy
(502/200), então os erros reais do NIM são gravados *dentro* de `lib/proxy.py`
via `record_nim_error(status)`. Por isso existe a métrica dedicada
`nim_upstream_errors_total` — é ela que separa 404 de 410, não `http_requests_total`.

## Dashboard

Grafana → **"NimFlow — Observabilidade"** (`uid: nimflow-obs`). Painéis:

1. Latência p95/p50 por endpoint
2. Requisições/segundo por status HTTP
3. Requisições em voo (concorrência)
4. Erros NIM upstream por status real (404 vs 410)
5. Taxa de erro HTTP (status >= 400)
6. Total de requisições por endpoint

## PromQL úteis

```promql
# Latência p95 global do proxy
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))

# Taxa de erro HTTP (fração das requests com status 4xx/5xx)
sum(rate(http_requests_total{status_code=~"4..|5.."}[5m])) / sum(rate(http_requests_total[5m]))

# Erros NIM por status real (404 vs 410)
sum(rate(nim_upstream_errors_total[5m])) by (nim_status)

# Concorrência atual
sum(http_requests_in_flight)
```