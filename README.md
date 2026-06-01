# soc-maturity-engine

Regras de detecção acumulam ruído silenciosamente. Esse projeto mede isso — FP rate, MTTD, MTTR e quality score por regra, calculados a partir dos dados que o SIEM já gera.

![SOC Maturity Dashboard](docs/screenshots/dashboard.png)

## O que é calculado

- MTTD — tempo médio entre `event_time` e `acknowledged_at`, por regra e agregado diário
- MTTR — tempo médio entre `event_time` e `closed_at`, por regra e agregado diário
- FP Rate — taxa de falsos positivos por regra, histórico de 30 dias
- Alert Fatigue Ratio — total de alertas dividido por true positives
- Cobertura ATT&CK — percentual de técnicas MITRE ATT&CK Enterprise cobertas por regras ativas, por tática
- Rule Quality Score — pontuação 0–100, classificada em excellent / good / noisy / critical
- Regressões de cobertura — técnicas que eram cobertas ontem e deixaram de ser hoje

## Como rodar

```bash
git clone https://github.com/YDSantos12/soc-maturity-engine
cd soc-maturity-engine

cp .env.example .env

mkdir -p stix
curl -Lo stix/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

docker compose up -d

python -m simulator.alert_simulator --days 30
python -m engines.kpi_engine --backfill --days 30
python -m engines.coverage_engine

# http://localhost:3000
```

No Windows, `demo.ps1` executa os passos acima em sequência com health check do PostgreSQL.

## Estrutura

```
soc-maturity-engine/
├── db/init.sql                     schema: 4 tabelas + view soc_daily_kpis
├── ingestion/
│   ├── normalizer.py               mapeamento de campos por fonte
│   ├── mitre_tagger.py             enriquecimento ATT&CK via STIX local
│   └── webhook_server.py           FastAPI: /ingest/wazuh, /crowdstrike, /generic
├── engines/
│   ├── kpi_engine.py               MTTD, MTTR, FP rate, backfill e scheduler
│   ├── coverage_engine.py          cobertura por técnica + detecção de regressões
│   └── rule_quality_scorer.py      score 0–100 por regra
├── simulator/alert_simulator.py    20 regras, distribuição Poisson, business hours
├── dashboards/                     dashboard JSON + provisioning do Grafana
├── docs/architecture.md            decisões de design e limitações da v1
├── docker-compose.yml
├── demo.ps1
└── .env.example
```

## Testes

```bash
docker compose up postgres -d
export DATABASE_URL=postgresql://socuser:socpassword@localhost:5432/socmaturity
pytest tests/ -v
```

Testes de integração são pulados sem `DATABASE_URL`.
