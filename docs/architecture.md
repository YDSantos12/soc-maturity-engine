# SOC Maturity Engine — Architecture

## Por que PostgreSQL e não Elasticsearch para KPIs

KPIs são cálculos relacionais: `GROUP BY rule_name`, janelas temporais com `DATE(event_time)`, médias condicionais com `FILTER (WHERE ...)`, e upserts com `ON CONFLICT`. Essas operações são nativas em PostgreSQL e executam em dezenas de milissegundos sobre os volumes deste projeto (< 10 milhões de alertas).

Elasticsearch resolve busca full-text e análise de logs em tempo real — não cálculo relacional. Usar ES aqui significaria reimplementar `GROUP BY` e `HAVING` em aggregations de Bucket + Metric, perdendo legibilidade e ganhando operacional. A VIEW `soc_daily_kpis` pode ser lida por um analista que conhece SQL sem conhecer nenhuma ferramenta específica.

## Por que SQL direto via `text()` e não ORM

As queries de ingestão são point-inserts com `ON CONFLICT DO NOTHING` — uma linha de SQL. As queries de KPI são `SELECT ... GROUP BY` com `FILTER` clauses que SQLAlchemy ORM não suporta nativamente. Escrever essas queries em ORM exigiria `func.count().filter(...)` em cada coluna — mais verboso que SQL direto e menos auditável por um analista sem conhecimento de SQLAlchemy.

SQLAlchemy é usado apenas para gerenciar o connection pool (`create_engine`, `pool_size`, `max_overflow`) e o escape seguro de parâmetros (`text()` com `:param`). O SQL em si é SQL legível.

Em contexto de ingestão de alta frequência, `engine.begin()` com `conn.execute(text(...), params)` tem overhead previsível. Um ORM que carrega objetos em memória, rastreia estado e emite múltiplos SELECTs antes do INSERT seria mais lento sem nenhum benefício funcional aqui.

## Modelo de timestamps e como viabilizam MTTD/MTTR

Cada alerta carrega quatro timestamps com semânticas distintas:

| Campo            | Quando é preenchido                              |
|------------------|--------------------------------------------------|
| `event_time`     | Quando o evento ocorreu na fonte (SIEM/EDR)      |
| `ingested_at`    | Quando o pipeline recebeu e persistiu o alerta   |
| `acknowledged_at`| Quando um analista abriu o caso                  |
| `closed_at`      | Quando o caso foi encerrado com um veredito      |

**MTTD** = `acknowledged_at − event_time`

**MTTR** = `closed_at − event_time`

O ponto de origem é `event_time`, não `ingested_at`. Usar `ingested_at` mediria o desempenho do pipeline de ingestão — quanto tempo levou para chegar ao banco — não o tempo de resposta do analista ao incidente. Um alerta gerado às 02:00 e ingerido às 02:00:05 que só foi reconhecido às 08:30 tem MTTD de 390 minutos, não de 5 segundos.

`ingested_at` existe para auditoria de latência do pipeline, não para KPIs operacionais.

Ambas as métricas excluem alertas com status `new` ou `in_progress` do denominador do FP rate: alertas não resolvidos não têm veredito ainda e distorceriam a taxa se incluídos.

## Como o Rule Quality Score é calculado

O score começa em 100 e recebe penalidades e bônus baseados em métricas operacionais do dia:

```
score = 100.0

# Penalidade 1 — Alta taxa de FP
if fp_rate > 50:
    score -= (fp_rate - 50) * 1.2

# Penalidade 2 — Alto volume sem nenhum TP
if total_alerts > 50 and tp_count == 0:
    score -= 30

# Penalidade 3 — Maioria dos alertas ignorada
if total_alerts > 0 and (open_count / total_alerts) > 0.8:
    score -= 15

# Penalidade 4 — Resolução muito lenta (cap em 10 pontos)
if avg_mttr_min > 480:
    score -= min((avg_mttr_min - 480) / 480 * 10, 10)

# Bônus — Regra de alta precisão confirmada
if tp_count > 0 and fp_rate < 10:
    score += 10

score = clamp(score, 0.0, 100.0)
```

**Por que penalidade gradual no FP rate e não threshold binário:** uma regra com 60% de FP rate ainda detecta 40% de eventos reais — tem valor. Um corte binário em 50% descartaria essa regra do mesmo jeito que uma com 95% de FP. A penalidade `(fp_rate − 50) × 1.2` é proporcional: quanto mais ruidosa, maior o desconto, mas a regra nunca é zerada apenas por ter FP alto se também tiver TPs.

**Por que o bônus de alta precisão existe:** regras com `fp_rate < 10` e `tp_count > 0` são raras em ambientes reais. O bônus de 10 pontos empurra essas regras para o tier `excellent (≥ 80)` mesmo que tenham `avg_mttr_min` elevado, reconhecendo que precisão alta justifica tolerar latência maior na resposta.

**Tiers de classificação:**

| Score    | Tier        | Interpretação                            |
|----------|-------------|------------------------------------------|
| ≥ 80     | excellent   | Regra confiável, baixo ruído             |
| 60–79    | good        | Operacional, mas com margem de melhoria  |
| 35–59    | noisy       | Gera fadiga; revisar lógica de detecção  |
| < 35     | critical    | Candidata a desabilitação ou reescrita   |

## Limitações conhecidas da v1

**Simulator não modela variância temporal realista entre dias.** O volume por regra é amostrado de uma distribuição Poisson independente a cada dia. Ambientes reais têm sazonalidade (pico na segunda, queda no fim de semana), campanhas de ataque que se concentram em períodos, e correlação entre regras quando o mesmo host dispara múltiplas delas. O simulator não captura nenhum desses padrões.

**MITRE tagger usa keyword matching simples sem NLP.** O `mitre_tagger.py` extrai técnicas de `rule_name` via regex (`T\d{4}`) e substring matching contra nomes de técnicas. Nomes ambíguos ou em idiomas diferentes do inglês não são mapeados. Uma abordagem com embeddings semânticos aumentaria a cobertura de tagging para alertas sem técnica explícita no nome da regra.

**`/ingest/generic` não tem autenticação.** O endpoint foi criado para o simulator e testes de integração. Em produção, expor esse endpoint sem token de validação permite que qualquer cliente injete alertas de qualquer `source_system`. Deve ser removido ou protegido antes de um deploy real.

**Coverage de ~1.97% é esperado com 20 regras simuladas.** O bundle ATT&CK Enterprise contém ~1015 técnicas e sub-técnicas. Com 20 regras cobrindo 20 técnicas distintas, a cobertura calculada é 20/1015 ≈ 1.97%. Isso não é um bug — é o estado real de um SOC pequeno sem mapeamento formal de cobertura. O Coverage Engine existe precisamente para tornar essa lacuna visível e mensurável ao longo do tempo.
