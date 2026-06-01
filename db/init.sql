-- SOC Maturity Engine — Database Schema
-- PostgreSQL 16

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- alerts_normalized
-- ---------------------------------------------------------------------------
CREATE TABLE alerts_normalized (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id        VARCHAR(255),
    source_system    VARCHAR(100) NOT NULL
                         CHECK (source_system IN ('wazuh', 'crowdstrike', 'simulator')),
    rule_name        VARCHAR(255) NOT NULL,
    rule_id          VARCHAR(100),
    severity         VARCHAR(20)  NOT NULL
                         CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category         VARCHAR(100),
    mitre_technique  VARCHAR(20),
    mitre_tactic     VARCHAR(50),
    hostname         VARCHAR(255),
    ip_address       INET,
    username         VARCHAR(255),
    event_time       TIMESTAMPTZ  NOT NULL,
    ingested_at      TIMESTAMPTZ  DEFAULT NOW(),
    status           VARCHAR(30)  DEFAULT 'new'
                         CHECK (status IN ('new', 'in_progress', 'escalated', 'closed_tp', 'closed_fp', 'closed_benign')),
    assigned_to      VARCHAR(100),
    acknowledged_at  TIMESTAMPTZ,
    closed_at        TIMESTAMPTZ,
    raw_payload      JSONB,
    created_at       TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_alerts_rule_name       ON alerts_normalized (rule_name);
CREATE INDEX idx_alerts_severity        ON alerts_normalized (severity);
CREATE INDEX idx_alerts_status          ON alerts_normalized (status);
CREATE INDEX idx_alerts_event_time      ON alerts_normalized (event_time DESC);
CREATE INDEX idx_alerts_mitre_technique ON alerts_normalized (mitre_technique);
CREATE INDEX idx_alerts_source_system   ON alerts_normalized (source_system);

-- ---------------------------------------------------------------------------
-- rule_performance_snapshots
-- ---------------------------------------------------------------------------
CREATE TABLE rule_performance_snapshots (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_date    DATE         NOT NULL,
    rule_name        VARCHAR(255) NOT NULL,
    source_system    VARCHAR(100) NOT NULL,
    total_alerts     INTEGER      DEFAULT 0,
    tp_count         INTEGER      DEFAULT 0,
    fp_count         INTEGER      DEFAULT 0,
    benign_count     INTEGER      DEFAULT 0,
    open_count       INTEGER      DEFAULT 0,
    fp_rate          NUMERIC(5,2),
    escalation_rate  NUMERIC(5,2),
    avg_mttd_min     NUMERIC(10,2),
    avg_mttr_min     NUMERIC(10,2),
    quality_score    NUMERIC(5,2),
    mitre_technique  VARCHAR(20),
    mitre_tactic     VARCHAR(50),
    created_at       TIMESTAMPTZ  DEFAULT NOW(),

    UNIQUE (snapshot_date, rule_name, source_system)
);

-- ---------------------------------------------------------------------------
-- mitre_coverage_snapshots
-- ---------------------------------------------------------------------------
CREATE TABLE mitre_coverage_snapshots (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_date    DATE         NOT NULL,
    mitre_technique  VARCHAR(20)  NOT NULL,
    mitre_tactic     VARCHAR(50),
    technique_name   VARCHAR(255),
    is_covered       BOOLEAN      DEFAULT FALSE,
    active_rules     INTEGER      DEFAULT 0,
    rule_names       TEXT[],
    coverage_quality NUMERIC(5,2),
    created_at       TIMESTAMPTZ  DEFAULT NOW(),

    UNIQUE (snapshot_date, mitre_technique)
);

-- ---------------------------------------------------------------------------
-- analyst_metrics
-- ---------------------------------------------------------------------------
CREATE TABLE analyst_metrics (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_date      DATE         NOT NULL,
    analyst          VARCHAR(100) NOT NULL,
    cases_handled    INTEGER      DEFAULT 0,
    cases_escalated  INTEGER      DEFAULT 0,
    cases_tp         INTEGER      DEFAULT 0,
    cases_fp         INTEGER      DEFAULT 0,
    avg_mttr_min     NUMERIC(10,2),
    created_at       TIMESTAMPTZ  DEFAULT NOW(),

    UNIQUE (metric_date, analyst)
);

-- ---------------------------------------------------------------------------
-- soc_daily_kpis  (view)
-- ---------------------------------------------------------------------------
CREATE VIEW soc_daily_kpis AS
SELECT
    DATE(event_time)                                               AS kpi_date,
    COUNT(*)                                                       AS total_alerts,
    COUNT(*) FILTER (WHERE severity = 'critical')                  AS critical_count,
    COUNT(*) FILTER (WHERE severity = 'high')                      AS high_count,
    COUNT(*) FILTER (WHERE status = 'closed_tp')                   AS true_positives,
    COUNT(*) FILTER (WHERE status = 'closed_fp')                   AS false_positives,
    COUNT(*) FILTER (WHERE status = 'closed_benign')               AS benign_alerts,
    COUNT(*) FILTER (WHERE status = 'new')                         AS open_alerts,
    ROUND(
        AVG(
            EXTRACT(EPOCH FROM (acknowledged_at - event_time)) / 60
        ) FILTER (WHERE acknowledged_at IS NOT NULL),
        2
    )                                                              AS avg_mttd_min,
    ROUND(
        AVG(
            EXTRACT(EPOCH FROM (closed_at - event_time)) / 60
        ) FILTER (WHERE closed_at IS NOT NULL),
        2
    )                                                              AS avg_mttr_min,
    ROUND(
        COUNT(*) FILTER (WHERE status = 'closed_fp')::NUMERIC
        / NULLIF(
            COUNT(*) FILTER (WHERE status IN ('closed_tp', 'closed_fp', 'closed_benign')),
            0
          ) * 100,
        2
    )                                                              AS fp_rate_pct
FROM alerts_normalized
GROUP BY DATE(event_time);
