"""Computes daily SOC operational KPIs from alerts_normalized and materializes
rule performance snapshots via direct SQL inserts."""

from __future__ import annotations

import logging
import traceback
import time
from datetime import date, timedelta
from typing import Any

from sqlalchemy import create_engine, text

from engines.rule_quality_scorer import RuleQualityScorer

_logger = logging.getLogger("soc_maturity.kpi_engine")

# Sync engine: KPI queries are bulk reads + batch inserts that complete in one
# shot. async overhead would add latency without enabling any concurrency gain
# here. FastAPI is not involved — this runs as a standalone process.
_DAILY_SNAPSHOT_SQL = text("""
    SELECT
        COUNT(*)                                                              AS total_alerts,
        COUNT(*) FILTER (WHERE severity = 'critical')                        AS critical_count,
        COUNT(*) FILTER (WHERE severity = 'high')                            AS high_count,
        COUNT(*) FILTER (WHERE severity = 'medium')                          AS medium_count,
        COUNT(*) FILTER (WHERE severity = 'low')                             AS low_count,
        COUNT(*) FILTER (WHERE status = 'closed_tp')                         AS true_positives,
        COUNT(*) FILTER (WHERE status = 'closed_fp')                         AS false_positives,
        COUNT(*) FILTER (WHERE status = 'closed_benign')                     AS benign_closed,
        COUNT(*) FILTER (WHERE status = 'new')                               AS open_alerts,
        AVG(
            EXTRACT(EPOCH FROM (acknowledged_at - event_time)) / 60
        ) FILTER (WHERE acknowledged_at IS NOT NULL)                          AS avg_mttd_min,
        AVG(
            EXTRACT(EPOCH FROM (closed_at - event_time)) / 60
        ) FILTER (WHERE closed_at IS NOT NULL)                                AS avg_mttr_min,
        CAST(
            COUNT(*) FILTER (WHERE status = 'closed_fp')::numeric * 100
            / NULLIF(
                COUNT(*) FILTER (WHERE status IN ('closed_tp', 'closed_fp', 'closed_benign')),
                0
            ) AS double precision
        )                                                                     AS fp_rate_pct,
        CAST(
            COUNT(*)::numeric
            / NULLIF(COUNT(*) FILTER (WHERE status = 'closed_tp'), 0)
            AS double precision
        )                                                                     AS alert_fatigue_ratio
    FROM alerts_normalized
    WHERE DATE(event_time) = :target_date
""")

_RULE_PERFORMANCE_SQL = text("""
    SELECT
        rule_name,
        source_system,
        COUNT(*)                                                              AS total_alerts,
        COUNT(*) FILTER (WHERE status = 'closed_tp')                         AS tp_count,
        COUNT(*) FILTER (WHERE status = 'closed_fp')                         AS fp_count,
        COUNT(*) FILTER (WHERE status = 'closed_benign')                     AS benign_count,
        COUNT(*) FILTER (WHERE status = 'new')                               AS open_count,
        COUNT(*) FILTER (WHERE status = 'escalated')                         AS escalated_count,
        CAST(
            COUNT(*) FILTER (WHERE status = 'closed_fp')::numeric * 100
            / NULLIF(
                COUNT(*) FILTER (WHERE status IN ('closed_tp', 'closed_fp', 'closed_benign')),
                0
            ) AS double precision
        )                                                                     AS fp_rate,
        CAST(
            COUNT(*) FILTER (WHERE status = 'escalated')::numeric * 100
            / COUNT(*) AS double precision
        )                                                                     AS escalation_rate,
        AVG(
            EXTRACT(EPOCH FROM (acknowledged_at - event_time)) / 60
        ) FILTER (WHERE acknowledged_at IS NOT NULL)                          AS avg_mttd_min,
        AVG(
            EXTRACT(EPOCH FROM (closed_at - event_time)) / 60
        ) FILTER (WHERE closed_at IS NOT NULL)                                AS avg_mttr_min
    FROM alerts_normalized
    WHERE DATE(event_time) = :target_date
    GROUP BY rule_name, source_system
    ORDER BY total_alerts DESC
""")

_UPSERT_RULE_SNAPSHOT = text("""
    INSERT INTO rule_performance_snapshots (
        snapshot_date, rule_name, source_system,
        total_alerts, tp_count, fp_count, benign_count, open_count,
        fp_rate, escalation_rate, avg_mttd_min, avg_mttr_min, quality_score
    ) VALUES (
        :snapshot_date, :rule_name, :source_system,
        :total_alerts, :tp_count, :fp_count, :benign_count, :open_count,
        :fp_rate, :escalation_rate, :avg_mttd_min, :avg_mttr_min, :quality_score
    )
    ON CONFLICT (snapshot_date, rule_name, source_system) DO UPDATE SET
        total_alerts    = EXCLUDED.total_alerts,
        tp_count        = EXCLUDED.tp_count,
        fp_count        = EXCLUDED.fp_count,
        benign_count    = EXCLUDED.benign_count,
        open_count      = EXCLUDED.open_count,
        fp_rate         = EXCLUDED.fp_rate,
        escalation_rate = EXCLUDED.escalation_rate,
        avg_mttd_min    = EXCLUDED.avg_mttd_min,
        avg_mttr_min    = EXCLUDED.avg_mttr_min,
        quality_score   = EXCLUDED.quality_score
""")


class KpiEngine:
    """Orchestrates daily KPI calculation and persistence for the SOC maturity engine."""

    def __init__(self, db_url: str) -> None:
        """Create engine and connection pool.

        Args:
            db_url: SQLAlchemy-compatible PostgreSQL connection string.
        """
        self._engine = create_engine(db_url, pool_size=5, max_overflow=10)

    def calculate_daily_snapshot(self, target_date: date) -> dict[str, Any]:
        """Compute aggregate SOC KPIs for a single calendar day.

        Args:
            target_date: The day to aggregate (matches DATE(event_time)).

        Returns:
            Dict with keys: total_alerts, critical_count, high_count, medium_count,
            low_count, true_positives, false_positives, benign_closed, open_alerts,
            avg_mttd_min, avg_mttr_min, fp_rate_pct, alert_fatigue_ratio.
            Integer count fields are 0 when no alerts exist. Float/rate fields
            are None when denominators are zero or no relevant events exist.
        """
        with self._engine.connect() as conn:
            row = conn.execute(
                _DAILY_SNAPSHOT_SQL, {"target_date": target_date}
            ).mappings().fetchone()

        def _int(v: Any) -> int:
            return int(v) if v is not None else 0

        def _float(v: Any) -> float | None:
            return float(v) if v is not None else None

        return {
            "total_alerts":        _int(row["total_alerts"]),
            "critical_count":      _int(row["critical_count"]),
            "high_count":          _int(row["high_count"]),
            "medium_count":        _int(row["medium_count"]),
            "low_count":           _int(row["low_count"]),
            "true_positives":      _int(row["true_positives"]),
            "false_positives":     _int(row["false_positives"]),
            "benign_closed":       _int(row["benign_closed"]),
            "open_alerts":         _int(row["open_alerts"]),
            "avg_mttd_min":        _float(row["avg_mttd_min"]),
            "avg_mttr_min":        _float(row["avg_mttr_min"]),
            "fp_rate_pct":         _float(row["fp_rate_pct"]),
            "alert_fatigue_ratio": _float(row["alert_fatigue_ratio"]),
        }

    def calculate_rule_performance(self, target_date: date) -> list[dict[str, Any]]:
        """Compute per-rule operational metrics for a single calendar day.

        Args:
            target_date: The day to aggregate.

        Returns:
            List of dicts ordered by total_alerts descending. Each dict contains:
            rule_name, source_system, total_alerts, tp_count, fp_count,
            benign_count, open_count, escalated_count, fp_rate, escalation_rate,
            avg_mttd_min, avg_mttr_min. Float fields are None when no relevant
            events exist. quality_score is absent — caller must populate it.
        """
        with self._engine.connect() as conn:
            rows = conn.execute(
                _RULE_PERFORMANCE_SQL, {"target_date": target_date}
            ).mappings().fetchall()

        def _int(v: Any) -> int:
            return int(v) if v is not None else 0

        def _float(v: Any) -> float | None:
            return float(v) if v is not None else None

        return [
            {
                "rule_name":       row["rule_name"],
                "source_system":   row["source_system"],
                "total_alerts":    _int(row["total_alerts"]),
                "tp_count":        _int(row["tp_count"]),
                "fp_count":        _int(row["fp_count"]),
                "benign_count":    _int(row["benign_count"]),
                "open_count":      _int(row["open_count"]),
                "escalated_count": _int(row["escalated_count"]),
                "fp_rate":         _float(row["fp_rate"]),
                "escalation_rate": _float(row["escalation_rate"]),
                "avg_mttd_min":    _float(row["avg_mttd_min"]),
                "avg_mttr_min":    _float(row["avg_mttr_min"]),
            }
            for row in rows
        ]

    def persist_rule_snapshots(
        self, snapshots: list[dict[str, Any]], target_date: date
    ) -> int:
        """Upsert rule performance snapshots into rule_performance_snapshots.

        Args:
            snapshots: List of dicts from calculate_rule_performance, each with
                       quality_score already populated by RuleQualityScorer.
            target_date: Date these snapshots represent.

        Returns:
            Total number of rows inserted or updated.
        """
        if not snapshots:
            return 0

        count = 0
        with self._engine.begin() as conn:
            for snap in snapshots:
                params = {
                    "snapshot_date":  target_date,
                    "rule_name":      snap["rule_name"],
                    "source_system":  snap["source_system"],
                    "total_alerts":   snap["total_alerts"],
                    "tp_count":       snap["tp_count"],
                    "fp_count":       snap["fp_count"],
                    "benign_count":   snap["benign_count"],
                    "open_count":     snap["open_count"],
                    "fp_rate":        snap.get("fp_rate"),
                    "escalation_rate": snap.get("escalation_rate"),
                    "avg_mttd_min":   snap.get("avg_mttd_min"),
                    "avg_mttr_min":   snap.get("avg_mttr_min"),
                    "quality_score":  snap.get("quality_score"),
                }
                result = conn.execute(_UPSERT_RULE_SNAPSHOT, params)
                count += result.rowcount

        return count

    def run_daily(self, target_date: date | None = None) -> None:
        """Compute, score, and persist rule performance snapshots for one day.

        If target_date is None, defaults to yesterday (today - 1 day).

        Args:
            target_date: Day to process, or None for yesterday.
        """
        if target_date is None:
            target_date = date.today() - timedelta(days=1)

        snapshots = self.calculate_rule_performance(target_date)

        scorer = RuleQualityScorer()
        for snap in snapshots:
            snap["quality_score"] = scorer.score(snap)

        persisted = self.persist_rule_snapshots(snapshots, target_date)

        avg_score = (
            sum(s["quality_score"] for s in snapshots) / len(snapshots)
            if snapshots else 0.0
        )
        _logger.info(
            "Daily run complete: date=%s, rules=%d, persisted=%d, avg_quality=%.1f",
            target_date, len(snapshots), persisted, avg_score,
        )


if __name__ == "__main__":
    import argparse
    import os
    import traceback

    import schedule
    from dotenv import load_dotenv

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    load_dotenv()
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL environment variable is required")

    parser = argparse.ArgumentParser(description="SOC KPI Engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--schedule", action="store_true", help="Run daily at 01:00")
    group.add_argument("--backfill", action="store_true", help="Process last N days")
    parser.add_argument("--days", type=int, default=7, help="Days for --backfill")
    args = parser.parse_args()

    kpi_engine = KpiEngine(db_url)

    if args.schedule:
        def _scheduled_job() -> None:
            start = time.time()
            _logger.info("Scheduled daily run starting")
            try:
                kpi_engine.run_daily()
                _logger.info("Scheduled daily run finished in %.1fs", time.time() - start)
            except Exception:
                _logger.error(
                    "Scheduled daily run failed after %.1fs:\n%s",
                    time.time() - start,
                    traceback.format_exc(),
                )

        schedule.every().day.at("01:00").do(_scheduled_job)
        _logger.info("KPI scheduler started — daily at 01:00")
        while True:
            schedule.run_pending()
            time.sleep(30)

    elif args.backfill:
        today = date.today()
        start_date = today - timedelta(days=args.days)
        for offset in range(args.days):
            target = start_date + timedelta(days=offset)
            _logger.info(
                "Backfill %d/%d: processing %s", offset + 1, args.days, target
            )
            kpi_engine.run_daily(target)
        _logger.info("Backfill complete: %d days processed", args.days)
