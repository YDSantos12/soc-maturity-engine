"""Maps active detection rules to MITRE ATT&CK techniques and materializes
coverage snapshots into mitre_coverage_snapshots, enabling gap analysis and
regression detection in Grafana."""

from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Any

from sqlalchemy import create_engine, text

from ingestion.mitre_tagger import MitreTagger

_logger = logging.getLogger("soc_maturity.coverage_engine")

_ACTIVE_RULES_SQL = text("""
    SELECT DISTINCT ON (rule_name, source_system)
        rule_name, source_system, mitre_technique, mitre_tactic
    FROM alerts_normalized
    WHERE mitre_technique IS NOT NULL
      AND event_time >= NOW() - INTERVAL '30 days'
    ORDER BY rule_name, source_system
""")

_QUALITY_SCORES_SQL = text("""
    SELECT rule_name, quality_score
    FROM rule_performance_snapshots
    WHERE snapshot_date = :snapshot_date
      AND quality_score IS NOT NULL
""")

_REGRESSIONS_SQL = text("""
    SELECT t.mitre_technique, t.technique_name, t.mitre_tactic
    FROM mitre_coverage_snapshots t
    JOIN mitre_coverage_snapshots y
        ON y.mitre_technique = t.mitre_technique
    WHERE t.snapshot_date = :today
      AND y.snapshot_date  = :yesterday
      AND y.is_covered = TRUE
      AND t.is_covered = FALSE
""")

_UPSERT_COVERAGE_SQL = text("""
    INSERT INTO mitre_coverage_snapshots (
        snapshot_date, mitre_technique, mitre_tactic, technique_name,
        is_covered, active_rules, rule_names, coverage_quality
    ) VALUES (
        :snapshot_date, :mitre_technique, :mitre_tactic, :technique_name,
        :is_covered, :active_rules, :rule_names, :coverage_quality
    )
    ON CONFLICT (snapshot_date, mitre_technique) DO UPDATE SET
        mitre_tactic     = EXCLUDED.mitre_tactic,
        technique_name   = EXCLUDED.technique_name,
        is_covered       = EXCLUDED.is_covered,
        active_rules     = EXCLUDED.active_rules,
        rule_names       = EXCLUDED.rule_names,
        coverage_quality = EXCLUDED.coverage_quality
""")


class CoverageEngine:
    """Computes MITRE ATT&CK coverage from active detection rules and persists gap snapshots."""

    def __init__(self, db_url: str, mitre_tagger: MitreTagger) -> None:
        """Initialize with a connection pool and a pre-loaded ATT&CK tagger.

        Args:
            db_url: SQLAlchemy PostgreSQL connection string.
            mitre_tagger: Pre-instantiated MitreTagger whose technique cache is
                          reused — avoids re-loading the STIX bundle on each call.
        """
        self._engine = create_engine(db_url, pool_size=5, max_overflow=10)
        self._mitre_tagger = mitre_tagger

    def get_active_rules(self) -> list[dict[str, Any]]:
        """Return distinct rules with at least one alert in the last 30 days.

        Excludes rules without a MITRE technique — they cannot contribute to
        ATT&CK coverage calculations.

        Returns:
            List of dicts with keys rule_name, source_system, mitre_technique,
            mitre_tactic, ordered by rule_name.
        """
        with self._engine.connect() as conn:
            rows = conn.execute(_ACTIVE_RULES_SQL).mappings().fetchall()
        return [
            {
                "rule_name":       row["rule_name"],
                "source_system":   row["source_system"],
                "mitre_technique": row["mitre_technique"],
                "mitre_tactic":    row["mitre_tactic"],
            }
            for row in rows
        ]

    def calculate_coverage(self) -> dict[str, Any]:
        """Cross-reference active rules against the full ATT&CK Enterprise technique catalog.

        Returns:
            Dict with keys:
              - total_techniques (int): total techniques in the loaded STIX bundle.
              - covered_techniques (int): techniques matched by at least one active rule.
              - coverage_pct (float): rounded to 2 decimal places.
              - uncovered_tactics (list[str]): sorted tactics with zero covered techniques.
              - coverage_by_tactic (dict): per-tactic stats — total, covered, pct.
        """
        all_techniques = self._mitre_tagger._technique_by_id
        active_rules = self.get_active_rules()
        covered_ids = {r["mitre_technique"] for r in active_rules}

        total = len(all_techniques)
        covered = len(covered_ids & set(all_techniques.keys()))
        coverage_pct = round(covered / total * 100, 2) if total else 0.0

        tactic_totals: dict[str, int] = {}
        tactic_covered: dict[str, int] = {}
        for tid, info in all_techniques.items():
            tactic = info["tactic"] or "unknown"
            tactic_totals[tactic] = tactic_totals.get(tactic, 0) + 1
            if tid in covered_ids:
                tactic_covered[tactic] = tactic_covered.get(tactic, 0) + 1

        coverage_by_tactic = {
            tactic: {
                "total":   total_t,
                "covered": tactic_covered.get(tactic, 0),
                "pct":     round(tactic_covered.get(tactic, 0) / total_t * 100, 2) if total_t else 0.0,
            }
            for tactic, total_t in tactic_totals.items()
        }

        uncovered_tactics = sorted(
            tactic for tactic, v in coverage_by_tactic.items() if v["covered"] == 0
        )

        return {
            "total_techniques":   total,
            "covered_techniques": covered,
            "coverage_pct":       coverage_pct,
            "uncovered_tactics":  uncovered_tactics,
            "coverage_by_tactic": coverage_by_tactic,
        }

    def persist_coverage_snapshot(self, target_date: date) -> None:
        """Upsert a coverage row for every technique in the ATT&CK Enterprise catalog.

        coverage_quality is the mean quality_score of rules that cover each technique,
        sourced from rule_performance_snapshots for target_date. NULL when no quality
        snapshot exists for that date.

        Args:
            target_date: The date these coverage facts represent.
        """
        active_rules = self.get_active_rules()

        technique_to_rules: dict[str, list[str]] = {}
        for rule in active_rules:
            technique_to_rules.setdefault(rule["mitre_technique"], []).append(rule["rule_name"])

        with self._engine.connect() as conn:
            score_rows = conn.execute(
                _QUALITY_SCORES_SQL, {"snapshot_date": target_date}
            ).mappings().fetchall()

        quality_by_rule = {
            r["rule_name"]: float(r["quality_score"])
            for r in score_rows
        }

        with self._engine.begin() as conn:
            for tid, info in self._mitre_tagger._technique_by_id.items():
                rule_names = technique_to_rules.get(tid, [])
                scores = [quality_by_rule[r] for r in rule_names if r in quality_by_rule]
                coverage_quality = round(sum(scores) / len(scores), 2) if scores else None

                conn.execute(_UPSERT_COVERAGE_SQL, {
                    "snapshot_date":    target_date,
                    "mitre_technique":  tid,
                    "mitre_tactic":     info["tactic"] or None,
                    "technique_name":   info["name"],
                    "is_covered":       len(rule_names) > 0,
                    "active_rules":     len(rule_names),
                    "rule_names":       rule_names or None,
                    "coverage_quality": coverage_quality,
                })

        _logger.info(
            "Coverage snapshot persisted: date=%s, total_techniques=%d, covered=%d",
            target_date,
            len(self._mitre_tagger._technique_by_id),
            len(technique_to_rules),
        )

    def detect_regressions(self, current_date: date) -> list[dict[str, Any]]:
        """Find techniques that were covered yesterday but are not covered today.

        Args:
            current_date: The date to treat as 'today'.

        Returns:
            List of dicts with mitre_technique, technique_name, mitre_tactic.
            Empty list when no regressions or no previous snapshot to compare against.
        """
        yesterday = current_date - timedelta(days=1)
        with self._engine.connect() as conn:
            rows = conn.execute(
                _REGRESSIONS_SQL,
                {"today": current_date, "yesterday": yesterday},
            ).mappings().fetchall()
        return [
            {
                "mitre_technique": row["mitre_technique"],
                "technique_name":  row["technique_name"],
                "mitre_tactic":    row["mitre_tactic"],
            }
            for row in rows
        ]


if __name__ == "__main__":
    import argparse
    import os
    import traceback

    from dotenv import load_dotenv

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    load_dotenv()
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL environment variable is required")

    parser = argparse.ArgumentParser(description="SOC Coverage Engine")
    parser.add_argument(
        "--date",
        type=date.fromisoformat,
        default=date.today(),
        help="Target date YYYY-MM-DD (default: today)",
    )
    args = parser.parse_args()

    stix_path = os.environ.get("STIX_BUNDLE_PATH")
    tagger = MitreTagger(stix_path=stix_path)
    engine = CoverageEngine(db_url, tagger)

    coverage = engine.calculate_coverage()
    _logger.info(
        "Coverage: %d/%d techniques (%.2f%%) | uncovered tactics: %s",
        coverage["covered_techniques"],
        coverage["total_techniques"],
        coverage["coverage_pct"],
        coverage["uncovered_tactics"] or "none",
    )

    try:
        engine.persist_coverage_snapshot(args.date)
    except Exception:
        _logger.error("Failed to persist coverage snapshot:\n%s", traceback.format_exc())
        raise

    regressions = engine.detect_regressions(args.date)
    if regressions:
        _logger.warning(
            "%d coverage regression(s): %s",
            len(regressions),
            [r["mitre_technique"] for r in regressions],
        )
    else:
        _logger.info("No coverage regressions detected")
