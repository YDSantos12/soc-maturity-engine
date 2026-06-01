"""Tests for engines.kpi_engine.KpiEngine and engines.rule_quality_scorer.RuleQualityScorer.

Database-dependent tests require DATABASE_URL and are skipped when absent.
All RuleQualityScorer tests are pure-Python and need no external services.
"""

from __future__ import annotations

import os
from datetime import date

import pytest

from engines.kpi_engine import KpiEngine
from engines.rule_quality_scorer import RuleQualityScorer

_DB_URL = os.environ.get("DATABASE_URL")
_NO_DB = not _DB_URL

_EMPTY_DATE = date(2099, 12, 31)



@pytest.mark.skipif(_NO_DB, reason="DATABASE_URL not set")
def test_snapshot_empty_date_returns_all_expected_keys():
    engine = KpiEngine(_DB_URL)
    snapshot = engine.calculate_daily_snapshot(_EMPTY_DATE)
    expected_keys = {
        "total_alerts", "critical_count", "high_count", "medium_count",
        "low_count", "true_positives", "false_positives", "benign_closed",
        "open_alerts", "avg_mttd_min", "avg_mttr_min",
        "fp_rate_pct", "alert_fatigue_ratio",
    }
    assert set(snapshot.keys()) == expected_keys
    for key in (
        "total_alerts", "critical_count", "high_count", "medium_count",
        "low_count", "true_positives", "false_positives", "benign_closed",
        "open_alerts",
    ):
        assert snapshot[key] == 0
    for key in ("avg_mttd_min", "avg_mttr_min", "fp_rate_pct", "alert_fatigue_ratio"):
        assert snapshot[key] is None


@pytest.mark.skipif(_NO_DB, reason="DATABASE_URL not set")
def test_fp_rate_pct_is_none_when_no_closed_alerts():
    engine = KpiEngine(_DB_URL)
    snapshot = engine.calculate_daily_snapshot(_EMPTY_DATE)
    assert snapshot["fp_rate_pct"] is None


@pytest.mark.skipif(_NO_DB, reason="DATABASE_URL not set")
def test_alert_fatigue_ratio_is_none_when_no_true_positives():
    engine = KpiEngine(_DB_URL)
    snapshot = engine.calculate_daily_snapshot(_EMPTY_DATE)
    assert snapshot["alert_fatigue_ratio"] is None


class TestRuleQualityScorerBounds:
    def test_score_within_bounds_for_all_zero_inputs(self):
        scorer = RuleQualityScorer()
        snapshot = {
            "fp_rate": 0.0, "total_alerts": 0, "tp_count": 0,
            "open_count": 0, "avg_mttr_min": None,
        }
        score = scorer.score(snapshot)
        assert 0.0 <= score <= 100.0

    def test_score_within_bounds_for_worst_case_inputs(self):
        scorer = RuleQualityScorer()
        snapshot = {
            "fp_rate": 100.0, "total_alerts": 1000, "tp_count": 0,
            "open_count": 900, "avg_mttr_min": 9999.0,
        }
        score = scorer.score(snapshot)
        assert 0.0 <= score <= 100.0

    def test_score_within_bounds_for_best_case_inputs(self):
        scorer = RuleQualityScorer()
        snapshot = {
            "fp_rate": 0.0, "total_alerts": 100, "tp_count": 100,
            "open_count": 0, "avg_mttr_min": 5.0,
        }
        score = scorer.score(snapshot)
        assert 0.0 <= score <= 100.0


class TestRuleQualityScorerClassify:
    def test_85_is_excellent(self):
        assert RuleQualityScorer().classify(85.0) == "excellent"

    def test_65_is_good(self):
        assert RuleQualityScorer().classify(65.0) == "good"

    def test_40_is_noisy(self):
        assert RuleQualityScorer().classify(40.0) == "noisy"

    def test_20_is_critical(self):
        assert RuleQualityScorer().classify(20.0) == "critical"


class TestRuleQualityScorerScoring:
    def test_pure_noise_rule_is_critical(self):
        scorer = RuleQualityScorer()
        snapshot = {
            "fp_rate": 80.0, "total_alerts": 100, "tp_count": 0,
            "open_count": 20, "avg_mttr_min": None,
        }
        score = scorer.score(snapshot)
        assert score < 35
        assert scorer.classify(score) == "critical"

    def test_high_quality_rule_is_excellent(self):
        scorer = RuleQualityScorer()
        snapshot = {
            "fp_rate": 5.0, "total_alerts": 50, "tp_count": 10,
            "open_count": 5, "avg_mttr_min": 120.0,
        }
        score = scorer.score(snapshot)
        assert score >= 80
        assert scorer.classify(score) == "excellent"

    def test_none_fields_do_not_raise(self):
        scorer = RuleQualityScorer()
        snapshot = {
            "fp_rate": None, "total_alerts": 10, "tp_count": 0,
            "open_count": 0, "avg_mttr_min": None,
        }
        score = scorer.score(snapshot)
        assert 0.0 <= score <= 100.0
