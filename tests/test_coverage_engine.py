"""Tests for engines.coverage_engine.CoverageEngine.

Database-dependent tests require DATABASE_URL and are skipped when absent.
The pure-Python test verifies SQLAlchemy's lazy engine creation.
"""

from __future__ import annotations

import os
from datetime import date

import pytest

from engines.coverage_engine import CoverageEngine

_DB_URL = os.environ.get("DATABASE_URL")
_NO_DB = not _DB_URL

_EMPTY_DATE = date(2099, 12, 31)


@pytest.fixture(scope="session")
def _engine():
    if _NO_DB:
        pytest.skip("DATABASE_URL not set")
    from ingestion.mitre_tagger import MitreTagger
    tagger = MitreTagger()
    return CoverageEngine(_DB_URL, tagger)


@pytest.mark.skipif(_NO_DB, reason="DATABASE_URL not set")
def test_calculate_coverage_returns_correct_keys(_engine: CoverageEngine):
    coverage = _engine.calculate_coverage()
    assert set(coverage.keys()) == {
        "total_techniques",
        "covered_techniques",
        "coverage_pct",
        "uncovered_tactics",
        "coverage_by_tactic",
    }


@pytest.mark.skipif(_NO_DB, reason="DATABASE_URL not set")
def test_coverage_pct_within_range(_engine: CoverageEngine):
    coverage = _engine.calculate_coverage()
    assert 0.0 <= coverage["coverage_pct"] <= 100.0


@pytest.mark.skipif(_NO_DB, reason="DATABASE_URL not set")
def test_coverage_by_tactic_structure(_engine: CoverageEngine):
    coverage = _engine.calculate_coverage()
    for tactic, stats in coverage["coverage_by_tactic"].items():
        assert isinstance(tactic, str)
        assert set(stats.keys()) == {"total", "covered", "pct"}
        assert stats["total"] >= stats["covered"] >= 0
        assert 0.0 <= stats["pct"] <= 100.0


@pytest.mark.skipif(_NO_DB, reason="DATABASE_URL not set")
def test_detect_regressions_no_previous_snapshot_returns_empty(_engine: CoverageEngine):
    result = _engine.detect_regressions(_EMPTY_DATE)
    assert result == []


@pytest.mark.skipif(_NO_DB, reason="DATABASE_URL not set")
def test_get_active_rules_filters_null_techniques(_engine: CoverageEngine):
    rules = _engine.get_active_rules()
    for rule in rules:
        assert rule["mitre_technique"] is not None
        assert rule["mitre_technique"] != ""


def test_invalid_db_url_does_not_raise_on_init():
    class _FakeTagger:
        _technique_by_id = {"T1059.001": {"name": "PowerShell", "tactic": "execution"}}

    engine = CoverageEngine("postgresql://fake:fake@localhost:5432/nonexistent", _FakeTagger())
    assert engine is not None
