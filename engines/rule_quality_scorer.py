"""Assigns a composite quality score to detection rules based on operational metrics."""

from __future__ import annotations

import logging

_logger = logging.getLogger("soc_maturity.kpi_engine")


class RuleQualityScorer:
    """Scores detection rules and classifies them by operational quality tier."""

    def score(self, rule_snapshot: dict) -> float:
        """Compute a quality score in [0.0, 100.0] for a single rule snapshot.

        Starts at 100.0 and applies the following adjustments:

        Penalty 1 — High FP rate:
            If fp_rate > 50, subtract (fp_rate - 50) * 1.2. Gradual penalty
            because a rule that is mostly FP still produces some TP value.

        Penalty 2 — High volume with zero TP:
            If total_alerts > 50 and tp_count == 0, subtract 30. This pattern
            is the clearest signal of pure noise.

        Penalty 3 — Most alerts left unclosed:
            If open_count / total_alerts > 0.8, subtract 15. A rule whose
            alerts are systematically ignored has no practical detection value.

        Penalty 4 — Slow resolution time:
            If avg_mttr_min > 480, subtract min((avg_mttr_min - 480) / 480 * 10, 10).
            Capped at 10 points to avoid dominating the score for single outliers.

        Bonus — Confirmed high-precision rule:
            If tp_count > 0 and fp_rate < 10, add 10.

        Fields that are None skip the corresponding penalty or bonus.

        Args:
            rule_snapshot: Dict from calculate_rule_performance, optionally
                           with quality_score already populated (will be overwritten).

        Returns:
            Float clamped to [0.0, 100.0].
        """
        result = 100.0

        fp_rate = rule_snapshot.get("fp_rate")
        total_alerts = rule_snapshot.get("total_alerts") or 0
        tp_count = rule_snapshot.get("tp_count") or 0
        open_count = rule_snapshot.get("open_count") or 0
        avg_mttr_min = rule_snapshot.get("avg_mttr_min")

        if fp_rate is not None and fp_rate > 50.0:
            result -= (fp_rate - 50.0) * 1.2

        if total_alerts > 50 and tp_count == 0:
            result -= 30.0

        if total_alerts > 0 and (open_count / total_alerts) > 0.8:
            result -= 15.0

        if avg_mttr_min is not None and avg_mttr_min > 480:
            result -= min((avg_mttr_min - 480) / 480 * 10, 10.0)

        if tp_count > 0 and fp_rate is not None and fp_rate < 10.0:
            result += 10.0

        return max(0.0, min(100.0, result))

    def classify(self, score: float) -> str:
        """Map a numeric score to a quality tier label.

        Args:
            score: Value in [0.0, 100.0].

        Returns:
            'excellent' (>=80), 'good' (>=60), 'noisy' (>=35), or 'critical' (<35).
        """
        if score >= 80:
            return "excellent"
        if score >= 60:
            return "good"
        if score >= 35:
            return "noisy"
        return "critical"
