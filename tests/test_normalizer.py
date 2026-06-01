"""Tests for ingestion.normalizer.AlertNormalizer: field extraction, severity
mapping, error conditions, and fallback behavior for Wazuh and CrowdStrike."""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from ingestion.normalizer import AlertNormalizer


_WAZUH_VALID = {
    "id": "wazuh-event-001",
    "timestamp": "2024-05-15T10:30:00.000+00:00",
    "rule": {
        "id": 100200,
        "description": "Suspicious PowerShell Encoded Command",
        "level": 12,
        "groups": ["powershell", "attack"],
        "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]},
    },
    "agent": {"name": "WIN-0042", "ip": "10.0.1.42"},
    "data": {"srcuser": "jsmith"},
}

_CROWDSTRIKE_BASE = {
    "DetectId": "cs-detect-001",
    "DetectName": "LSASS Memory Dump",
    "StartTimestamp": 1715768400000,
}


class TestWazuhNormalization:
    def setup_method(self):
        self.n = AlertNormalizer()

    def test_valid_payload_populates_required_fields(self):
        result = self.n.normalize(_WAZUH_VALID, "wazuh")
        assert result["rule_name"] == "Suspicious PowerShell Encoded Command"
        assert result["severity"] == "high"
        assert isinstance(result["event_time"], datetime)
        assert result["source_system"] == "wazuh"

    def test_missing_username_returns_none_without_exception(self):
        payload = {**_WAZUH_VALID, "data": {}}
        result = self.n.normalize(payload, "wazuh")
        assert result["username"] is None

    def test_level_3_maps_to_low(self):
        payload = {**_WAZUH_VALID, "rule": {**_WAZUH_VALID["rule"], "level": 3}}
        result = self.n.normalize(payload, "wazuh")
        assert result["severity"] == "low"

    def test_level_15_maps_to_critical(self):
        payload = {**_WAZUH_VALID, "rule": {**_WAZUH_VALID["rule"], "level": 15}}
        result = self.n.normalize(payload, "wazuh")
        assert result["severity"] == "critical"

    def test_level_9_maps_to_medium(self):
        payload = {**_WAZUH_VALID, "rule": {**_WAZUH_VALID["rule"], "level": 9}}
        result = self.n.normalize(payload, "wazuh")
        assert result["severity"] == "medium"


class TestCrowdStrikeNormalization:
    def setup_method(self):
        self.n = AlertNormalizer()

    def test_severity_6_maps_to_high(self):
        result = self.n.normalize({**_CROWDSTRIKE_BASE, "Severity": 6}, "crowdstrike")
        assert result["severity"] == "high"

    def test_severity_1_maps_to_info(self):
        result = self.n.normalize({**_CROWDSTRIKE_BASE, "Severity": 1}, "crowdstrike")
        assert result["severity"] == "info"

    def test_severity_9_maps_to_critical(self):
        result = self.n.normalize({**_CROWDSTRIKE_BASE, "Severity": 9}, "crowdstrike")
        assert result["severity"] == "critical"


class TestNormalizerErrors:
    def setup_method(self):
        self.n = AlertNormalizer()

    def test_unknown_source_system_raises_value_error(self):
        with pytest.raises(ValueError, match="splunk"):
            self.n.normalize({}, "splunk")

    def test_wazuh_missing_rule_description_raises_value_error(self):
        payload = {
            "rule": {"id": 100, "level": 10},
            "timestamp": "2024-01-01T00:00:00Z",
            "agent": {},
        }
        with pytest.raises(ValueError, match="rule.description"):
            self.n.normalize(payload, "wazuh")

    def test_wazuh_missing_timestamp_raises_value_error(self):
        payload = {
            "rule": {"id": 100, "description": "test rule", "level": 10},
            "agent": {},
        }
        with pytest.raises(ValueError):
            self.n.normalize(payload, "wazuh")

    def test_missing_id_field_generates_valid_uuid_fallback(self):
        payload = {k: v for k, v in _WAZUH_VALID.items() if k != "id"}
        result = self.n.normalize(payload, "wazuh")
        assert result["source_id"] is not None
        uuid.UUID(result["source_id"])
