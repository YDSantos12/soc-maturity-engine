"""Transforms raw alert payloads from Wazuh, CrowdStrike, and simulator
into the unified alerts_normalized schema for database persistence."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any


_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _wazuh_level_to_severity(level: int) -> str:
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 8:
        return "medium"
    if level >= 3:
        return "low"
    return "info"


def _crowdstrike_int_to_severity(value: int) -> str:
    if value >= 8:
        return "critical"
    if value >= 6:
        return "high"
    if value >= 4:
        return "medium"
    if value >= 2:
        return "low"
    return "info"


_CROWDSTRIKE_STRING_SEVERITY: dict[str, int] = {
    "Critical":      9,
    "High":          7,
    "Medium":        5,
    "Low":           3,
    "Informational": 1,
}


def _parse_iso_timestamp(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _empty_row(source_system: str) -> dict[str, Any]:
    return {
        "source_id":       None,
        "source_system":   source_system,
        "rule_name":       None,
        "rule_id":         None,
        "severity":        None,
        "category":        None,
        "mitre_technique": None,
        "mitre_tactic":    None,
        "hostname":        None,
        "ip_address":      None,
        "username":        None,
        "event_time":      None,
        "status":          "new",
        "assigned_to":     None,
        "acknowledged_at": None,
        "closed_at":       None,
        "raw_payload":     None,
    }


class AlertNormalizer:
    """Maps raw source payloads to the alerts_normalized column schema."""

    def normalize(self, raw_alert: dict[str, Any], source_system: str) -> dict[str, Any]:
        """Normalize a raw alert payload into the alerts_normalized column mapping.

        Args:
            raw_alert: The raw JSON payload from the source system.
            source_system: One of 'wazuh', 'crowdstrike', or 'simulator'.

        Returns:
            Dict with keys matching alerts_normalized columns, ready for INSERT.

        Raises:
            ValueError: If source_system is unsupported, rule_name cannot be
                        extracted, or event_time is missing or unparseable.
        """
        handlers = {
            "wazuh":       self._normalize_wazuh,
            "crowdstrike": self._normalize_crowdstrike,
            "simulator":   self._normalize_simulator,
        }
        handler = handlers.get(source_system)
        if handler is None:
            raise ValueError(
                f"Unsupported source_system '{source_system}'. "
                f"Expected one of: {sorted(handlers)}"
            )
        return handler(raw_alert)

    def _normalize_wazuh(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        rule = raw_alert.get("rule") or {}
        agent = raw_alert.get("agent") or {}
        data = raw_alert.get("data") or {}

        rule_name = rule.get("description")
        if not rule_name:
            raise ValueError("Wazuh payload missing required field 'rule.description'")

        raw_ts = raw_alert.get("timestamp") or raw_alert.get("@timestamp")
        if not raw_ts:
            raise ValueError("Wazuh payload missing required field 'timestamp'")
        try:
            event_time = _parse_iso_timestamp(raw_ts)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Cannot parse Wazuh timestamp '{raw_ts}': {exc}") from exc

        mitre = rule.get("mitre") or {}
        technique_ids = mitre.get("id") or []
        tactic_names = mitre.get("tactic") or []

        win_eventdata = (data.get("win") or {}).get("eventdata") or {}
        username = data.get("srcuser") or win_eventdata.get("subjectUserName") or None

        groups = rule.get("groups") or []

        row = _empty_row("wazuh")
        row.update({
            "source_id":       raw_alert.get("id") or str(uuid.uuid4()),
            "rule_name":       rule_name,
            "rule_id":         str(rule["id"]) if rule.get("id") is not None else None,
            "severity":        _wazuh_level_to_severity(int(rule.get("level") or 0)),
            "category":        groups[0] if groups else None,
            "mitre_technique": technique_ids[0] if technique_ids else None,
            "mitre_tactic":    tactic_names[0].lower().replace(" ", "-") if tactic_names else None,
            "hostname":        agent.get("name"),
            "ip_address":      agent.get("ip"),
            "username":        username,
            "event_time":      event_time,
            "raw_payload":     raw_alert,
        })
        return row

    def _normalize_crowdstrike(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        rule_name = raw_alert.get("DetectName") or raw_alert.get("CompositeId")
        if not rule_name:
            raise ValueError(
                "CrowdStrike payload missing required field 'DetectName' or 'CompositeId'"
            )

        raw_ts = raw_alert.get("StartTimestamp") or raw_alert.get("ProcessStartTime")
        if raw_ts is None:
            raise ValueError(
                "CrowdStrike payload missing required field 'StartTimestamp' or 'ProcessStartTime'"
            )

        if isinstance(raw_ts, (int, float)):
            event_time = datetime.fromtimestamp(raw_ts / 1000, tz=timezone.utc)
        else:
            try:
                event_time = _parse_iso_timestamp(str(raw_ts))
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Cannot parse CrowdStrike timestamp '{raw_ts}': {exc}"
                ) from exc

        raw_severity = raw_alert.get("Severity", 1)
        if isinstance(raw_severity, str):
            raw_severity = _CROWDSTRIKE_STRING_SEVERITY.get(raw_severity, 1)

        device = raw_alert.get("DeviceDetails") or {}
        hostname = raw_alert.get("ComputerName") or device.get("hostname")

        row = _empty_row("crowdstrike")
        row.update({
            "source_id":  raw_alert.get("id") or raw_alert.get("DetectId") or str(uuid.uuid4()),
            "rule_name":  rule_name,
            "rule_id":    raw_alert.get("DetectId"),
            "severity":   _crowdstrike_int_to_severity(int(raw_severity)),
            "hostname":   hostname,
            "username":   raw_alert.get("UserName"),
            "event_time": event_time,
            "raw_payload": raw_alert,
        })
        return row

    def _normalize_simulator(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        rule_name = raw_alert.get("rule_name")
        if not rule_name:
            raise ValueError("Simulator payload missing required field 'rule_name'")

        event_time = raw_alert.get("event_time")
        if not event_time:
            raise ValueError("Simulator payload missing required field 'event_time'")
        if isinstance(event_time, str):
            try:
                event_time = _parse_iso_timestamp(event_time)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Cannot parse simulator event_time '{event_time}': {exc}"
                ) from exc

        row = _empty_row("simulator")
        row.update({
            "source_id":       raw_alert.get("id") or str(uuid.uuid4()),
            "rule_name":       rule_name,
            "rule_id":         raw_alert.get("rule_id"),
            "severity":        raw_alert.get("severity", "info"),
            "category":        raw_alert.get("category"),
            "mitre_technique": raw_alert.get("mitre_technique"),
            "mitre_tactic":    raw_alert.get("mitre_tactic"),
            "hostname":        raw_alert.get("hostname"),
            "ip_address":      raw_alert.get("ip_address"),
            "username":        raw_alert.get("username"),
            "event_time":      event_time,
            "status":          raw_alert.get("status", "new"),
            "assigned_to":     raw_alert.get("assigned_to"),
            "acknowledged_at": raw_alert.get("acknowledged_at"),
            "closed_at":       raw_alert.get("closed_at"),
            "raw_payload":     raw_alert,
        })
        return row
