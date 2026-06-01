"""Generates synthetic SOC alert data with realistic distributions: per-rule severity
weights, MITRE ATT&CK coverage, business-hours concentration, and Poisson volume."""

from __future__ import annotations

import hashlib
import logging
import math
import random
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any

import psycopg2
import psycopg2.extras

_logger = logging.getLogger("soc_maturity.simulator")

_HOSTNAMES = [
    "CORP-WS-001", "CORP-WS-002", "CORP-WS-003", "CORP-WS-004", "CORP-WS-005",
    "CORP-WS-006", "CORP-WS-007", "CORP-WS-008", "CORP-WS-009", "CORP-WS-010",
    "SRV-DC-01", "SRV-SQL-01", "SRV-FILE-01", "SRV-APP-01", "SRV-MGMT-01",
    "SRV-BACKUP-01", "SRV-EXCHANGE-01", "SRV-PROXY-01", "SRV-MONITOR-01", "SRV-JUMP-01",
]

_USERNAMES = [
    "j.silva", "m.santos", "r.costa", "a.oliveira",
    "c.ferreira", "l.souza", "p.rodrigues", "t.lima",
    "svc-backup", "svc-monitoring", "svc-deploy", "corp-admin",
]

def _rule_id(rule_name: str) -> str:
    return "sigma-" + hashlib.md5(rule_name.encode()).hexdigest()[:6]


_RAW_CATALOG: list[dict[str, Any]] = [
    {
        "rule_name":        "Valid Account Login Outside Business Hours",
        "source_system":    "simulator",
        "severity_weights": {"high": 0.3, "medium": 0.5, "low": 0.2},
        "mitre_technique":  "T1078",
        "mitre_tactic":     "initial-access",
        "fp_probability":   0.55,
        "avg_daily_volume": 15,
        "category":         "identity",
    },
    {
        "rule_name":        "Phishing Email Attachment Executed",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.2, "high": 0.6, "medium": 0.2},
        "mitre_technique":  "T1566.001",
        "mitre_tactic":     "initial-access",
        "fp_probability":   0.25,
        "avg_daily_volume": 5,
        "category":         "email",
    },
    {
        "rule_name":        "Suspicious PowerShell Encoded Command",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.2, "high": 0.5, "medium": 0.3},
        "mitre_technique":  "T1059.001",
        "mitre_tactic":     "execution",
        "fp_probability":   0.30,
        "avg_daily_volume": 25,
        "category":         "endpoint",
    },
    {
        "rule_name":        "WMI Remote Command Execution",
        "source_system":    "simulator",
        "severity_weights": {"high": 0.6, "medium": 0.3, "low": 0.1},
        "mitre_technique":  "T1047",
        "mitre_tactic":     "execution",
        "fp_probability":   0.35,
        "avg_daily_volume": 10,
        "category":         "endpoint",
    },
    {
        "rule_name":        "CMD Shell Spawned by Office Application",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.15, "high": 0.65, "medium": 0.2},
        "mitre_technique":  "T1059.003",
        "mitre_tactic":     "execution",
        "fp_probability":   0.20,
        "avg_daily_volume": 8,
        "category":         "endpoint",
    },
    {
        "rule_name":        "Scheduled Task Created by Non-Admin User",
        "source_system":    "simulator",
        "severity_weights": {"high": 0.3, "medium": 0.5, "low": 0.2},
        "mitre_technique":  "T1053.005",
        "mitre_tactic":     "persistence",
        "fp_probability":   0.45,
        "avg_daily_volume": 12,
        "category":         "persistence",
    },
    {
        "rule_name":        "Registry Run Key Added for Persistence",
        "source_system":    "simulator",
        "severity_weights": {"medium": 0.5, "low": 0.35, "info": 0.15},
        "mitre_technique":  "T1547.001",
        "mitre_tactic":     "persistence",
        "fp_probability":   0.65,
        "avg_daily_volume": 18,
        "category":         "persistence",
    },
    {
        "rule_name":        "UAC Bypass via Event Viewer Exploit",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.5, "high": 0.5},
        "mitre_technique":  "T1548.002",
        "mitre_tactic":     "privilege-escalation",
        "fp_probability":   0.10,
        "avg_daily_volume": 3,
        "category":         "privilege-escalation",
    },
    {
        "rule_name":        "Token Impersonation by Non-System Process",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.4, "high": 0.6},
        "mitre_technique":  "T1134",
        "mitre_tactic":     "privilege-escalation",
        "fp_probability":   0.15,
        "avg_daily_volume": 4,
        "category":         "privilege-escalation",
    },
    {
        "rule_name":        "LSASS Memory Access Detected",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.8, "high": 0.2},
        "mitre_technique":  "T1003.001",
        "mitre_tactic":     "credential-access",
        "fp_probability":   0.05,
        "avg_daily_volume": 2,
        "category":         "credential-access",
    },
    {
        "rule_name":        "Multiple Failed Login Attempts Detected",
        "source_system":    "simulator",
        "severity_weights": {"medium": 0.6, "low": 0.3, "high": 0.1},
        "mitre_technique":  "T1110",
        "mitre_tactic":     "credential-access",
        "fp_probability":   0.70,
        "avg_daily_volume": 60,
        "category":         "identity",
    },
    {
        "rule_name":        "Kerberoasting SPN Enumeration",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.3, "high": 0.7},
        "mitre_technique":  "T1558.003",
        "mitre_tactic":     "credential-access",
        "fp_probability":   0.12,
        "avg_daily_volume": 3,
        "category":         "credential-access",
    },
    {
        "rule_name":        "RDP Connection from Unusual Source Host",
        "source_system":    "simulator",
        "severity_weights": {"high": 0.5, "medium": 0.4, "low": 0.1},
        "mitre_technique":  "T1021.001",
        "mitre_tactic":     "lateral-movement",
        "fp_probability":   0.50,
        "avg_daily_volume": 8,
        "category":         "lateral-movement",
    },
    {
        "rule_name":        "Pass-the-Hash Attack Detected",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.7, "high": 0.3},
        "mitre_technique":  "T1550.002",
        "mitre_tactic":     "lateral-movement",
        "fp_probability":   0.08,
        "avg_daily_volume": 2,
        "category":         "lateral-movement",
    },
    {
        "rule_name":        "Account and Group Discovery Commands Executed",
        "source_system":    "simulator",
        "severity_weights": {"low": 0.5, "medium": 0.35, "info": 0.15},
        "mitre_technique":  "T1087",
        "mitre_tactic":     "discovery",
        "fp_probability":   0.75,
        "avg_daily_volume": 40,
        "category":         "discovery",
    },
    {
        "rule_name":        "Internal Network Port Scan Detected",
        "source_system":    "simulator",
        "severity_weights": {"medium": 0.4, "low": 0.45, "info": 0.15},
        "mitre_technique":  "T1046",
        "mitre_tactic":     "discovery",
        "fp_probability":   0.65,
        "avg_daily_volume": 35,
        "category":         "discovery",
    },
    {
        "rule_name":        "Sensitive File Access on Domain Controller",
        "source_system":    "simulator",
        "severity_weights": {"high": 0.5, "medium": 0.4, "critical": 0.1},
        "mitre_technique":  "T1005",
        "mitre_tactic":     "collection",
        "fp_probability":   0.20,
        "avg_daily_volume": 6,
        "category":         "collection",
    },
    {
        "rule_name":        "Clipboard Data Harvesting by Unusual Process",
        "source_system":    "simulator",
        "severity_weights": {"medium": 0.5, "high": 0.3, "low": 0.2},
        "mitre_technique":  "T1115",
        "mitre_tactic":     "collection",
        "fp_probability":   0.35,
        "avg_daily_volume": 4,
        "category":         "collection",
    },
    {
        "rule_name":        "Large Data Upload to Cloud Storage Service",
        "source_system":    "simulator",
        "severity_weights": {"high": 0.4, "medium": 0.45, "low": 0.15},
        "mitre_technique":  "T1567",
        "mitre_tactic":     "exfiltration",
        "fp_probability":   0.40,
        "avg_daily_volume": 7,
        "category":         "exfiltration",
    },
    {
        "rule_name":        "Data Exfiltration over Alternative Protocol",
        "source_system":    "simulator",
        "severity_weights": {"critical": 0.3, "high": 0.6, "medium": 0.1},
        "mitre_technique":  "T1048",
        "mitre_tactic":     "exfiltration",
        "fp_probability":   0.15,
        "avg_daily_volume": 3,
        "category":         "exfiltration",
    },
]

_RULE_CATALOG: list[dict[str, Any]] = [
    {**r, "rule_id": _rule_id(r["rule_name"])} for r in _RAW_CATALOG
]

_INSERT_SQL = """
    INSERT INTO alerts_normalized (
        id, source_id, source_system, rule_name, rule_id, severity, category,
        mitre_technique, mitre_tactic, hostname, ip_address, username,
        event_time, ingested_at, status, acknowledged_at, closed_at, raw_payload
    ) VALUES %s
    ON CONFLICT (id) DO NOTHING
"""

_INSERT_TEMPLATE = (
    "(%(id)s, %(source_id)s, %(source_system)s, %(rule_name)s, %(rule_id)s,"
    " %(severity)s, %(category)s, %(mitre_technique)s, %(mitre_tactic)s,"
    " %(hostname)s, %(ip_address)s::inet, %(username)s,"
    " %(event_time)s, %(ingested_at)s, %(status)s,"
    " %(acknowledged_at)s, %(closed_at)s, %(raw_payload)s)"
)


def _poisson(lam: float) -> int:
    """Sample from Poisson(lam) using Knuth's algorithm for lam <= 30, normal approximation otherwise."""
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, round(random.gauss(lam, lam ** 0.5)))
    L = math.exp(-lam)
    k, p = 0, 1.0
    while True:
        k += 1
        p *= random.random()
        if p <= L:
            return k - 1


def _random_event_time(target_date: date) -> datetime:
    if random.random() < 0.70:
        minutes = random.randint(8 * 60, 18 * 60 - 1)
    else:
        off_minutes = random.randint(0, 839)
        minutes = off_minutes if off_minutes < 480 else 18 * 60 + (off_minutes - 480)
    hour, minute = divmod(minutes, 60)
    return datetime(
        target_date.year, target_date.month, target_date.day,
        hour, minute, random.randint(0, 59), tzinfo=timezone.utc,
    )


def _get_ip(hostname: str) -> str:
    if hostname.startswith("CORP-WS"):
        return f"10.10.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return f"10.20.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _build_alert(rule: dict[str, Any], target_date: date) -> dict[str, Any]:
    hostname = random.choice(_HOSTNAMES)
    event_time = _random_event_time(target_date)

    is_tp = random.random() > rule["fp_probability"]
    is_open = random.random() < 0.20

    if is_open:
        status = "new"
        acknowledged_at = None
        closed_at = None
    elif is_tp:
        status = "escalated" if random.random() < 0.10 else "closed_tp"
        acknowledged_at = event_time + timedelta(minutes=random.randint(5, 90))
        closed_at = (
            acknowledged_at + timedelta(minutes=random.randint(15, 360))
            if status == "closed_tp" else None
        )
    else:
        status = "closed_benign" if random.random() < 0.30 else "closed_fp"
        acknowledged_at = event_time + timedelta(minutes=random.randint(5, 90))
        closed_at = acknowledged_at + timedelta(minutes=random.randint(15, 360))

    severity = random.choices(
        list(rule["severity_weights"].keys()),
        weights=list(rule["severity_weights"].values()),
        k=1,
    )[0]

    return {
        "id":              str(uuid.uuid4()),
        "source_id":       str(uuid.uuid4()),
        "source_system":   rule["source_system"],
        "rule_name":       rule["rule_name"],
        "rule_id":         rule["rule_id"],
        "severity":        severity,
        "category":        rule["category"],
        "mitre_technique": rule["mitre_technique"],
        "mitre_tactic":    rule["mitre_tactic"],
        "hostname":        hostname,
        "ip_address":      _get_ip(hostname),
        "username":        random.choice(_USERNAMES),
        "event_time":      event_time.isoformat(),
        "ingested_at":     (event_time + timedelta(seconds=random.randint(1, 30))).isoformat(),
        "status":          status,
        "acknowledged_at": acknowledged_at.isoformat() if acknowledged_at else None,
        "closed_at":       closed_at.isoformat() if closed_at else None,
        "raw_payload":     None,
    }


class AlertSimulator:
    """Generates and persists synthetic SOC alerts using the rule catalog."""

    def __init__(self, db_url: str) -> None:
        """Store the database URL for use in run() and clear().

        Args:
            db_url: psycopg2-compatible PostgreSQL connection string.
        """
        self._db_url = db_url

    def run(self, days: int = 30, multiplier: float = 1.0) -> int:
        """Generate and insert alerts for the past N days.

        Volume per rule per day is sampled from Poisson(avg_daily_volume * multiplier).
        All inserts for each day are batched via execute_values.

        Args:
            days: Number of past days to simulate (today - days to today - 1).
            multiplier: Scales avg_daily_volume for all rules uniformly.

        Returns:
            Total number of rows inserted.
        """
        today = date.today()
        total_inserted = 0

        conn = psycopg2.connect(self._db_url)
        try:
            with conn:
                cur = conn.cursor()
                try:
                    for i in range(1, days + 1):
                        target_date = today - timedelta(days=days - i + 1)
                        day_alerts: list[dict[str, Any]] = []

                        for rule in _RULE_CATALOG:
                            count = _poisson(rule["avg_daily_volume"] * multiplier)
                            for _ in range(count):
                                day_alerts.append(_build_alert(rule, target_date))

                        if day_alerts:
                            psycopg2.extras.execute_values(
                                cur, _INSERT_SQL, day_alerts, template=_INSERT_TEMPLATE
                            )
                            total_inserted += len(day_alerts)

                        if i % 5 == 0:
                            _logger.info(
                                "Progress: %d/%d days processed (last: %s)",
                                i, days, target_date,
                            )
                finally:
                    cur.close()
        finally:
            conn.close()

        _logger.info(
            "Simulation complete: %d alerts inserted over %d days", total_inserted, days
        )
        return total_inserted

    def clear(self) -> None:
        """Delete all alerts with source_system='simulator' after interactive confirmation.

        Prompts the user before executing the DELETE. Logs the number of rows removed.
        """
        confirm = input("This will delete ALL simulator alerts. Type 'yes' to confirm: ")
        if confirm.strip().lower() != "yes":
            _logger.info("Clear cancelled by user")
            return

        conn = psycopg2.connect(self._db_url)
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM alerts_normalized WHERE source_system = 'simulator'"
                    )
                    deleted = cur.rowcount
        finally:
            conn.close()

        _logger.info("Deleted %d simulator alerts", deleted)


if __name__ == "__main__":
    import argparse
    import os

    from dotenv import load_dotenv

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    load_dotenv()
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL environment variable is required")

    parser = argparse.ArgumentParser(description="SOC Alert Simulator")
    parser.add_argument("--days",       type=int,   default=30,  help="Days of history to generate")
    parser.add_argument("--multiplier", type=float, default=1.0, help="Volume multiplier per rule")
    parser.add_argument("--clear",      action="store_true",     help="Delete all simulator alerts")
    args = parser.parse_args()

    simulator = AlertSimulator(db_url)

    if args.clear:
        simulator.clear()
    else:
        simulator.run(days=args.days, multiplier=args.multiplier)
