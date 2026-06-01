"""Enriches normalized alerts with MITRE ATT&CK technique and tactic metadata
by querying a cached lookup built from the local or downloaded STIX bundle."""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from pathlib import Path
from typing import Any


_logger = logging.getLogger("soc_maturity.ingestion")

_DEFAULT_BUNDLE_PATH = Path(__file__).parent.parent / "data" / "enterprise-attack.json"
_STIX_DOWNLOAD_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


class MitreTagger:
    """Enriches alert dicts with MITRE ATT&CK technique and tactic from a cached bundle."""

    _TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

    def __init__(self, stix_path: str | None = None) -> None:
        """Load the ATT&CK Enterprise STIX bundle and build lookup caches.

        Args:
            stix_path: Path to a local enterprise-attack.json file. When None,
                       falls back to data/enterprise-attack.json, then attempts
                       a one-time download from the MITRE GitHub repository.

        Raises:
            RuntimeError: If stix_path is None, the default bundle is absent,
                          and the download fails.
        """
        bundle = self._load_bundle(stix_path)
        self._technique_by_id: dict[str, dict[str, str]] = {}
        self._keyword_to_id: dict[str, str] = {}
        self._build_caches(bundle)
        _logger.info(
            "MitreTagger ready: %d techniques indexed", len(self._technique_by_id)
        )

    def tag(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Enrich alert dict with mitre_technique and mitre_tactic in-place.

        Enrichment priority:
        1. If mitre_technique already set, fill mitre_tactic only when absent.
        2. Regex match of T\\d{4}(.\\d{3})? pattern inside rule_name.
        3. Keyword match: substring of lowercase rule_name against technique names.

        Returns the same dict (modified in-place).
        """
        existing_technique = alert.get("mitre_technique")
        if existing_technique:
            if not alert.get("mitre_tactic"):
                info = self._technique_by_id.get(existing_technique)
                if info:
                    alert["mitre_tactic"] = info["tactic"] or None
            return alert

        rule_name = alert.get("rule_name") or ""

        regex_match = self._TECHNIQUE_RE.search(rule_name)
        if regex_match:
            tid = regex_match.group(0)
            info = self._technique_by_id.get(tid)
            if info:
                alert["mitre_technique"] = tid
                alert["mitre_tactic"] = info["tactic"] or None
            return alert

        rule_lower = rule_name.lower()
        for keyword, tid in self._keyword_to_id.items():
            if keyword in rule_lower:
                info = self._technique_by_id[tid]
                alert["mitre_technique"] = tid
                alert["mitre_tactic"] = info["tactic"] or None
                break

        return alert

    def get_technique_name(self, technique_id: str) -> str | None:
        """Return the human-readable technique name (e.g. 'Kerberoasting'), or None."""
        info = self._technique_by_id.get(technique_id)
        return info["name"] if info else None

    def _load_bundle(self, stix_path: str | None) -> dict[str, Any]:
        if stix_path is not None:
            with open(stix_path) as f:
                return json.load(f)

        if _DEFAULT_BUNDLE_PATH.exists():
            with _DEFAULT_BUNDLE_PATH.open() as f:
                return json.load(f)

        try:
            _logger.info("Downloading ATT&CK STIX bundle from MITRE GitHub...")
            with urllib.request.urlopen(_STIX_DOWNLOAD_URL, timeout=60) as resp:
                data = json.loads(resp.read())
            _DEFAULT_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with _DEFAULT_BUNDLE_PATH.open("w") as f:
                json.dump(data, f)
            return data
        except Exception as exc:
            raise RuntimeError(
                f"STIX bundle unavailable and download failed: {exc}. "
                f"Download manually: curl -Lo data/enterprise-attack.json {_STIX_DOWNLOAD_URL}"
            ) from exc

    def _build_caches(self, bundle: dict[str, Any]) -> None:
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern" or obj.get("revoked"):
                continue

            technique_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                None,
            )
            if not technique_id:
                continue

            name = obj.get("name", "")
            tactics = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]

            self._technique_by_id[technique_id] = {
                "name":   name,
                "tactic": tactics[0] if tactics else "",
            }

            name_lower = name.lower()
            if name_lower and name_lower not in self._keyword_to_id:
                self._keyword_to_id[name_lower] = technique_id
