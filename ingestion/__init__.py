"""Ingestion layer: receives raw alerts from external sources, normalizes them, and persists to the database."""

from ingestion.mitre_tagger import MitreTagger
from ingestion.normalizer import AlertNormalizer

__all__ = ["AlertNormalizer", "MitreTagger"]
