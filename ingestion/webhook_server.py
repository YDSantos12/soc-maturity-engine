"""FastAPI ingestion server: normalizes alert payloads, enriches with MITRE ATT&CK,
and persists to PostgreSQL via direct SQL inserts."""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, text

from ingestion.mitre_tagger import MitreTagger
from ingestion.normalizer import AlertNormalizer

_logger = logging.getLogger("soc_maturity.ingestion")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

WAZUH_WEBHOOK_TOKEN = os.environ.get("WAZUH_WEBHOOK_TOKEN", "")

# Sync engine instead of asyncpg: ingestion queries are simple point-inserts
# that don't benefit from async overhead. FastAPI runs sync route functions in
# a threadpool, so the event loop is not blocked.
engine = create_engine(DATABASE_URL, pool_size=5, max_overflow=10)

_normalizer = AlertNormalizer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    tagger: MitreTagger | None = None
    stix_path = os.environ.get("STIX_BUNDLE_PATH")
    try:
        tagger = MitreTagger(stix_path=stix_path)
    except Exception as exc:
        _logger.warning("MITRE enrichment disabled — STIX load failed: %s", exc)
    app.state.mitre_tagger = tagger
    yield
    engine.dispose()


app = FastAPI(title="SOC Maturity Engine — Ingestion API", lifespan=lifespan)

_INSERT_ALERT = text("""
    INSERT INTO alerts_normalized (
        source_id, source_system, rule_name, rule_id, severity, category,
        mitre_technique, mitre_tactic, hostname, ip_address, username,
        event_time, status, assigned_to, acknowledged_at, closed_at, raw_payload
    ) VALUES (
        :source_id, :source_system, :rule_name, :rule_id, :severity, :category,
        :mitre_technique, :mitre_tactic, :hostname,
        CASE WHEN :ip_address IS NULL THEN NULL ELSE :ip_address::inet END,
        :username, :event_time, :status, :assigned_to,
        :acknowledged_at, :closed_at, :raw_payload::jsonb
    )
    ON CONFLICT DO NOTHING
    RETURNING id
""")


def _persist(raw_alert: dict[str, Any], source_system: str) -> str | None:
    tagger: MitreTagger | None = app.state.mitre_tagger
    normalized = _normalizer.normalize(raw_alert, source_system)
    if tagger is not None:
        tagger.tag(normalized)
    params = dict(normalized)
    params["raw_payload"] = json.dumps(params.get("raw_payload") or {})
    with engine.begin() as conn:
        result = conn.execute(_INSERT_ALERT, params)
        row = result.fetchone()
    return str(row[0]) if row else None


def _token_valid(x_webhook_token: str) -> bool:
    return not WAZUH_WEBHOOK_TOKEN or x_webhook_token == WAZUH_WEBHOOK_TOKEN


@app.post("/ingest/wazuh")
def ingest_wazuh(
    payload: dict[str, Any],
    x_webhook_token: str = Header(default=""),
) -> JSONResponse:
    """Ingest a raw Wazuh alert. Requires X-Webhook-Token header."""
    if not _token_valid(x_webhook_token):
        return JSONResponse({"status": "error", "detail": "Invalid webhook token"}, status_code=401)
    try:
        alert_id = _persist(payload, "wazuh")
        return JSONResponse({"status": "ok", "alert_id": alert_id})
    except ValueError as exc:
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=422)


@app.post("/ingest/crowdstrike")
def ingest_crowdstrike(
    payload: dict[str, Any],
    x_webhook_token: str = Header(default=""),
) -> JSONResponse:
    """Ingest a raw CrowdStrike detection. Requires X-Webhook-Token header."""
    if not _token_valid(x_webhook_token):
        return JSONResponse({"status": "error", "detail": "Invalid webhook token"}, status_code=401)
    try:
        alert_id = _persist(payload, "crowdstrike")
        return JSONResponse({"status": "ok", "alert_id": alert_id})
    except ValueError as exc:
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=422)


class _GenericIngestBody(BaseModel):
    source_system: str
    alert: dict[str, Any]


@app.post("/ingest/generic", summary="Internal: no-auth ingest for simulator and integration tests")
def ingest_generic(body: _GenericIngestBody) -> JSONResponse:
    """Ingest an alert for any supported source_system. No authentication required."""
    try:
        alert_id = _persist(body.alert, body.source_system)
        return JSONResponse({"status": "ok", "alert_id": alert_id})
    except ValueError as exc:
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=422)


@app.get("/health")
def health() -> JSONResponse:
    """Liveness and database connectivity check."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return JSONResponse({"status": "ok", "db": "connected"})
    except Exception:
        return JSONResponse({"status": "degraded", "db": "unreachable"}, status_code=503)
