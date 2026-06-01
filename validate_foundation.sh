#!/usr/bin/env bash
set -euo pipefail

POSTGRES_DB="${POSTGRES_DB:-socmaturity}"
POSTGRES_USER="${POSTGRES_USER:-socuser}"

EXPECTED_TABLES=("alerts_normalized" "rule_performance_snapshots" "mitre_coverage_snapshots" "analyst_metrics")
EXPECTED_VIEWS=("soc_daily_kpis")

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

fail() {
    echo -e "${RED}FOUNDATION FAILED: ${1}${NC}" >&2
    docker compose down --remove-orphans 2>/dev/null || true
    exit 1
}

echo "Starting postgres service..."
docker compose up postgres -d

echo "Waiting for healthcheck to pass..."
RETRIES=30
until [ "$(docker inspect --format='{{.State.Health.Status}}' "$(docker compose ps -q postgres)")" = "healthy" ]; do
    RETRIES=$((RETRIES - 1))
    if [ "$RETRIES" -eq 0 ]; then
        fail "postgres healthcheck timed out after 30 attempts"
    fi
    sleep 2
done
echo "postgres is healthy."

PSQL="docker compose exec -T postgres psql -U ${POSTGRES_USER} -d ${POSTGRES_DB} -t -A"

echo "Checking tables..."
FOUND_TABLES=$($PSQL -c "\dt" 2>&1) || fail "could not connect to postgres: ${FOUND_TABLES}"

for table in "${EXPECTED_TABLES[@]}"; do
    if ! echo "$FOUND_TABLES" | grep -q "${table}"; then
        fail "table '${table}' not found in schema. Found:\n${FOUND_TABLES}"
    fi
    echo "  [OK] table: ${table}"
done

echo "Checking views..."
FOUND_VIEWS=$($PSQL -c "\dv" 2>&1) || fail "could not query views: ${FOUND_VIEWS}"

for view in "${EXPECTED_VIEWS[@]}"; do
    if ! echo "$FOUND_VIEWS" | grep -q "${view}"; then
        fail "view '${view}' not found in schema. Found:\n${FOUND_VIEWS}"
    fi
    echo "  [OK] view:  ${view}"
done

echo "Verifying constraint on alerts_normalized.severity..."
INVALID_SEV=$($PSQL -c "INSERT INTO alerts_normalized (source_system, rule_name, severity, event_time) VALUES ('wazuh','test-rule','INVALID',NOW());" 2>&1 || true)
if ! echo "$INVALID_SEV" | grep -qi "violates check constraint\|check_constraint\|violates"; then
    fail "severity CHECK constraint did not fire: ${INVALID_SEV}"
fi
echo "  [OK] severity CHECK constraint is active"

echo "Verifying soc_daily_kpis view is queryable..."
VIEW_RESULT=$($PSQL -c "SELECT COUNT(*) FROM soc_daily_kpis;" 2>&1) || fail "soc_daily_kpis view query failed: ${VIEW_RESULT}"
echo "  [OK] soc_daily_kpis returned ${VIEW_RESULT} rows"

echo "Tearing down postgres..."
docker compose down --remove-orphans

echo -e "${GREEN}FOUNDATION OK${NC}"
