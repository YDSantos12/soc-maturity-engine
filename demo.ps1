$envVars = @{}
if (Test-Path ".env") {
    Get-Content ".env" | ForEach-Object {
        if ($_ -match '^\s*([^#=\s][^=]*?)\s*=\s*(.*)$') {
            $envVars[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
}

$pgUser     = if ($envVars["POSTGRES_USER"])     { $envVars["POSTGRES_USER"] }     else { "socuser" }
$pgPassword = if ($envVars["POSTGRES_PASSWORD"]) { $envVars["POSTGRES_PASSWORD"] } else { "socpassword" }
$pgDb       = if ($envVars["POSTGRES_DB"])       { $envVars["POSTGRES_DB"] }       else { "socmaturity" }

Write-Host "Starting services..."
docker compose up -d

Write-Host "Waiting for PostgreSQL to become healthy..."
$containerId = docker compose ps -q postgres
$maxAttempts = 30
$attempt     = 0
$health      = ""

while ($health -ne "healthy" -and $attempt -lt $maxAttempts) {
    Start-Sleep -Seconds 2
    $health = docker inspect --format '{{.State.Health.Status}}' $containerId
    $attempt++
}

if ($health -ne "healthy") {
    Write-Error "PostgreSQL did not become healthy after $($attempt * 2) seconds."
    exit 1
}

Write-Host "PostgreSQL is ready."

$env:DATABASE_URL      = "postgresql://${pgUser}:${pgPassword}@localhost:5432/${pgDb}"
$env:STIX_BUNDLE_PATH  = "stix/enterprise-attack.json"

Write-Host "Generating 30 days of simulated alerts..."
python -m simulator.alert_simulator --days 30

Write-Host "Running KPI backfill for 30 days..."
python -m engines.kpi_engine --backfill --days 30

Write-Host "Running coverage engine..."
python -m engines.coverage_engine

Write-Host "Demo ready. Open http://localhost:3000"
