#!/usr/bin/env bash
# Full test suite: run before pushing to GitHub.
# Requires: Docker (containers started via ./run.sh), optional: Python 3, Node/npm
set -euo pipefail

# Match run.sh: production compose (backend not exposed)
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"

# Project root: script may be run from repo root or from script dir
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" && pwd)"
cd "$ROOT_DIR"

FAILED=0
PASSED=0

run_section() {
    echo
    echo "=========================================="
    echo "$1"
    echo "=========================================="
}

pass() {
    echo "  ✓ $1"
    ((PASSED+=1)) || true
}

fail() {
    echo "  ✗ $1"
    ((FAILED+=1)) || true
}

# -----------------------------------------------------------------------------
# 1. Pre-requisites: required containers exist and are running
# -----------------------------------------------------------------------------
run_section "1. Checking container status"

REQUIRED_CONTAINERS="blog_postgres blog_backend blog_nginx"
MISSING=""
for c in $REQUIRED_CONTAINERS; do
    if ! docker ps -a --format "{{.Names}}" | grep -q "^${c}$"; then
        MISSING="${MISSING} ${c}"
    elif ! docker ps --format "{{.Names}}" | grep -q "^${c}$"; then
        echo "  Container $c exists but is not running."
        docker ps -a --filter "name=$c" --format "table {{.Names}}\t{{.Status}}"
        MISSING="${MISSING} ${c}(stopped)"
    fi
done

if [ -n "$MISSING" ]; then
    echo "Error: Required containers missing or stopped:$MISSING"
    echo "Start the stack first: ./run.sh"
    exit 1
fi
pass "Required containers running (postgres, backend, nginx)"

# -----------------------------------------------------------------------------
# 2. Wait for services to be ready
# -----------------------------------------------------------------------------
run_section "2. Waiting for services"

max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec blog_postgres pg_isready -U bloguser -d blogdb >/dev/null 2>&1; then
        pass "Database is ready"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
if [ $attempt -ge $max_attempts ]; then
    fail "Database not ready after ${max_attempts}s"
fi

attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec blog_backend python -c "import django; print('OK')" 2>/dev/null | grep -q "OK"; then
        pass "Backend (Django) is ready"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
if [ $attempt -ge $max_attempts ]; then
    fail "Backend not ready after ${max_attempts}s"
fi

attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec blog_nginx wget -q -O - http://localhost/health 2>/dev/null | grep -q "OK"; then
        pass "Nginx reverse proxy is ready (port 80)"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
if [ $attempt -ge $max_attempts ]; then
    fail "Nginx not ready after ${max_attempts}s"
fi

# -----------------------------------------------------------------------------
# 3. Backend migrations
# -----------------------------------------------------------------------------
run_section "3. Backend migrations"

if docker exec blog_backend sh -c "cd /app && python manage.py migrate --noinput" 2>/dev/null; then
    pass "Migrations applied"
else
    fail "Migrations failed"
fi

# -----------------------------------------------------------------------------
# 4. Backend unit tests (pytest)
# -----------------------------------------------------------------------------
run_section "4. Backend unit tests (pytest)"

if docker exec blog_backend sh -c "cd /app && python -m pytest -v --tb=short" 2>/dev/null; then
    pass "Backend unit tests passed"
else
    fail "Backend unit tests failed"
    echo "    Run inside container: docker exec blog_backend sh -c 'cd /app && python -m pytest -v'"
fi

# -----------------------------------------------------------------------------
# 5. Integration / E2E tests (via nginx on port 80)
# -----------------------------------------------------------------------------
run_section "5. Integration tests (API and frontend via nginx)"

run_integration() {
    if [ -n "${1:-}" ]; then
        "$1" tests/integration_test.py
    else
        python3 tests/integration_test.py 2>/dev/null || python tests/integration_test.py 2>/dev/null
    fi
}

INTEGRATION_OK=0
if command -v python3 >/dev/null 2>&1 && python3 -c "import requests" 2>/dev/null; then
    echo "  Using local Python 3 + requests"
    if run_integration python3; then
        INTEGRATION_OK=1
    fi
elif command -v python >/dev/null 2>&1 && python -c "import requests" 2>/dev/null; then
    echo "  Using local Python + requests"
    if run_integration python; then
        INTEGRATION_OK=1
    fi
else
    echo "  Installing requests and running integration tests in Docker..."
    if docker run --rm \
        --add-host=host.docker.internal:host-gateway \
        -e TEST_BASE_URL="http://host.docker.internal" \
        -v "${ROOT_DIR}/tests:/tests:ro" \
        python:3.12-slim \
        sh -c "pip install requests --quiet && python /tests/integration_test.py"; then
        INTEGRATION_OK=1
    fi
fi

if [ $INTEGRATION_OK -eq 1 ]; then
    pass "Integration tests passed"
else
    fail "Integration tests failed"
fi

# -----------------------------------------------------------------------------
# 6. Frontend build (optional but recommended before push)
# -----------------------------------------------------------------------------
run_section "6. Frontend build check"

if [ -f "frontend/package.json" ] && command -v npm >/dev/null 2>&1; then
    if (cd frontend && npm ci --silent 2>/dev/null) || (cd frontend && npm install --silent 2>/dev/null); then
        if (cd frontend && npm run build 2>/dev/null); then
            pass "Frontend build succeeded"
        else
            fail "Frontend build failed"
        fi
    else
        echo "  (npm install failed or skipped; run manually: cd frontend && npm install && npm run build)"
    fi
else
    echo "  (npm not found or frontend/package.json missing; skip frontend build)"
fi

# -----------------------------------------------------------------------------
# Summary and exit
# -----------------------------------------------------------------------------
run_section "Summary"

echo "  Passed: $PASSED"
if [ "$FAILED" -gt 0 ]; then
    echo "  Failed: $FAILED"
    echo
    echo "Fix failing steps before pushing to GitHub."
    exit 1
fi
echo
echo "All tests passed. Safe to push."
exit 0
