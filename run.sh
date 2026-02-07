#!/usr/bin/env bash
set -euo pipefail

# Production mode: only nginx on port 80; backend not exposed to host
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"

echo "Building containers (frontend, backend, db, redis, internal_proxy, nginx)..."
docker-compose $COMPOSE_FILES build

echo "Starting containers in the background..."
docker-compose $COMPOSE_FILES up -d

echo
echo "Waiting for services to be ready..."
echo "  Waiting for database..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec blog_postgres pg_isready -U bloguser -d blogdb >/dev/null 2>&1; then
        echo "  ✓ Database is ready"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "  ⚠ Database not ready after $max_attempts seconds, but continuing..."
fi

echo "  Waiting for backend (via internal network)..."
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec blog_backend python -c "import django; print('OK')" 2>/dev/null | grep -q "OK"; then
        echo "  ✓ Backend is ready"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "  ⚠ Backend not ready after $max_attempts seconds"
    echo "     Check logs: docker logs blog_backend"
fi

echo "  Waiting for nginx reverse proxy (port 80)..."
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec blog_nginx wget -q -O - http://localhost/health 2>/dev/null | grep -q "OK"; then
        echo "  ✓ Nginx reverse proxy is ready and listening on port 80"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "  ⚠ Nginx not ready after $max_attempts seconds"
    echo "     Check logs: docker logs blog_nginx"
fi

echo "  Validating nginx config..."
if docker exec blog_nginx nginx -t 2>/dev/null; then
    echo "  ✓ Nginx config valid"
else
    echo "  ⚠ Nginx config check failed (non-fatal)"
fi

echo
echo "All services started."
echo "============================================"
echo "  Site URL:  http://localhost (port 80)"
echo "  Admin:     http://localhost/admin"
echo "============================================"
echo ""
echo "Nginx reverse proxy is listening on port 80 and routes:"
echo "  - /         -> frontend (SPA)"
echo "  - /api/*    -> backend (Django API)"
echo "  - /health   -> health check"
echo ""
echo "Backend is not exposed to the host (access only via nginx)."
echo ""
echo "To run tests: ./test.sh"
echo "To stop:      docker-compose $COMPOSE_FILES down"
echo "To view logs: docker-compose $COMPOSE_FILES logs -f"
echo ""
