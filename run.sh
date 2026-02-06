#!/usr/bin/env bash
set -euo pipefail

echo "Building containers (frontend, backend, db, redis, internal_proxy)..."
docker-compose build

echo "Starting containers in the background..."
docker-compose up -d

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

echo "  Waiting for backend to be ready..."
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec blog_backend python -c "import django; print('OK')" 2>/dev/null | grep -q "OK"; then
        # Check if the API responds (curl is optional)
        if command -v curl >/dev/null 2>&1; then
            if curl -s http://localhost:8000/api/posts/ >/dev/null 2>&1; then
                echo "  ✓ Backend is ready"
                break
            fi
        else
            # If curl not available, just check Django is importable
            echo "  ✓ Backend is ready"
            break
        fi
    fi
    attempt=$((attempt + 1))
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "  ⚠ Backend not fully ready after $max_attempts seconds"
    echo "     Check logs with: docker logs blog_backend"
fi

echo
echo "All services started."
echo "Frontend: http://localhost:80 (listening on port 80)"
echo "Backend API: http://localhost:8000"
echo
echo "In your VPS nginx configuration, proxy:"
echo "  - public site (blogs/auth/dashboard) -> http://127.0.0.1:80"
echo "  - backend API (/api/) -> http://127.0.0.1:8000"
echo
echo "To run tests: ./test.sh"

