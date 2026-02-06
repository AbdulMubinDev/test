#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo "Blog Application Test Suite"
echo "=========================================="
echo

# Check if containers exist and are running
echo "Checking container status..."

# Check if backend container exists
if ! docker ps -a --format "{{.Names}}" | grep -q "^blog_backend$"; then
    echo "Error: Backend container does not exist."
    echo "Please start containers first with: ./run.sh"
    exit 1
fi

# Check if backend container is running
if ! docker ps --format "{{.Names}}" | grep -q "^blog_backend$"; then
    echo "Error: Backend container exists but is not running."
    echo "Container status:"
    docker ps -a --filter "name=blog_backend" --format "table {{.Names}}\t{{.Status}}"
    echo ""
    echo "Try starting containers with: ./run.sh"
    echo "Or check logs with: docker logs blog_backend"
    exit 1
fi

# Wait for backend to be ready (check if Django is accessible)
echo "Waiting for backend to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    # Check if we can execute commands in the container and Django is available
    if docker exec blog_backend python -c "import django; print('OK')" 2>/dev/null | grep -q "OK"; then
        echo "Backend is ready!"
        break
    fi
    attempt=$((attempt + 1))
    if [ $((attempt % 5)) -eq 0 ]; then
        echo "  Still waiting... ($attempt/$max_attempts)"
    fi
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "Error: Backend container is not ready after $max_attempts seconds."
    echo "Check logs with: docker logs blog_backend"
    exit 1
fi

echo "Running backend unit tests (pytest)..."
echo "----------------------------------------"
# Ensure migrations are run first
echo "Running migrations..."
docker exec blog_backend sh -c "cd /app && python manage.py migrate --noinput" || {
    echo "Migrations failed!"
    exit 1
}
# Run pytest - use sh -c to avoid Git Bash path interpretation issues on Windows
docker exec blog_backend sh -c "cd /app && python -m pytest blog/tests.py -v" || {
    echo ""
    echo "Checking container contents..."
    docker exec blog_backend sh -c "cd /app && ls -la blog/*.py 2>&1 | head -10"
    echo ""
    # Check if file exists using Python (works reliably across platforms)
    if ! docker exec blog_backend sh -c "python -c \"import os; exit(0 if os.path.exists('/app/blog/tests.py') else 1)\"" 2>/dev/null; then
        echo "ERROR: Test file /app/blog/tests.py not found in container!"
        echo ""
        echo "The container was built with cached layers. Rebuild without cache:"
        echo "  docker-compose build --no-cache backend"
        echo "  ./run.sh"
    else
        echo "Test file exists but pytest failed. Check error above."
    fi
    exit 1
}

echo
echo "Running integration/E2E tests..."
echo "----------------------------------------"
# Try local Python first, fallback to Docker container
PYTHON_CMD=""
for cmd in python3 python py; do
    if command -v "$cmd" >/dev/null 2>&1 && "$cmd" --version >/dev/null 2>&1; then
        PYTHON_CMD="$cmd"
        break
    fi
done

if [ -n "$PYTHON_CMD" ]; then
    echo "Using local Python: $PYTHON_CMD"
    # Check if requests module is available
    if ! "$PYTHON_CMD" -c "import requests" 2>/dev/null; then
        echo "Installing requests module..."
        "$PYTHON_CMD" -m pip install requests --quiet 2>&1 || {
            echo "Failed to install requests. Trying Docker instead..."
            PYTHON_CMD=""
        }
    fi
    
    if [ -n "$PYTHON_CMD" ]; then
        "$PYTHON_CMD" tests/integration_test.py || {
            echo "Integration tests failed!"
            exit 1
        }
        exit 0
    fi
fi

# Fallback: Run integration tests in Docker container with host network access
echo "Python not available locally. Running integration tests in Docker container..."
docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$(pwd)/tests:/tests:ro" \
    python:3.12-slim \
    sh -c "pip install requests --quiet && python /tests/integration_test.py" || {
    echo ""
    echo "Integration tests failed!"
    echo ""
    echo "To run integration tests locally, install Python 3 and requests:"
    echo "  python3 -m pip install requests"
    echo "  python3 tests/integration_test.py"
    exit 1
}

echo
echo "=========================================="
echo "All tests passed! ✓"
echo "=========================================="
echo
echo "Your application is ready for production deployment."
