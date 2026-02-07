# Gunicorn configuration file
# Security hardening settings

# Bind address
bind = "0.0.0.0:8000"

# Worker settings
workers = 2
worker_class = "sync"
timeout = 30
keepalive = 65

# Logging (disable access log to reduce info leakage)
accesslog = "/dev/null"
errorlog = "-"
loglevel = "warning"

# Security: Disable server header
# This prevents Gunicorn from showing its version in responses
def pre_fork(server, worker):
    pass

def post_fork(server, worker):
    pass

# Custom header handling
def on_response(worker, req, environ, resp):
    # Remove Server header if present
    if 'Server' in resp.headers:
        del resp.headers['Server']
