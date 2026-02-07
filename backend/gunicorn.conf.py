# Gunicorn configuration file - security hardening

bind = "0.0.0.0:8000"
workers = 2
worker_class = "sync"
timeout = 30
keepalive = 65
accesslog = "/dev/null"
errorlog = "-"
loglevel = "warning"

# Hide server identity (no version in Server header)
import gunicorn
gunicorn.SERVER_SOFTWARE = ""

# Remove Server header (Django SecurityHeadersMiddleware also strips it from response)
