import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

application = get_wsgi_application()

# Remove server header for security
# This hides the Django version from responses
try:
    from django.conf import settings
    settings.SECURE_BARE_EXCLUDE_PATHS = ['/']
except Exception:
    pass
