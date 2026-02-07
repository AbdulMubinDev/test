import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-key-change-me")

DEBUG = os.environ.get("DEBUG", "1") == "1"

ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "blog",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "core.middleware.BlockBannedIPMiddleware",  # Block banned IPs before anything else
    "django.middleware.common.CommonMiddleware",
    "core.middleware.CsrfExemptApiMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.UnauthorizedAccessLoggingMiddleware",
    "core.middleware.TrafficLoggingMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "blogdb"),
        "USER": os.environ.get("POSTGRES_USER", "bloguser"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "blogpassword"),
        "HOST": os.environ.get("POSTGRES_HOST", "internal_proxy"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
    }
}

REDIS_HOST = os.environ.get("REDIS_HOST", "internal_proxy")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"redis://{REDIS_HOST}:{REDIS_PORT}/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    }
}

# Use Redis for sessions
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

# Session cookie settings for cross-origin requests
SESSION_COOKIE_NAME = "sessionid"
SESSION_COOKIE_AGE = 86400 * 7  # 1 week
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", None)
SESSION_COOKIE_SECURE = os.environ.get("DEBUG", "1") != "1"  # True in production
SESSION_COOKIE_HTTPONLY = True

# CSRF settings
CSRF_COOKIE_NAME = "csrftoken"
CSRF_COOKIE_AGE = 86400 * 7
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_DOMAIN = os.environ.get("CSRF_COOKIE_DOMAIN", None)
CSRF_COOKIE_SECURE = os.environ.get("DEBUG", "1") != "1"
CSRF_TRUSTED_ORIGINS = os.environ.get("CSRF_TRUSTED_ORIGINS", "http://localhost,http://127.0.0.1").split(",")

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticatedOrReadOnly",
    ],
}

# Security: Disable server header
# This hides the Django/Gunicorn version from HTTP responses
DISABLE_SERVER_HEADER = True

# Security: Hide technical information in error pages
if not DEBUG:
    # Disable technical error reporting that could reveal stack traces
    DEBUG_PROPAGATE_EXCEPTIONS = False

