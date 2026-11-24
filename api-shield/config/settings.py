import sys
from functools import partial
from pathlib import Path

from decouple import AutoConfig
from dj_database_url import parse as parse_database_url

BASE_DIR = Path(__file__).resolve().parent.parent
config = AutoConfig(search_path=str(BASE_DIR))


def csv_setting(name, default=""):
    value = config(name, default=default)
    if isinstance(value, list):
        return value
    return [item.strip() for item in str(value).split(",") if item.strip()]


def enum_choices(model_path, enum_name):
    module_path, model_name = model_path.rsplit(".", 1)
    model = getattr(__import__(module_path, fromlist=[model_name]), model_name)
    return getattr(model, enum_name).choices


SECRET_KEY = config("SECRET_KEY", default="dev-only-insecure-secret-change-before-production")
DEBUG = config("DEBUG", default=True, cast=bool)
TESTING = config("TESTING", default=False, cast=bool) or "test" in sys.argv or "pytest" in sys.argv

ALLOWED_HOSTS = csv_setting("ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = csv_setting("CSRF_TRUSTED_ORIGINS", "http://localhost:8000")
CORS_ALLOWED_ORIGINS = csv_setting("CORS_ALLOWED_ORIGINS", "")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "rest_framework_simplejwt",
    "oauth2_provider",
    "drf_spectacular",
    "corsheaders",
    "whitenoise",
    "accounts",
    "organizations",
    "api_projects",
    "endpoint_discovery",
    "api_scanner",
    "authentication_audit",
    "behaviour_monitor",
    "vulnerability_manager",
    "ai_analysis",
    "reports",
    "dashboard",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "accounts.middleware.RequestIdMiddleware",
    "organizations.middleware.OrganizationContextMiddleware",
    "behaviour_monitor.middleware.ApiBehaviourMonitorMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "organizations.context_processors.apishield_context",
            ],
        },
    }
]

DATABASE_URL = config(
    "DATABASE_URL",
    default="postgres://apishield:apishield@localhost:5432/apishield",
)
DATABASES = {"default": parse_database_url(DATABASE_URL)}
if TESTING:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    }
DATABASES["default"]["CONN_MAX_AGE"] = 600 if not TESTING else 0
DATABASES["default"]["ATOMIC_REQUESTS"] = False

AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "dashboard:index"
LOGOUT_REDIRECT_URL = "accounts:login"
ALLOW_PUBLIC_REGISTRATION = config("ALLOW_PUBLIC_REGISTRATION", default=False, cast=bool)

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
        if not DEBUG
        else "whitenoise.storage.CompressedStaticFilesStorage"
    },
}

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
REPORTS_ROOT = MEDIA_ROOT / "reports"
UPLOAD_ROOT = MEDIA_ROOT / "uploads"
SPECIFICATION_UPLOAD_ROOT = UPLOAD_ROOT / "openapi"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "oauth2_provider.contrib.rest_framework.OAuth2Authentication",
        "accounts.authentication.ApiKeyAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
    "EXCEPTION_HANDLER": "config.exception_handler.api_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {},
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": __import__("datetime").timedelta(
        minutes=config("JWT_ACCESS_TOKEN_LIFETIME_MINUTES", default=30, cast=int)
    ),
    "REFRESH_TOKEN_LIFETIME": __import__("datetime").timedelta(
        days=config("JWT_REFRESH_TOKEN_LIFETIME_DAYS", default=7, cast=int)
    ),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "APIShield API",
    "DESCRIPTION": "Intelligent API security testing and threat detection platform.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SECURITY": [{"BearerAuth": []}, {"ApiKeyAuth": []}, {"OAuth2": []}],
    "SECURITY_SCHEMES": {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
        "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        "OAuth2": {"type": "oauth2", "flows": {"password": {"tokenUrl": "/oauth/token/"}}},
    },
    "ENUM_NAME_OVERRIDES": {
        "ScanRunStatusEnum": partial(enum_choices, "api_scanner.models.ScanRun", "Status"),
        "ScanFindingStatusEnum": partial(enum_choices, "api_scanner.models.ScanFinding", "Status"),
        "ApiProjectStatusEnum": partial(enum_choices, "api_projects.models.ApiProject", "Status"),
        "VulnerabilityAssignmentStatusEnum": partial(
            enum_choices, "vulnerability_manager.models.VulnerabilityAssignment", "Status"
        ),
        "BehaviourAlertStatusEnum": partial(enum_choices, "behaviour_monitor.models.BehaviourAlert", "Status"),
        "ReportStatusEnum": partial(enum_choices, "reports.models.Report", "Status"),
        "AuthenticationAuditResultEnum": partial(
            enum_choices, "authentication_audit.models.AuthenticationAudit", "Result"
        ),
        "VerificationRecordResultEnum": partial(
            enum_choices, "vulnerability_manager.models.VerificationRecord", "Result"
        ),
    },
}

APISHIELD = {
    "ACTIVE_TESTING_ENABLED": config("ACTIVE_TESTING_ENABLED", default=False, cast=bool),
    "ALLOW_ZAP": config("ALLOW_ZAP", default=True, cast=bool),
    "ZAP_API_URL": config("ZAP_API_URL", default="http://127.0.0.1:8080"),
    "ZAP_API_KEY": config("ZAP_API_KEY", default=""),
    "SCAN_TIMEOUT_SECONDS": config("SCAN_TIMEOUT_SECONDS", default=15, cast=int),
    "MAX_ACTIVE_REQUESTS": config("MAX_ACTIVE_REQUESTS", default=40, cast=int),
    "SCAN_RATE_LIMIT_RPM": config("SCAN_RATE_LIMIT_RPM", default=30, cast=int),
    "AI_EXPLANATIONS_ENABLED": config("AI_EXPLANATIONS_ENABLED", default=False, cast=bool),
    "GEMINI_API_KEY": config("GEMINI_API_KEY", default=""),
    "GEMINI_MODEL": config("GEMINI_MODEL", default="gemini-1.5-flash"),
    "BEHAVIOUR_WINDOW_MINUTES": config("BEHAVIOUR_WINDOW_MINUTES", default=10, cast=int),
    "FAILED_REQUEST_THRESHOLD": config("FAILED_REQUEST_THRESHOLD", default=12, cast=int),
    "REQUEST_FREQUENCY_THRESHOLD": config("REQUEST_FREQUENCY_THRESHOLD", default=120, cast=int),
    "SENSITIVE_PATH_TERMS": csv_setting(
        "SENSITIVE_PATH_TERMS", "admin,auth,token,password,secret,payment,billing,api-key"
    ),
    "DEMO_MODE": config("DEMO_MODE", default=True, cast=bool),
}

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = not DEBUG
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
X_FRAME_OPTIONS = "DENY"
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"},
    },
    "filters": {
        "request_id": {"()": "accounts.logging_filters.RequestIdFilter"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "filters": ["request_id"],
        },
    },
    "root": {
        "handlers": ["console"],
        "level": config("LOG_LEVEL", default="INFO"),
    },
    "loggers": {
        "django.request": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "apishield": {
            "handlers": ["console"],
            "level": config("LOG_LEVEL", default="INFO"),
            "propagate": False,
        },
    },
}

if not DEBUG and not TESTING:
    secret = config("SECRET_KEY", default="")
    if len(secret) < 50:
        raise RuntimeError("SECRET_KEY must be at least 50 characters in production.")
