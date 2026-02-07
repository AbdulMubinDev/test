import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpRequest, JsonResponse, HttpResponse
from django.db import connection

logger = logging.getLogger(__name__)


def get_client_ip(request: HttpRequest) -> str:
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


class BlockBannedIPMiddleware(MiddlewareMixin):
    """Block requests from banned IPs before any other processing."""

    def process_request(self, request: HttpRequest):
        ip = get_client_ip(request)
        if not ip:
            return None
        try:
            from blog.models import BannedIP
            if BannedIP.objects.filter(ip_address=ip).exists():
                return HttpResponse("Forbidden", status=403)
        except Exception:
            pass
        return None


class CsrfExemptApiMiddleware(MiddlewareMixin):
    """
    CSRF middleware that exempts API endpoints from CSRF checks.
    This is safe for REST APIs that use session authentication.
    """

    def process_request(self, request):
        # Exempt API endpoints from CSRF
        if request.path.startswith("/api/"):
            setattr(request, "_dont_enforce_csrf_checks", True)
        return None


class UnauthorizedAccessLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log unauthorized access attempts for security monitoring.
    Persists to AuditLog for admin portal.
    """

    PROTECTED_API_PATHS = [
        "/api/auth/me/",
        "/api/my-posts/",
        "/api/admin/",
    ]
    ALLOWED_ANY_PATHS = [
        "/api/admin/status",
        "/api/admin/setup",
        "/api/admin/login",
    ]

    def process_request(self, request: HttpRequest):
        if any(request.path.startswith(p) for p in self.ALLOWED_ANY_PATHS):
            return None
        if not any(request.path.startswith(path) for path in self.PROTECTED_API_PATHS):
            return None
        if request.user.is_authenticated:
            return None
        ip = get_client_ip(request)
        logger.warning(
            f"Unauthorized access attempt: {request.method} {request.path} "
            f"from IP: {ip} User-Agent: {request.META.get('HTTP_USER_AGENT', 'Unknown')}"
        )
        try:
            from blog.models import AuditLog
            AuditLog.objects.create(
                ip_address=ip,
                path=request.path,
                method=request.method,
                action="unauthorized_attempt",
                details={"user_agent": request.META.get("HTTP_USER_AGENT", "")[:500]},
            )
        except Exception:
            pass
        return JsonResponse(
            {"detail": "You are not authorized to access this resource"},
            status=401,
        )


class TrafficLoggingMiddleware(MiddlewareMixin):
    """Log API requests to TrafficLog for admin dashboard."""

    def process_response(self, request, response):
        if not request.path.startswith("/api/"):
            return response
        ip = get_client_ip(request)
        try:
            from blog.models import TrafficLog
            TrafficLog.objects.create(
                ip_address=ip,
                path=request.path,
                method=request.method,
                status_code=response.status_code,
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
            )
        except Exception:
            pass
        return response


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers to all responses and remove version information.
    """

    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    HEADERS_TO_REMOVE = [
        "Server",
        "X-Django-Version",
        "X-Powered-By",
    ]

    def process_response(self, request, response):
        for header in self.HEADERS_TO_REMOVE:
            if header in response:
                del response[header]
        for header, value in self.SECURITY_HEADERS.items():
            if header not in response:
                response[header] = value
        return response
