import time
import logging
from django.utils.deprecation import MiddlewareMixin
from django.middleware.csrf import CsrfViewMiddleware
from django.http import HttpRequest, JsonResponse

logger = logging.getLogger(__name__)


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
    """

    # Protected API endpoints that require authentication
    PROTECTED_API_PATHS = [
        "/api/auth/me/",
        "/api/my-posts/",
    ]

    def process_request(self, request: HttpRequest):
        # Only check protected API endpoints
        if not any(request.path.startswith(path) for path in self.PROTECTED_API_PATHS):
            return None

        # Check if user is authenticated
        if not request.user.is_authenticated:
            logger.warning(
                f"Unauthorized access attempt: {request.method} {request.path} "
                f"from IP: {self._get_client_ip(request)} "
                f"User-Agent: {request.META.get('HTTP_USER_AGENT', 'Unknown')}"
            )
            # Return 401 Unauthorized response for API calls
            return JsonResponse(
                {"detail": "You are not authorized to access this resource"},
                status=401
            )

        return None

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'Unknown')


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers to all responses and remove version information.
    """

    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    }

    # Headers to remove to hide tech stack
    HEADERS_TO_REMOVE = [
        'Server',
        'X-Django-Version',
        'X-Powered-By',
    ]

    def process_response(self, request, response):
        # Remove version headers to hide tech stack
        for header in self.HEADERS_TO_REMOVE:
            if header in response:
                del response[header]

        # Add security headers
        for header, value in self.SECURITY_HEADERS.items():
            if header not in response:
                response[header] = value
        return response
