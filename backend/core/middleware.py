import time
import re
import logging
import threading
from django.utils.deprecation import MiddlewareMixin
from django.middleware.csrf import CsrfViewMiddleware
from django.http import HttpRequest, JsonResponse
from django.conf import settings

from blog.models import TrafficLog, AttackLog, IPBlacklist, IPWhitelist

logger = logging.getLogger(__name__)


# Rate limiting storage (in-memory for simplicity)
rate_limit_storage = {}
rate_limit_lock = threading.Lock()


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


class AttackDetectionMiddleware(MiddlewareMixin):
    """
    Middleware to detect and log attacks on the website.
    Detects: SQL injection, XSS, path traversal, brute force, etc.
    """
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(\%3D)|(=)[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*(\%27)|(\')|((\%6F)|(o)|(\%4F))((\%72)|(r)|(\%52))",
        r"((\%27)|(\')|\`)|(union|select|insert|update|delete|drop|alter|create|truncate)",
        r"(union|select|insert|update|delete|drop|alter|create|truncate).*from",
        r"'.*OR.*'.*=.*'",
        r"'.*AND.*'.*=.*'",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script>",
        r"</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"<object",
        r"<embed",
        r"expression\s*\(",
        r"data:text/html",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.%2f",
        r"%2e%2e",
        r"\.\.%5c",
        r"%2e%2e%5c",
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r";\s*(cat|ls|wget|curl|ping|nc|rm|mkdir|cp|mv|chmod|chown)",
        r"\|\s*(cat|ls|wget|curl|ping|nc|rm|mkdir|cp|mv|chmod|chown)",
        r"`.*`",
        r"\$\(.*\)",
    ]
    
    # Suspicious user agents
    SUSPICIOUS_USER_AGENTS = [
        r"sqlmap",
        r"nikto",
        r"nmap",
        r"masscan",
        r"havij",
        r"acunetix",
        r"burp",
        r"zap",
        r"python-requests/.*",
    ]
    
    # Rate limiting settings
    RATE_LIMIT_REQUESTS = 100  # requests per window
    RATE_LIMIT_WINDOW = 60  # seconds
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance."""
        self.compiled_patterns = {
            'sql_injection': [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS],
            'xss': [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS],
            'path_traversal': [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS],
            'command_injection': [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS],
            'suspicious_user_agent': [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_USER_AGENTS],
        }
    
    def process_request(self, request: HttpRequest):
        """Process incoming request for attack detection."""
        start_time = time.time()
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Check if IP is whitelisted
        if IPWhitelist.objects.filter(ip_address=client_ip, active=True).exists():
            request.is_whitelisted_ip = True
            return None
        
        # Check if IP is blacklisted
        if IPBlacklist.objects.filter(ip_address=client_ip, active=True).exists():
            # Log and block the request
            self._log_attack(
                request, client_ip, "other", "medium",
                "Blocked request from blacklisted IP",
                "Blacklisted IP address"
            )
            return JsonResponse(
                {"detail": "Access denied. Your IP has been blocked."},
                status=403
            )
        
        request.is_whitelisted_ip = False
        
        # Check rate limiting
        rate_limit_result = self._check_rate_limit(client_ip)
        if rate_limit_result.get('blocked'):
            self._log_attack(
                request, client_ip, "rate_limit", "high",
                "Rate limit exceeded",
                f"Exceeded {self.RATE_LIMIT_REQUESTS} requests per {self.RATE_LIMIT_WINDOW} seconds"
            )
            return JsonResponse(
                {"detail": "Rate limit exceeded. Please try again later."},
                status=429
            )
        
        # Check for attacks
        attack_result = self._detect_attacks(request)
        if attack_result['detected']:
            attack = attack_result['attack']
            # Log the attack
            self._log_attack(
                request, client_ip,
                attack['type'],
                attack['severity'],
                attack['payload'],
                attack.get('description', '')
            )
            
            # Block the request for high severity attacks
            if attack['severity'] in ['high', 'critical']:
                return JsonResponse(
                    {"detail": "Malicious request detected. Access denied."},
                    status=403
                )
        
        # Store timing info for logging
        request._start_time = start_time
        return None
    
    def process_response(self, request: HttpRequest, response):
        """Log traffic after response."""
        if not hasattr(request, '_start_time'):
            return response
        
        start_time = request._start_time
        response_time_ms = int((time.time() - start_time) * 1000)
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Determine if this was an attack request
        is_attack = getattr(request, '_is_attack', False)
        
        # Log the traffic (async to not slow down response)
        try:
            TrafficLog.objects.create(
                path=request.path[:500],
                method=request.method,
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                user=request.user if request.user.is_authenticated else None,
                response_time_ms=response_time_ms,
                status_code=response.status_code,
                is_attack=is_attack
            )
        except Exception as e:
            logger.error(f"Failed to log traffic: {e}")
        
        return response
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'Unknown')
    
    def _detect_attacks(self, request: HttpRequest) -> dict:
        """Detect various types of attacks in the request."""
        # Combine all inputs to check
        check_strings = []
        
        # Check path
        check_strings.append(request.path)
        
        # Check query string
        if request.META.get('QUERY_STRING'):
            check_strings.append(request.META['QUERY_STRING'])
        
        # Check request body (for POST/PUT requests)
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                body = request.body.decode('utf-8', errors='ignore')
                check_strings.append(body)
            except Exception:
                pass
        
        # Check user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        check_strings.append(user_agent)
        
        combined_text = ' '.join(check_strings)
        
        # Check for SQL injection
        for pattern in self.compiled_patterns['sql_injection']:
            match = pattern.search(combined_text)
            if match:
                return {
                    'detected': True,
                    'attack': {
                        'type': 'sql_injection',
                        'severity': 'critical',
                        'payload': match.group()[:500],
                        'description': 'SQL injection attempt detected'
                    }
                }
        
        # Check for XSS
        for pattern in self.compiled_patterns['xss']:
            match = pattern.search(combined_text)
            if match:
                return {
                    'detected': True,
                    'attack': {
                        'type': 'xss',
                        'severity': 'high',
                        'payload': match.group()[:500],
                        'description': 'Cross-site scripting (XSS) attempt detected'
                    }
                }
        
        # Check for path traversal
        for pattern in self.compiled_patterns['path_traversal']:
            match = pattern.search(combined_text)
            if match:
                return {
                    'detected': True,
                    'attack': {
                        'type': 'path_traversal',
                        'severity': 'high',
                        'payload': match.group()[:500],
                        'description': 'Path traversal attempt detected'
                    }
                }
        
        # Check for command injection
        for pattern in self.compiled_patterns['command_injection']:
            match = pattern.search(combined_text)
            if match:
                return {
                    'detected': True,
                    'attack': {
                        'type': 'command_injection',
                        'severity': 'critical',
                        'payload': match.group()[:500],
                        'description': 'Command injection attempt detected'
                    }
                }
        
        # Check for suspicious user agents
        for pattern in self.compiled_patterns['suspicious_user_agent']:
            if pattern.search(user_agent):
                return {
                    'detected': True,
                    'attack': {
                        'type': 'suspicious_user_agent',
                        'severity': 'medium',
                        'payload': user_agent[:500],
                        'description': 'Suspicious user agent detected'
                    }
                }
        
        # Check for malformed requests
        if self._is_malformed_request(request):
            return {
                'detected': True,
                'attack': {
                    'type': 'invalid_request',
                    'severity': 'low',
                    'payload': combined_text[:500],
                    'description': 'Malformed or invalid request detected'
                }
            }
        
        return {'detected': False}
    
    def _is_malformed_request(self, request: HttpRequest) -> bool:
        """Check if request is malformed."""
        # Check for extremely long paths (potential DoS)
        if len(request.path) > 2000:
            return True
        
        # Check for null bytes in path
        if '\x00' in request.path:
            return True
        
        # Check for null bytes in query string
        query_string = request.META.get('QUERY_STRING', '')
        if '\x00' in query_string:
            return True
        
        return False
    
    def _check_rate_limit(self, client_ip: str) -> dict:
        """Check if client has exceeded rate limit."""
        current_time = time.time()
        window_start = current_time - self.RATE_LIMIT_WINDOW
        
        with rate_limit_lock:
            # Clean old entries
            for ip in list(rate_limit_storage.keys()):
                rate_limit_storage[ip] = [
                    t for t in rate_limit_storage[ip] if t > window_start
                ]
                if not rate_limit_storage[ip]:
                    del rate_limit_storage[ip]
            
            # Get or create entry for this IP
            if client_ip not in rate_limit_storage:
                rate_limit_storage[client_ip] = []
            
            # Count requests in current window
            request_count = len(rate_limit_storage[client_ip])
            
            if request_count >= self.RATE_LIMIT_REQUESTS:
                return {'blocked': True, 'count': request_count}
            
            # Add current request
            rate_limit_storage[client_ip].append(current_time)
            
            return {'blocked': False, 'count': request_count + 1}
    
    def _log_attack(self, request: HttpRequest, client_ip: str, attack_type: str, 
                   severity: str, payload: str, description: str):
        """Log detected attacks to the database."""
        try:
            AttackLog.objects.create(
                attack_type=attack_type,
                severity=severity,
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                path=request.path[:500],
                payload=payload,
                user=request.user if request.user.is_authenticated else None,
                blocked=True,
                request_data=f"{request.method} {request.path}"
            )
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
        
        # Mark request as attack for traffic logging
        request._is_attack = True
        
        logger.warning(
            f"Attack detected: {attack_type} ({severity}) from {client_ip} "
            f"on {request.method} {request.path}"
        )
