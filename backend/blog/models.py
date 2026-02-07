from django.conf import settings
from django.db import models


class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    bio = models.TextField(blank=True)
    display_name = models.CharField(max_length=100, blank=True)
    is_admin = models.BooleanField(default=False, help_text="Admin users can access the admin dashboard")

    def __str__(self) -> str:
        return self.display_name or self.user.username


class Post(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    content = models.TextField()
    published = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.title


class TrafficLog(models.Model):
    """Model to track website traffic and requests."""
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=10)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    response_time_ms = models.IntegerField(default=0)
    status_code = models.IntegerField(default=200)
    is_attack = models.BooleanField(default=False)
    
    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["-timestamp"]),
            models.Index(fields=["ip_address"]),
            models.Index(fields=["path"]),
        ]

    def __str__(self) -> str:
        return f"{self.method} {self.path} - {self.ip_address} @ {self.timestamp}"


class AttackLog(models.Model):
    """Model to log detected attacks and suspicious activities."""
    ATTACK_TYPES = [
        ("sql_injection", "SQL Injection"),
        ("xss", "Cross-Site Scripting (XSS)"),
        ("csrf", "CSRF Attack"),
        ("brute_force", "Brute Force Attempt"),
        ("path_traversal", "Path Traversal"),
        ("command_injection", "Command Injection"),
        ("rate_limit", "Rate Limit Exceeded"),
        ("suspicious_user_agent", "Suspicious User Agent"),
        ("invalid_request", "Invalid/Malformed Request"),
        ("other", "Other"),
    ]
    
    SEVERITY_LEVELS = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]
    
    attack_type = models.CharField(max_length=50, choices=ATTACK_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default="medium")
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    path = models.CharField(max_length=500)
    payload = models.TextField(blank=True, help_text="Malicious payload that triggered the detection")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    blocked = models.BooleanField(default=False)
    request_data = models.TextField(blank=True, help_text="Raw request data")
    
    class Meta:
        ordering = ["-timestamp"]
        verbose_name_plural = "Attack logs"
    
    def __str__(self) -> str:
        return f"{self.attack_type} - {self.ip_address} @ {self.timestamp}"


class IPWhitelist(models.Model):
    """Whitelist trusted IP addresses."""
    ip_address = models.GenericIPAddressField(unique=True)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    active = models.BooleanField(default=True)
    
    def __str__(self) -> str:
        return f"{self.ip_address} - {self.description or 'No description'}"


class IPBlacklist(models.Model):
    """Blacklist malicious IP addresses."""
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    active = models.BooleanField(default=True)
    
    def __str__(self) -> str:
        return f"{self.ip_address} - {self.reason or 'No reason'}"
