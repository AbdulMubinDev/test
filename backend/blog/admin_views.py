"""
Admin portal API. One-time setup (no preset credentials), then session-based admin auth.
All admin endpoints require is_staff except status and setup.
"""
from django.contrib.auth import get_user_model, login, logout
from django.db import transaction
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from core.middleware import get_client_ip
from .models import AdminSetup, AuditLog, BannedIP, TrafficLog

User = get_user_model()


def is_staff_only(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return False
    return True


def log_admin_audit(request, action, details=None):
    try:
        AuditLog.objects.create(
            user=request.user,
            ip_address=get_client_ip(request),
            path=request.path,
            method=request.method,
            action=action,
            details=details or {},
        )
    except Exception:
        pass


@api_view(["GET"])
@permission_classes([AllowAny])
def admin_status(request):
    """Public: is admin configured? No auth."""
    try:
        setup = AdminSetup.objects.first()
        configured = setup.configured if setup else False
    except Exception:
        configured = False
    return Response({"configured": configured})


@api_view(["POST"])
@permission_classes([AllowAny])
def admin_setup(request):
    """One-time setup: create admin user. No preset credentials."""
    if request.method != "POST":
        return Response(status=405)
    try:
        setup = AdminSetup.objects.first()
        if not setup:
            setup = AdminSetup.objects.create(configured=False)
        if setup.configured:
            return Response(
                {"detail": "Admin is already configured."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    except Exception:
        setup = AdminSetup(configured=False)
        setup.save()

    username = (request.data.get("username") or "").strip()
    password = request.data.get("password")
    if not username or not password:
        return Response(
            {"detail": "Username and password are required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if User.objects.filter(username=username).exists():
        return Response(
            {"detail": "Username already exists."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if len(password) < 8:
        return Response(
            {"detail": "Password must be at least 8 characters."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    with transaction.atomic():
        admin_user = User.objects.create_user(
            username=username,
            email="",
            password=password,
            is_staff=True,
            is_superuser=True,
        )
        setup.configured = True
        setup.save(update_fields=["configured"])

    login(request, admin_user)
    log_admin_audit(request, "admin_setup", {"username": username})
    return Response(
        {"username": admin_user.username, "id": admin_user.id},
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def admin_login(request):
    """Admin login. Only staff users can log in here."""
    username = request.data.get("username") or ""
    password = request.data.get("password") or ""
    from django.contrib.auth import authenticate
    user = authenticate(request, username=username, password=password)
    if not user or not user.is_staff:
        return Response(
            {"detail": "Invalid credentials or not an admin."},
            status=status.HTTP_401_UNAUTHORIZED,
        )
    login(request, user)
    log_admin_audit(request, "admin_login", {"username": user.username})
    return Response({"id": user.id, "username": user.username})


@api_view(["POST"])
def admin_logout(request):
    if is_staff_only(request):
        log_admin_audit(request, "admin_logout", {"username": request.user.username})
    logout(request)
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["GET"])
def admin_me(request):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    return Response({
        "id": request.user.id,
        "username": request.user.username,
        "email": request.user.email or "",
    })


@api_view(["GET", "POST"])
def admin_users_list(request):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    if request.method == "GET":
        users = User.objects.filter(is_superuser=False).order_by("-date_joined")
        return Response([
            {
                "id": u.id,
                "username": u.username,
                "email": u.email or "",
                "is_active": u.is_active,
                "date_joined": u.date_joined.isoformat() if u.date_joined else None,
            }
            for u in users
        ])
    # POST - create user
    username = (request.data.get("username") or "").strip()
    password = request.data.get("password")
    email = (request.data.get("email") or "").strip()
    if not username or not password:
        return Response(
            {"detail": "Username and password required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if User.objects.filter(username=username).exists():
        return Response(
            {"detail": "Username already exists."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    user = User.objects.create_user(
        username=username,
        email=email or "",
        password=password,
    )
    log_admin_audit(request, "admin_user_create", {"username": username})
    return Response(
        {"id": user.id, "username": user.username, "email": user.email or "", "is_active": user.is_active},
        status=status.HTTP_201_CREATED,
    )


@api_view(["GET", "PUT", "DELETE"])
def admin_user_detail(request, user_id):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
    if user.is_superuser:
        return Response({"detail": "Cannot modify superuser."}, status=status.HTTP_400_BAD_REQUEST)

    if request.method == "GET":
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email or "",
            "is_active": user.is_active,
            "date_joined": user.date_joined.isoformat() if user.date_joined else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        })
    if request.method == "PUT":
        if "email" in request.data:
            user.email = (request.data.get("email") or "").strip()
        if "password" in request.data and request.data["password"]:
            user.set_password(request.data["password"])
        if "is_active" in request.data:
            user.is_active = bool(request.data["is_active"])
        user.save()
        log_admin_audit(request, "admin_user_update", {"user_id": user.id, "username": user.username})
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email or "",
            "is_active": user.is_active,
        })
    # DELETE
    username = user.username
    user.delete()
    log_admin_audit(request, "admin_user_delete", {"username": username})
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["POST"])
def admin_user_ban(request, user_id):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return Response({"detail": "Not found."}, status=404)
    if user.is_superuser:
        return Response({"detail": "Cannot ban superuser."}, status=400)
    user.is_active = False
    user.save()
    log_admin_audit(request, "admin_user_ban", {"user_id": user.id, "username": user.username})
    return Response({"is_active": False})


@api_view(["POST"])
def admin_user_unban(request, user_id):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return Response({"detail": "Not found."}, status=404)
    user.is_active = True
    user.save()
    log_admin_audit(request, "admin_user_unban", {"user_id": user.id, "username": user.username})
    return Response({"is_active": True})


@api_view(["GET"])
def admin_audit_logs(request):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    limit = min(int(request.GET.get("limit", 100)), 500)
    logs = AuditLog.objects.all()[:limit]
    return Response([
        {
            "id": l.id,
            "user": l.user_id,
            "username": l.user.username if l.user_id else None,
            "ip_address": str(l.ip_address) if l.ip_address else None,
            "path": l.path,
            "method": l.method,
            "action": l.action,
            "details": l.details,
            "created_at": l.created_at.isoformat() if l.created_at else None,
        }
        for l in logs
    ])


@api_view(["GET"])
def admin_traffic(request):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    limit = min(int(request.GET.get("limit", 100)), 500)
    logs = TrafficLog.objects.all()[:limit]
    return Response([
        {
            "id": l.id,
            "ip_address": str(l.ip_address) if l.ip_address else None,
            "path": l.path,
            "method": l.method,
            "status_code": l.status_code,
            "user_agent": l.user_agent[:80] + "..." if len(l.user_agent or "") > 80 else (l.user_agent or ""),
            "created_at": l.created_at.isoformat() if l.created_at else None,
        }
        for l in logs
    ])


@api_view(["GET"])
def admin_attacks(request):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    limit = min(int(request.GET.get("limit", 100)), 500)
    logs = AuditLog.objects.filter(action="unauthorized_attempt").order_by("-created_at")[:limit]
    return Response([
        {
            "id": l.id,
            "ip_address": str(l.ip_address) if l.ip_address else None,
            "path": l.path,
            "method": l.method,
            "details": l.details,
            "created_at": l.created_at.isoformat() if l.created_at else None,
        }
        for l in logs
    ])


@api_view(["GET", "POST"])
def admin_banned_ips_list(request):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    if request.method == "GET":
        ips = BannedIP.objects.all()
        return Response([
            {"id": b.id, "ip_address": str(b.ip_address), "reason": b.reason, "created_at": b.created_at.isoformat()}
            for b in ips
        ])
    ip_address = (request.data.get("ip_address") or "").strip()
    reason = (request.data.get("reason") or "").strip()
    if not ip_address:
        return Response({"detail": "ip_address required."}, status=status.HTTP_400_BAD_REQUEST)
    if BannedIP.objects.filter(ip_address=ip_address).exists():
        return Response({"detail": "IP already banned."}, status=status.HTTP_400_BAD_REQUEST)
    banned = BannedIP.objects.create(ip_address=ip_address, reason=reason)
    log_admin_audit(request, "admin_ip_ban", {"ip_address": ip_address})
    return Response(
        {"id": banned.id, "ip_address": str(banned.ip_address), "reason": banned.reason},
        status=status.HTTP_201_CREATED,
    )


@api_view(["DELETE"])
def admin_banned_ip_detail(request, ban_id):
    if not is_staff_only(request):
        return Response({"detail": "Forbidden"}, status=403)
    try:
        banned = BannedIP.objects.get(pk=ban_id)
    except BannedIP.DoesNotExist:
        return Response({"detail": "Not found."}, status=404)
    ip_address = str(banned.ip_address)
    banned.delete()
    log_admin_audit(request, "admin_ip_unban", {"ip_address": ip_address})
    return Response(status=status.HTTP_204_NO_CONTENT)
