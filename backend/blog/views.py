from django.contrib.auth import login, logout
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from rest_framework import generics, permissions, status, views
from rest_framework.response import Response
from django.contrib.auth import get_user_model

from .models import Post, Profile, TrafficLog, AttackLog, IPWhitelist, IPBlacklist
from .serializers import (
    LoginSerializer,
    PostSerializer,
    ProfileSerializer,
    RegisterSerializer,
    UserSerializer,
    AdminUserSerializer,
    AdminUserCreateSerializer,
    AdminUserUpdateSerializer,
    TrafficLogSerializer,
    AttackLogSerializer,
    IPWhitelistSerializer,
    IPBlacklistSerializer,
)


User = get_user_model()


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


class LoginView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        login(request, user)
        return Response(UserSerializer(user).data)


class LogoutView(views.APIView):
    def post(self, request, *args, **kwargs):
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(views.APIView):
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({"detail": "Not authenticated"}, status=401)
        profile, _ = Profile.objects.get_or_create(user=request.user)
        return Response(ProfileSerializer(profile).data)

    @transaction.atomic
    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({"detail": "Not authenticated"}, status=401)
        profile, _ = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class PublicPostListView(generics.ListAPIView):
    queryset = Post.objects.filter(published=True)
    serializer_class = PostSerializer
    permission_classes = [permissions.AllowAny]


class UserPostListCreateView(generics.ListCreateAPIView):
    serializer_class = PostSerializer

    def get_queryset(self):
        return Post.objects.filter(author=self.request.user)

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class UserPostDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PostSerializer

    def get_queryset(self):
        return Post.objects.filter(author=self.request.user)
    
    def delete(self, request, *args, **kwargs):
        """Allow users to delete their own posts."""
        instance = self.get_object()
        if instance.author != request.user:
            return Response({"detail": "You can only delete your own posts."}, status=403)
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Admin Views

class IsAdminUser(permissions.BasePermission):
    """Custom permission to check if user is admin."""
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        try:
            profile = Profile.objects.get(user=request.user)
            return profile.is_admin or request.user.is_superuser
        except Profile.DoesNotExist:
            return False


class AdminUserListView(generics.ListCreateAPIView):
    """Admin endpoint to list and create users."""
    serializer_class = AdminUserSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return User.objects.all().order_by('-date_joined')
    
    def create(self, request, *args, **kwargs):
        serializer = AdminUserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        # Return full user data
        user = User.objects.get(id=serializer.instance.id)
        return Response(AdminUserSerializer(user).data, status=status.HTTP_201_CREATED)


class AdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Admin endpoint to get, update, delete specific users."""
    serializer_class = AdminUserSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return User.objects.all()
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        # Don't allow users to demote themselves or other superusers
        if instance == request.user:
            # Users can't modify their own superuser status
            if 'is_superuser' in request.data and request.data['is_superuser'] != instance.is_superuser:
                return Response(
                    {"detail": "You cannot change your own superuser status."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        serializer = AdminUserUpdateSerializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(AdminUserSerializer(instance).data)
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        # Don't allow users to delete themselves
        if instance == request.user:
            return Response(
                {"detail": "You cannot delete your own account."},
                status=status.HTTP_400_BAD_REQUEST
            )
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdminPostListView(generics.ListCreateAPIView):
    """Admin endpoint to list and create all posts."""
    serializer_class = PostSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        queryset = Post.objects.all()
        # Filter by published status
        published = self.request.query_params.get('published')
        if published is not None:
            queryset = queryset.filter(published=published.lower() == 'true')
        return queryset.order_by('-created_at')
    
    def create(self, request, *args, **kwargs):
        # Allow admin to create posts for any user
        author_id = request.data.get('author')
        if author_id:
            try:
                author = User.objects.get(id=author_id)
            except User.DoesNotExist:
                return Response({"detail": "Author not found."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            author = request.user
        serializer = PostSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(author=author)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class AdminPostDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Admin endpoint to get, update, delete specific posts."""
    serializer_class = PostSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return Post.objects.all()


class TrafficLogListView(generics.ListAPIView):
    """Admin endpoint to list traffic logs."""
    serializer_class = TrafficLogSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        queryset = TrafficLog.objects.all()
        # Filter by attack status
        is_attack = self.request.query_params.get('is_attack')
        if is_attack is not None:
            queryset = queryset.filter(is_attack=is_attack.lower() == 'true')
        # Filter by IP
        ip = self.request.query_params.get('ip')
        if ip:
            queryset = queryset.filter(ip_address=ip)
        # Filter by date range
        start_date = self.request.query_params.get('start')
        end_date = self.request.query_params.get('end')
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)
        return queryset.order_by('-timestamp')[:10000]  # Limit to 10k records


class AttackLogListView(generics.ListAPIView):
    """Admin endpoint to list attack logs."""
    serializer_class = AttackLogSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        queryset = AttackLog.objects.all()
        # Filter by attack type
        attack_type = self.request.query_params.get('type')
        if attack_type:
            queryset = queryset.filter(attack_type=attack_type)
        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        # Filter by IP
        ip = self.request.query_params.get('ip')
        if ip:
            queryset = queryset.filter(ip_address=ip)
        # Filter by blocked status
        blocked = self.request.query_params.get('blocked')
        if blocked is not None:
            queryset = queryset.filter(blocked=blocked.lower() == 'true')
        # Filter by date range
        start_date = self.request.query_params.get('start')
        end_date = self.request.query_params.get('end')
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)
        return queryset.order_by('-timestamp')[:10000]  # Limit to 10k records


class AttackLogDetailView(generics.RetrieveUpdateAPIView):
    """Admin endpoint to get and update specific attack logs."""
    serializer_class = AttackLogSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return AttackLog.objects.all()
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        # Allow updating severity and blocked status
        if 'severity' in request.data:
            instance.severity = request.data['severity']
        if 'blocked' in request.data:
            instance.blocked = request.data['blocked']
        instance.save()
        return Response(AttackLogSerializer(instance).data)


class IPWhitelistListView(generics.ListCreateAPIView):
    """Admin endpoint to list and create IP whitelist entries."""
    serializer_class = IPWhitelistSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return IPWhitelist.objects.all().order_by('-created_at')


class IPWhitelistDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Admin endpoint to manage specific IP whitelist entries."""
    serializer_class = IPWhitelistSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return IPWhitelist.objects.all()


class IPBlacklistListView(generics.ListCreateAPIView):
    """Admin endpoint to list and create IP blacklist entries."""
    serializer_class = IPBlacklistSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return IPBlacklist.objects.all().order_by('-created_at')
    
    def create(self, request, *args, **kwargs):
        ip_address = request.data.get('ip_address')
        if IPBlacklist.objects.filter(ip_address=ip_address, active=True).exists():
            return Response(
                {"detail": "This IP is already blacklisted."},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().create(request, *args, **kwargs)


class IPBlacklistDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Admin endpoint to manage specific IP blacklist entries."""
    serializer_class = IPBlacklistSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return IPBlacklist.objects.all()


class AdminDashboardStatsView(views.APIView):
    """Admin endpoint to get dashboard statistics."""
    permission_classes = [IsAdminUser]
    
    def get(self, request, *args, **kwargs):
        # Get time range (default: last 24 hours)
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        
        # Basic counts
        total_users = User.objects.count()
        total_posts = Post.objects.count()
        published_posts = Post.objects.filter(published=True).count()
        
        # Traffic stats
        traffic_filter = Q(timestamp__gte=since)
        total_requests = TrafficLog.objects.filter(traffic_filter).count()
        attack_requests = TrafficLog.objects.filter(traffic_filter, is_attack=True).count()
        unique_visitors = TrafficLog.objects.filter(traffic_filter).values('ip_address').distinct().count()
        
        # Requests by method
        requests_by_method = dict(
            TrafficLog.objects.filter(traffic_filter)
            .values('method')
            .annotate(count=Count('id'))
            .values_list('method', 'count')
        )
        
        # Requests by status
        requests_by_status = dict(
            TrafficLog.objects.filter(traffic_filter)
            .values('status_code')
            .annotate(count=Count('id'))
            .values_list('status_code', 'count')
        )
        
        # Top paths
        top_paths = list(
            TrafficLog.objects.filter(traffic_filter)
            .exclude(path__startswith='/static/')
            .exclude(path__startswith='/admin/')
            .values('path')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        # Attacks by type
        attacks_by_type = dict(
            AttackLog.objects.filter(timestamp__gte=since)
            .values('attack_type')
            .annotate(count=Count('id'))
            .values_list('attack_type', 'count')
        )
        
        # Recent attacks
        recent_attacks = AttackLog.objects.filter(timestamp__gte=since).order_by('-timestamp')[:10]
        
        # Hourly distribution (last 24 hours)
        hourly_distribution = []
        for i in range(24):
            hour_start = timezone.now() - timedelta(hours=i+1)
            hour_end = timezone.now() - timedelta(hours=i)
            count = TrafficLog.objects.filter(
                timestamp__gte=hour_start, 
                timestamp__lt=hour_end
            ).count()
            hourly_distribution.append({
                'hour': i,
                'count': count
            })
        hourly_distribution.reverse()
        
        return Response({
            'users': {
                'total': total_users,
                'active': total_users,  # All users are considered active
            },
            'posts': {
                'total': total_posts,
                'published': published_posts,
                'drafts': total_posts - published_posts,
            },
            'traffic': {
                'total_requests': total_requests,
                'attack_requests': attack_requests,
                'unique_visitors': unique_visitors,
                'requests_by_method': requests_by_method,
                'requests_by_status': requests_by_status,
                'top_paths': top_paths,
                'attacks_by_type': attacks_by_type,
                'recent_attacks': AttackLogSerializer(recent_attacks, many=True).data,
                'hourly_distribution': hourly_distribution,
            }
        })


class BlockIPView(views.APIView):
    """Admin endpoint to quickly block an IP."""
    permission_classes = [IsAdminUser]
    
    def post(self, request, *args, **kwargs):
        ip_address = request.data.get('ip_address')
        reason = request.data.get('reason', '')
        
        if not ip_address:
            return Response({"detail": "IP address is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        blacklist, created = IPBlacklist.objects.get_or_create(
            ip_address=ip_address,
            defaults={'reason': reason, 'active': True}
        )
        
        if not created:
            blacklist.active = True
            blacklist.reason = reason
            blacklist.save()
        
        return Response(
            {"detail": f"IP {ip_address} has been blocked.", "id": blacklist.id},
            status=status.HTTP_201_CREATED
        )


class UnblockIPView(views.APIView):
    """Admin endpoint to unblock an IP."""
    permission_classes = [IsAdminUser]
    
    def post(self, request, *args, **kwargs):
        ip_address = request.data.get('ip_address')
        
        if not ip_address:
            return Response({"detail": "IP address is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            blacklist = IPBlacklist.objects.get(ip_address=ip_address, active=True)
            blacklist.active = False
            blacklist.save()
            return Response({"detail": f"IP {ip_address} has been unblocked."})
        except IPBlacklist.DoesNotExist:
            return Response(
                {"detail": f"IP {ip_address} is not in the blacklist."},
                status=status.HTTP_404_NOT_FOUND
            )
