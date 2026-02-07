from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

from .models import Post, Profile, TrafficLog, AttackLog, IPWhitelist, IPBlacklist


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "is_active", "date_joined", "last_login"]
        read_only_fields = ["id", "date_joined", "last_login"]


class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Profile
        fields = ["user", "display_name", "bio", "is_admin"]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "username", "email", "password"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        Profile.objects.get_or_create(user=user)
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = authenticate(
            username=attrs.get("username"),
            password=attrs.get("password"),
        )
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        attrs["user"] = user
        return attrs


class PostSerializer(serializers.ModelSerializer):
    author_username = serializers.ReadOnlyField(source="author.username")

    class Meta:
        model = Post
        fields = [
            "id",
            "title",
            "content",
            "published",
            "author_username",
            "author",
            "created_at",
            "updated_at",
        ]


# Admin Serializers

class AdminUserSerializer(serializers.ModelSerializer):
    """Serializer for admin user management."""
    profile = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ["id", "username", "email", "is_active", "is_staff", "is_superuser", 
                  "date_joined", "last_login", "profile"]
        read_only_fields = ["id", "date_joined", "last_login"]
    
    def get_profile(self, obj):
        try:
            profile = Profile.objects.get(user=obj)
            return {
                "display_name": profile.display_name,
                "bio": profile.bio,
                "is_admin": profile.is_admin,
            }
        except Profile.DoesNotExist:
            return None


class AdminUserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new users (admin)."""
    password = serializers.CharField(write_only=True, min_length=8)
    
    class Meta:
        model = User
        fields = ["username", "email", "password", "is_active", "is_staff", "is_superuser"]
    
    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        Profile.objects.get_or_create(user=user)
        return user


class AdminUserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating users (admin)."""
    
    class Meta:
        model = User
        fields = ["username", "email", "is_active", "is_staff", "is_superuser"]


class TrafficLogSerializer(serializers.ModelSerializer):
    """Serializer for traffic logs."""
    user_username = serializers.ReadOnlyField(source="user.username")
    
    class Meta:
        model = TrafficLog
        fields = [
            "id", "path", "method", "ip_address", "user_agent", "user_username",
            "timestamp", "response_time_ms", "status_code", "is_attack"
        ]


class AttackLogSerializer(serializers.ModelSerializer):
    """Serializer for attack logs."""
    user_username = serializers.ReadOnlyField(source="user.username")
    
    class Meta:
        model = AttackLog
        fields = [
            "id", "attack_type", "severity", "ip_address", "user_agent", "path",
            "payload", "user_username", "timestamp", "blocked", "request_data"
        ]


class IPWhitelistSerializer(serializers.ModelSerializer):
    """Serializer for IP whitelist."""
    
    class Meta:
        model = IPWhitelist
        fields = ["id", "ip_address", "description", "created_at", "active"]


class IPBlacklistSerializer(serializers.ModelSerializer):
    """Serializer for IP blacklist."""
    
    class Meta:
        model = IPBlacklist
        fields = ["id", "ip_address", "reason", "created_at", "expires_at", "active"]


class TrafficStatsSerializer(serializers.Serializer):
    """Serializer for traffic statistics."""
    total_requests = serializers.IntegerField()
    total_attacks = serializers.IntegerField()
    unique_visitors = serializers.IntegerField()
    requests_by_method = serializers.DictField()
    requests_by_status = serializers.DictField()
    top_paths = serializers.ListField()
    attacks_by_type = serializers.DictField()
    recent_attacks = AttackLogSerializer(many=True)
    hourly_distribution = serializers.ListField()
