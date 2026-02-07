from django.contrib.auth import login, logout
from django.db import transaction
from rest_framework import generics, permissions, status, views
from rest_framework.response import Response

from core.middleware import get_client_ip
from .models import AuditLog, Post, Profile
from .serializers import (
    LoginSerializer,
    PostSerializer,
    ProfileSerializer,
    RegisterSerializer,
    UserSerializer,
)


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
        try:
            AuditLog.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                path=request.path,
                method=request.method,
                action="login",
                details={},
            )
        except Exception:
            pass
        return Response(UserSerializer(user).data)


class LogoutView(views.APIView):
    def post(self, request, *args, **kwargs):
        user = request.user
        try:
            if user.is_authenticated:
                AuditLog.objects.create(
                    user=user,
                    ip_address=get_client_ip(request),
                    path=request.path,
                    method=request.method,
                    action="logout",
                    details={},
                )
        except Exception:
            pass
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


class UserPostDetailView(generics.RetrieveUpdateAPIView):
    serializer_class = PostSerializer

    def get_queryset(self):
        return Post.objects.filter(author=self.request.user)

