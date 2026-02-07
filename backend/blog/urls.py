from django.urls import path

from . import views
from . import admin_views

urlpatterns = [
    # Auth
    path("auth/register/", views.RegisterView.as_view(), name="register"),
    path("auth/login/", views.LoginView.as_view(), name="login"),
    path("auth/logout/", views.LogoutView.as_view(), name="logout"),
    path("auth/me/", views.MeView.as_view(), name="me"),
    # Public posts
    path("posts/", views.PublicPostListView.as_view(), name="public-posts"),
    # User's own posts
    path("my-posts/", views.UserPostListCreateView.as_view(), name="my-posts"),
    path("my-posts/<int:pk>/", views.UserPostDetailView.as_view(), name="my-post-detail"),
    # Admin portal (one-time setup, then session auth)
    path("admin/status/", admin_views.admin_status),
    path("admin/setup/", admin_views.admin_setup),
    path("admin/login/", admin_views.admin_login),
    path("admin/logout/", admin_views.admin_logout),
    path("admin/me/", admin_views.admin_me),
    path("admin/users/", admin_views.admin_users_list),
    path("admin/users/<int:user_id>/", admin_views.admin_user_detail),
    path("admin/users/<int:user_id>/ban/", admin_views.admin_user_ban),
    path("admin/users/<int:user_id>/unban/", admin_views.admin_user_unban),
    path("admin/audit/", admin_views.admin_audit_logs),
    path("admin/traffic/", admin_views.admin_traffic),
    path("admin/attacks/", admin_views.admin_attacks),
    path("admin/banned-ips/", admin_views.admin_banned_ips_list),
    path("admin/banned-ips/<int:ban_id>/", admin_views.admin_banned_ip_detail),
]

