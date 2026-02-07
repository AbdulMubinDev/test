from django.urls import path

from . import views


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
    
    # Admin URLs
    path("admin/users/", views.AdminUserListView.as_view(), name="admin-users"),
    path("admin/users/<int:pk>/", views.AdminUserDetailView.as_view(), name="admin-user-detail"),
    path("admin/posts/", views.AdminPostListView.as_view(), name="admin-posts"),
    path("admin/posts/<int:pk>/", views.AdminPostDetailView.as_view(), name="admin-post-detail"),
    path("admin/traffic/", views.TrafficLogListView.as_view(), name="admin-traffic"),
    path("admin/attacks/", views.AttackLogListView.as_view(), name="admin-attacks"),
    path("admin/attacks/<int:pk>/", views.AttackLogDetailView.as_view(), name="admin-attack-detail"),
    path("admin/whitelist/", views.IPWhitelistListView.as_view(), name="admin-whitelist"),
    path("admin/whitelist/<int:pk>/", views.IPWhitelistDetailView.as_view(), name="admin-whitelist-detail"),
    path("admin/blacklist/", views.IPBlacklistListView.as_view(), name="admin-blacklist"),
    path("admin/blacklist/<int:pk>/", views.IPBlacklistDetailView.as_view(), name="admin-blacklist-detail"),
    path("admin/dashboard/stats/", views.AdminDashboardStatsView.as_view(), name="admin-dashboard-stats"),
    path("admin/block-ip/", views.BlockIPView.as_view(), name="admin-block-ip"),
    path("admin/unblock-ip/", views.UnblockIPView.as_view(), name="admin-unblock-ip"),
]
