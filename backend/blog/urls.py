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
]

