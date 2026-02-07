import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

from .models import Post, Profile

User = get_user_model()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def user(db):
    return User.objects.create_user(
        username="testuser",
        email="test@example.com",
        password="testpass123"
    )


@pytest.fixture
def authenticated_client(api_client, user):
    # Use session login so AuthenticationMiddleware sets request.user;
    # middleware and DRF then see an authenticated request.
    api_client.login(username=user.username, password="testpass123")
    return api_client


@pytest.fixture
def profile(db, user):
    return Profile.objects.create(
        user=user,
        display_name="Test User",
        bio="Test bio"
    )


@pytest.fixture
def published_post(db, user):
    return Post.objects.create(
        author=user,
        title="Published Post",
        content="This is a published post content.",
        published=True
    )


@pytest.fixture
def draft_post(db, user):
    return Post.objects.create(
        author=user,
        title="Draft Post",
        content="This is a draft post content.",
        published=False
    )


@pytest.mark.django_db
class TestAuth:
    def test_register_user(self, api_client):
        url = reverse("register")
        data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "securepass123"
        }
        response = api_client.post(url, data, format="json")
        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(username="newuser").exists()
        assert Profile.objects.filter(user__username="newuser").exists()

    def test_login_user(self, api_client, user):
        url = reverse("login")
        data = {
            "username": "testuser",
            "password": "testpass123"
        }
        response = api_client.post(url, data, format="json")
        assert response.status_code == status.HTTP_200_OK
        assert "username" in response.data

    def test_login_invalid_credentials(self, api_client, user):
        url = reverse("login")
        data = {
            "username": "testuser",
            "password": "wrongpass"
        }
        response = api_client.post(url, data, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_get_me_unauthenticated(self, api_client):
        url = reverse("me")
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_me_authenticated(self, authenticated_client, user, profile):
        url = reverse("me")
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data["user"]["username"] == user.username

    def test_update_profile(self, authenticated_client, user, profile):
        url = reverse("me")
        data = {
            "display_name": "Updated Name",
            "bio": "Updated bio"
        }
        response = authenticated_client.put(url, data, format="json")
        assert response.status_code == status.HTTP_200_OK
        profile.refresh_from_db()
        assert profile.display_name == "Updated Name"
        assert profile.bio == "Updated bio"


@pytest.mark.django_db
class TestPublicPosts:
    def test_list_published_posts(self, api_client, published_post, draft_post):
        url = reverse("public-posts")
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 1
        assert response.data[0]["title"] == "Published Post"
        assert response.data[0]["published"] is True

    def test_draft_posts_not_visible(self, api_client, draft_post):
        url = reverse("public-posts")
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 0


@pytest.mark.django_db
class TestUserPosts:
    def test_list_own_posts(self, authenticated_client, user, published_post, draft_post):
        url = reverse("my-posts")
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 2

    def test_create_post(self, authenticated_client, user):
        url = reverse("my-posts")
        data = {
            "title": "New Post",
            "content": "New post content",
            "published": True
        }
        response = authenticated_client.post(url, data, format="json")
        assert response.status_code == status.HTTP_201_CREATED
        assert Post.objects.filter(title="New Post", author=user).exists()

    def test_update_own_post(self, authenticated_client, user, published_post):
        url = reverse("my-post-detail", kwargs={"pk": published_post.pk})
        data = {
            "title": "Updated Title",
            "content": "Updated content",
            "published": False
        }
        response = authenticated_client.put(url, data, format="json")
        assert response.status_code == status.HTTP_200_OK
        published_post.refresh_from_db()
        assert published_post.title == "Updated Title"
        assert published_post.published is False

    def test_cannot_update_other_user_post(self, authenticated_client, user):
        other_user = User.objects.create_user(
            username="otheruser",
            password="pass123"
        )
        other_post = Post.objects.create(
            author=other_user,
            title="Other Post",
            content="Content",
            published=True
        )
        url = reverse("my-post-detail", kwargs={"pk": other_post.pk})
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND
