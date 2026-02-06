#!/usr/bin/env python3
"""
Integration/E2E tests for the blog application.
Tests the full flow: frontend -> backend -> database
Run this after starting containers with ./run.sh
"""
import requests
import time
import sys
from typing import Dict, Optional

# Detect if running in Docker and adjust URLs accordingly
import os
if os.path.exists("/.dockerenv"):
    # Running inside Docker container - use host.docker.internal for Windows/Mac
    # or host network access
    BASE_URL = os.environ.get("TEST_BASE_URL", "http://host.docker.internal")
else:
    # Running locally
    BASE_URL = "http://localhost"

FRONTEND_URL = f"{BASE_URL}:80"
BACKEND_URL = f"{BASE_URL}:8000"
API_URL = f"{BACKEND_URL}/api"

# Colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


class TestRunner:
    def __init__(self):
        self.session = requests.Session()
        self.passed = 0
        self.failed = 0
        self.test_username = f"testuser_{int(time.time())}"
        self.test_password = "testpass123"

    def log(self, message: str, status: str = "info"):
        if status == "pass":
            print(f"{GREEN}✓{RESET} {message}")
        elif status == "fail":
            print(f"{RED}✗{RESET} {message}")
        elif status == "info":
            print(f"{YELLOW}→{RESET} {message}")

    def test(self, name: str, func):
        """Run a test and track results"""
        try:
            func()
            self.passed += 1
            self.log(f"{name}", "pass")
            return True
        except Exception as e:
            self.failed += 1
            self.log(f"{name}: {str(e)}", "fail")
            return False

    def wait_for_service(self, url: str, service_name: str, max_retries: int = 30):
        """Wait for a service to be ready"""
        for i in range(max_retries):
            try:
                response = requests.get(url, timeout=2)
                if response.status_code < 500:
                    return True
            except:
                pass
            if i < max_retries - 1:
                time.sleep(1)
        raise Exception(f"{service_name} not ready after {max_retries} seconds")

    def test_frontend_accessible(self):
        """Test 1: Frontend is accessible"""
        response = requests.get(FRONTEND_URL, timeout=5)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert "html" in response.text.lower() or "root" in response.text.lower()

    def test_backend_api_accessible(self):
        """Test 2: Backend API is accessible"""
        response = requests.get(f"{API_URL}/posts/", timeout=5)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    def test_register_user(self):
        """Test 3: User registration works"""
        data = {
            "username": self.test_username,
            "email": f"{self.test_username}@test.com",
            "password": self.test_password
        }
        response = requests.post(f"{API_URL}/auth/register/", json=data, timeout=5)
        assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"

    def test_login_user(self):
        """Test 4: User login works"""
        data = {
            "username": self.test_username,
            "password": self.test_password
        }
        response = self.session.post(f"{API_URL}/auth/login/", json=data, timeout=5)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        assert "username" in response.json()

    def test_get_profile(self):
        """Test 5: Get user profile"""
        response = self.session.get(f"{API_URL}/auth/me/", timeout=5)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "user" in data

    def test_update_profile(self):
        """Test 6: Update user profile"""
        data = {
            "display_name": "Test Display Name",
            "bio": "Test bio for integration testing"
        }
        response = self.session.put(f"{API_URL}/auth/me/", json=data, timeout=5)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        updated = response.json()
        assert updated["display_name"] == "Test Display Name"

    def test_create_post(self):
        """Test 7: Create a blog post"""
        data = {
            "title": "Integration Test Post",
            "content": "This is a test post created during integration testing.",
            "published": True
        }
        response = self.session.post(f"{API_URL}/my-posts/", json=data, timeout=5)
        assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"
        post_data = response.json()
        assert post_data["title"] == "Integration Test Post"
        assert post_data["published"] is True
        return post_data["id"]

    def test_list_own_posts(self):
        """Test 8: List user's own posts"""
        response = self.session.get(f"{API_URL}/my-posts/", timeout=5)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        posts = response.json()
        assert isinstance(posts, list)
        assert len(posts) > 0

    def test_update_post(self, post_id: int):
        """Test 9: Update a blog post"""
        data = {
            "title": "Updated Integration Test Post",
            "content": "Updated content",
            "published": False
        }
        response = self.session.put(f"{API_URL}/my-posts/{post_id}/", json=data, timeout=5)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        updated = response.json()
        assert updated["title"] == "Updated Integration Test Post"
        assert updated["published"] is False

    def test_public_posts_list(self, post_id: int):
        """Test 10: Public posts list shows published posts"""
        response = requests.get(f"{API_URL}/posts/", timeout=5)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        posts = response.json()
        assert isinstance(posts, list)
        # Check that our published post is in the list (before we make it a draft)
        post_ids = [p["id"] for p in posts]
        assert post_id in post_ids, f"Published post {post_id} should be in public list"

    def test_draft_not_in_public_list(self, post_id: int):
        """Test 11: Draft posts don't appear in public list"""
        response = requests.get(f"{API_URL}/posts/", timeout=5)
        assert response.status_code == 200
        posts = response.json()
        post_ids = [p["id"] for p in posts]
        # The post we updated to draft should not be in public list
        assert post_id not in post_ids, "Draft post should not appear in public list"

    def test_logout(self):
        """Test 12: User logout works"""
        response = self.session.post(f"{API_URL}/auth/logout/", timeout=5)
        assert response.status_code == 204, f"Expected 204, got {response.status_code}"

    def run_all(self):
        """Run all integration tests"""
        print(f"\n{YELLOW}Starting Integration Tests{RESET}\n")
        print(f"Frontend URL: {FRONTEND_URL}")
        print(f"Backend URL: {BACKEND_URL}\n")

        # Wait for services
        self.log("Waiting for services to be ready...", "info")
        try:
            self.wait_for_service(FRONTEND_URL, "Frontend")
            self.wait_for_service(f"{API_URL}/posts/", "Backend")
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")
            print(f"{YELLOW}Make sure containers are running: ./run.sh{RESET}\n")
            sys.exit(1)

        print()

        # Run tests
        post_id = None
        self.test("Frontend accessible", self.test_frontend_accessible)
        self.test("Backend API accessible", self.test_backend_api_accessible)
        self.test("User registration", self.test_register_user)
        self.test("User login", self.test_login_user)
        self.test("Get profile", self.test_get_profile)
        self.test("Update profile", self.test_update_profile)
        post_id = None
        if self.test("Create blog post", lambda: setattr(self, '_post_id', self.test_create_post())):
            post_id = self._post_id
        self.test("List own posts", self.test_list_own_posts)
        # Check public list BEFORE updating to draft
        if post_id:
            self.test("Public posts list", lambda: self.test_public_posts_list(post_id))
        if post_id:
            self.test("Update blog post", lambda: self.test_update_post(post_id))
        if post_id:
            self.test("Draft not in public list", lambda: self.test_draft_not_in_public_list(post_id))
        self.test("User logout", self.test_logout)

        # Summary
        print(f"\n{YELLOW}{'='*50}{RESET}")
        print(f"{GREEN}Passed: {self.passed}{RESET}")
        if self.failed > 0:
            print(f"{RED}Failed: {self.failed}{RESET}")
        else:
            print(f"{GREEN}All tests passed! ✓{RESET}")
        print(f"{YELLOW}{'='*50}{RESET}\n")

        return self.failed == 0


if __name__ == "__main__":
    runner = TestRunner()
    success = runner.run_all()
    sys.exit(0 if success else 1)
