# Blue & Gold Blog – React + Django + Postgres + Redis

This is a simple three-page blog platform with a **React** frontend, **Django REST** backend, **PostgreSQL** for persistence, and **Redis** for caching/sessions. All pieces run in Docker containers, including an **internal networking proxy** between the backend and the DB layer.

### Pages

- **Blogs page (`/`)**: Public list of published blog posts.
- **Auth page (`/auth`)**: Sign up and login using username/password.
- **Dashboard page (`/dashboard`)**: Authenticated user dashboard where users can:
  - Edit their profile (display name + bio)
  - Create new blogs and decide to publish or keep as draft
  - Edit their existing blogs (title, content, published flag)

### Containers & Architecture

- **`frontend`** (React, Vite, served by nginx inside the container, **listens on port 80**)
- **`backend`** (Django + Django REST Framework + Gunicorn, listens on port 8000)
- **`db`** (PostgreSQL, internal-only, no host port exposure)
- **`redis`** (Redis cache / session store, internal-only)
- **`internal_proxy`** (nginx in TCP `stream` mode; internal networking router between backend and DB/cache)

**Note**: The public-facing nginx (with DNS, WAF, UFW) runs on your VPS, not in Docker. It proxies to the containers.

### Request Flow (Blog Read)

When a user reads a blog post list on the public blogs page, the conceptual flow is:

1. **User request** – browser navigates to the blog URL.
2. **DNS** – resolves your blog domain to the public entrypoint (e.g. a load balancer / IP).
3. **WAF** – optional web application firewall in front of the cluster.
4. **VPS Nginx** (on your VPS, not in Docker) – terminates HTTP and routes:
   - `/` → `http://127.0.0.1:80` (frontend container)
   - `/api/` → `http://127.0.0.1:8000` (backend container)
5. **Frontend** – React app calls `/api/posts/` via VPS nginx.
6. **VPS Nginx** – proxies `/api/posts/` to the `backend` container on port 8000.
7. **Backend** – Django REST API queries the DB through the internal proxy:
   - Connects to `internal_proxy:5432` (Postgres via internal nginx stream)
   - Optionally uses Redis via `internal_proxy:6379`
8. **DB / Cache** – Postgres and Redis respond back through `internal_proxy` to the backend.
9. **Backend** – serializes the blog data as JSON.
10. **VPS Nginx** – forwards the JSON back to the frontend.
11. **Frontend** – renders the blogs in a blue & gold themed UI.
12. **User** – sees the published blogs.

In shorthand, this maps closely to your desired workflow:

`user req -> DNS -> WAF -> VPS Nginx -> frontend:80 -> VPS Nginx -> backend:8000 -> internal_proxy -> db/redis -> backend -> VPS Nginx -> frontend (rendered) -> VPS Nginx -> user`

### Running Locally

From the project root:

```bash
./run.sh
```

This builds and starts all containers. With the default production compose, only port 80 is exposed. Then:
- **Site (frontend + API)**: `http://localhost`
- **Admin portal**: `http://localhost/admin`

### Testing

Run the comprehensive test suite to validate everything works before deploying to production:

```bash
./test.sh
```

This runs:
1. **Backend unit tests** (pytest) - Tests Django API endpoints, models, authentication
2. **Integration/E2E tests** - Tests full user flows: registration → login → profile → create/edit posts → public visibility

All tests must pass before deploying to your VPS.

### Security and URL access

- **Protected routes**: `/dashboard` and `/admin` are enforced on both frontend and backend. Visiting them via URL without being logged in shows the login/unauthorized screen; the API returns 401/403 for unauthenticated or unauthorized requests.
- **No URL manipulation**: Users cannot access another user’s data by changing IDs in the URL; the backend filters all “my-posts” and profile endpoints by the authenticated user.

### Key Endpoints

- `GET /api/posts/` – public list of published blog posts.
- `POST /api/auth/register/` – create user.
- `POST /api/auth/login/` – login (session cookie).
- `POST /api/auth/logout/` – logout.
- `GET/PUT /api/auth/me/` – get or update profile.
- `GET/POST /api/my-posts/` – list or create your own posts.
- `GET/PUT /api/my-posts/<id>/` – retrieve or update an existing post.

