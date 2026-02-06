import { FormEvent, useEffect, useState } from "react";

interface Post {
  id: number;
  title: string;
  content: string;
  published: boolean;
}

interface Props {
  apiBase: string;
}

export const DashboardPage = ({ apiBase }: Props) => {
  const [profile, setProfile] = useState<{ display_name?: string; bio?: string }>({});
  const [posts, setPosts] = useState<Post[]>([]);
  const [editing, setEditing] = useState<Post | null>(null);
  const [form, setForm] = useState({ title: "", content: "", published: true });
  const [saving, setSaving] = useState(false);

  const loadProfileAndPosts = async () => {
    const [meRes, postsRes] = await Promise.all([
      fetch(`${apiBase}/auth/me/`, { credentials: "include" }),
      fetch(`${apiBase}/my-posts/`, { credentials: "include" }),
    ]);
    if (meRes.ok) {
      setProfile(await meRes.json());
    }
    if (postsRes.ok) {
      setPosts(await postsRes.json());
    }
  };

  useEffect(() => {
    loadProfileAndPosts();
  }, []);

  const startCreate = () => {
    setEditing(null);
    setForm({ title: "", content: "", published: true });
  };

  const startEdit = (post: Post) => {
    setEditing(post);
    setForm({
      title: post.title,
      content: post.content,
      published: post.published,
    });
  };

  const handlePostSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    const payload = {
      title: form.title,
      content: form.content,
      published: form.published,
    };
    try {
      const url = editing
        ? `${apiBase}/my-posts/${editing.id}/`
        : `${apiBase}/my-posts/`;
      const method = editing ? "PUT" : "POST";
      const res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "include",
      });
      if (res.ok) {
        await loadProfileAndPosts();
        startCreate();
      }
    } finally {
      setSaving(false);
    }
  };

  const handleProfileSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await fetch(`${apiBase}/auth/me/`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(profile),
      credentials: "include",
    });
  };

  return (
    <section className="dashboard">
      <h1 className="page-title">Your creator dashboard</h1>
      <p className="page-subtitle">
        Edit your profile, write new blogs, and manage what you&apos;ve published.
      </p>
      <div className="dashboard-grid">
        <div className="card">
          <h2>Profile</h2>
          <form className="stack" onSubmit={handleProfileSubmit}>
            <label className="field">
              <span>Display name</span>
              <input
                value={profile.display_name || ""}
                onChange={(e) =>
                  setProfile({ ...profile, display_name: e.target.value })
                }
              />
            </label>
            <label className="field">
              <span>Bio</span>
              <textarea
                rows={3}
                value={profile.bio || ""}
                onChange={(e) => setProfile({ ...profile, bio: e.target.value })}
              />
            </label>
            <button className="btn-outline" type="submit">
              Save profile
            </button>
          </form>
        </div>
        <div className="card">
          <h2>{editing ? "Edit blog post" : "Write a new blog"}</h2>
          <form className="stack" onSubmit={handlePostSubmit}>
            <label className="field">
              <span>Title</span>
              <input
                required
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
              />
            </label>
            <label className="field">
              <span>Content</span>
              <textarea
                required
                rows={6}
                value={form.content}
                onChange={(e) => setForm({ ...form, content: e.target.value })}
              />
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={form.published}
                onChange={(e) =>
                  setForm({ ...form, published: e.target.checked })
                }
              />
              <span>Publish immediately</span>
            </label>
            <button className="btn-primary" type="submit" disabled={saving}>
              {saving ? "Saving..." : editing ? "Update blog" : "Publish blog"}
            </button>
          </form>
        </div>
      </div>

      <div className="card">
        <h2>Your existing blogs</h2>
        {posts.length === 0 ? (
          <p className="muted">No posts yet. Start by writing something above.</p>
        ) : (
          <ul className="list">
            {posts.map((post) => (
              <li key={post.id} className="list-item">
                <div>
                  <div className="list-title">{post.title}</div>
                  <div className="muted">
                    {post.published ? "Published" : "Draft"} · ID #{post.id}
                  </div>
                </div>
                <button className="btn-small" onClick={() => startEdit(post)}>
                  Edit
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
};

