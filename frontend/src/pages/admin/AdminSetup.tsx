import { FormEvent, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

interface Props {
  onSuccess: (user: { id: number; username: string }) => void;
}

export const AdminSetup = ({ onSuccess }: Props) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/admin/setup/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.detail || "Setup failed");
        return;
      }
      onSuccess({ id: data.id, username: data.username });
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="admin-portal">
      <div className="admin-card">
        <h1 className="admin-title">Admin setup</h1>
        <p className="admin-subtitle">Set your admin credentials once. This cannot be undone.</p>
        <form className="admin-form" onSubmit={handleSubmit}>
          <label className="field">
            <span>Username</span>
            <input
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </label>
          <label className="field">
            <span>Password</span>
            <input
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
            />
          </label>
          <label className="field">
            <span>Confirm password</span>
            <input
              type="password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
            />
          </label>
          {error && <div className="error">{error}</div>}
          <button className="btn-primary" type="submit" disabled={loading}>
            {loading ? "Setting up..." : "Create admin"}
          </button>
        </form>
      </div>
    </div>
  );
};
