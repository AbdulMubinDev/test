import { FormEvent, useState } from "react";
import type { UserInfo } from "../App";

interface Props {
  apiBase: string;
  onAuthSuccess: (user: UserInfo) => void;
}

export const AuthPage = ({ apiBase, onAuthSuccess }: Props) => {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      if (mode === "register") {
        const res = await fetch(`${apiBase}/auth/register/`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: form.username,
            email: form.email || undefined,
            password: form.password,
          }),
          credentials: "include",
        });
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          setError(data.detail || "Registration failed");
          return;
        }
      }
      const res = await fetch(`${apiBase}/auth/login/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: form.username,
          password: form.password,
        }),
        credentials: "include",
      });
      if (!res.ok) {
        setError("Invalid credentials");
        return;
      }
      const data = await res.json();
      onAuthSuccess({ username: data.username, email: data.email });
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="auth-section">
      <h1 className="page-title">
        {mode === "login" ? "Welcome back" : "Create an account"}
      </h1>
      <p className="page-subtitle">
        {mode === "login"
          ? "Sign in to access your dashboard and manage your blogs."
          : "Sign up to start writing and publishing your own posts."}
      </p>
      <div className="toggle-row">
        <button
          type="button"
          className={mode === "login" ? "pill active" : "pill"}
          onClick={() => setMode("login")}
        >
          Login
        </button>
        <button
          type="button"
          className={mode === "register" ? "pill active" : "pill"}
          onClick={() => setMode("register")}
        >
          Register
        </button>
      </div>
      <form className="card form-card" onSubmit={handleSubmit}>
        <label className="field">
          <span>Username</span>
          <input
            required
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
          />
        </label>
        {mode === "register" && (
          <label className="field">
            <span>Email (optional)</span>
            <input
              type="email"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
            />
          </label>
        )}
        <label className="field">
          <span>Password</span>
          <input
            type="password"
            required
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
          />
        </label>
        {error && <div className="error">{error}</div>}
        <button className="btn-primary" type="submit" disabled={loading}>
          {loading ? "Please wait..." : mode === "login" ? "Login" : "Register & Login"}
        </button>
      </form>
    </section>
  );
};

