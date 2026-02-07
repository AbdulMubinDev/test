import { FormEvent, useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
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
  const [showUnauthorizedMessage, setShowUnauthorizedMessage] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    // Check if user was redirected from unauthorized access
    if (location.state && (location.state as { from?: string }).from) {
      setShowUnauthorizedMessage(true);
      // Clear the state to prevent showing the message on page refresh
      navigate(location.pathname, { replace: true });
    }

    // Also check sessionStorage for unauthorized attempt
    const unauthorizedAttempt = sessionStorage.getItem("unauthorized_attempt_url");
    if (unauthorizedAttempt) {
      setShowUnauthorizedMessage(true);
      sessionStorage.removeItem("unauthorized_attempt_url");
    }
  }, [location, navigate]);

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
      {showUnauthorizedMessage && (
        <div className="unauthorized-notice">
          <span className="unauthorized-notice-icon">⚠️</span>
          <span>You are not authorized to access that page. Please login first.</span>
        </div>
      )}
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
