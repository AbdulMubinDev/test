import { Route, Routes, Navigate, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { BlogListPage } from "./pages/BlogListPage";
import { AuthPage } from "./pages/AuthPage";
import { DashboardPage } from "./pages/DashboardPage";
import { Layout } from "./components/Layout";

export interface UserInfo {
  username: string;
  email?: string;
}

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

function App() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loadingUser, setLoadingUser] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchMe = async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/me/`, {
          credentials: "include",
        });
        if (res.ok) {
          const data = await res.json();
          setUser({ username: data.user.username, email: data.user.email });
        }
      } catch {
        // ignore
      } finally {
        setLoadingUser(false);
      }
    };
    fetchMe();
  }, []);

  const handleLogout = async () => {
    await fetch(`${API_BASE}/auth/logout/`, {
      method: "POST",
      credentials: "include",
    });
    setUser(null);
    navigate("/");
  };

  if (loadingUser) {
    return (
      <div className="app-loading">
        <div className="spinner" />
      </div>
    );
  }

  return (
    <Layout user={user} onLogout={handleLogout}>
      <Routes>
        <Route path="/" element={<BlogListPage apiBase={API_BASE} />} />
        <Route
          path="/auth"
          element={<AuthPage apiBase={API_BASE} onAuthSuccess={setUser} />}
        />
        <Route
          path="/dashboard"
          element={
            user ? (
              <DashboardPage apiBase={API_BASE} />
            ) : (
              <Navigate to="/auth" replace />
            )
          }
        />
      </Routes>
    </Layout>
  );
}

export default App;

