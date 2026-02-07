import { Route, Routes, Navigate, useNavigate, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import { BlogListPage } from "./pages/BlogListPage";
import { AuthPage } from "./pages/AuthPage";
import { DashboardPage } from "./pages/DashboardPage";
import { UnauthorizedPage } from "./pages/UnauthorizedPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { AdminPage } from "./pages/AdminPage";
import { Layout } from "./components/Layout";

export interface UserInfo {
  username: string;
  email?: string;
}

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

// Protected route wrapper component
const ProtectedRoute = ({
  user,
  children,
  redirectUrl,
}: {
  user: UserInfo | null;
  children: React.ReactNode;
  redirectUrl?: string;
}) => {
  const location = useLocation();

  if (!user) {
    // Store the attempted URL for potential use after login
    sessionStorage.setItem(
      "unauthorized_attempt_url",
      redirectUrl || location.pathname
    );
    return <UnauthorizedPage />;
  }

  return <>{children}</>;
};

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
    <>
      <Routes>
        <Route path="/admin" element={<AdminPage />} />
        <Route path="/" element={<Layout user={user} onLogout={handleLogout}><BlogListPage apiBase={API_BASE} /></Layout>} />
        <Route
          path="/auth"
          element={
            user ? (
              <Navigate to="/dashboard" replace />
            ) : (
              <Layout user={user} onLogout={handleLogout}>
                <AuthPage apiBase={API_BASE} onAuthSuccess={setUser} />
              </Layout>
            )
          }
        />
        <Route
          path="/dashboard"
          element={
            <Layout user={user} onLogout={handleLogout}>
              <ProtectedRoute user={user} redirectUrl="/dashboard">
                <DashboardPage apiBase={API_BASE} />
              </ProtectedRoute>
            </Layout>
          }
        />
        <Route path="/unauthorized" element={<Layout user={user} onLogout={handleLogout}><UnauthorizedPage /></Layout>} />
        <Route path="/404" element={<Layout user={user} onLogout={handleLogout}><NotFoundPage /></Layout>} />
        <Route path="*" element={<Layout user={user} onLogout={handleLogout}><NotFoundPage /></Layout>} />
      </Routes>
    </>
  );
}

export default App;
