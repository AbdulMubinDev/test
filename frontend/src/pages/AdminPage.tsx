import { useEffect, useState } from "react";
import { AdminSetup } from "./admin/AdminSetup";
import { AdminLogin } from "./admin/AdminLogin";
import { AdminDashboard } from "./admin/AdminDashboard";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

type AdminState = "loading" | "setup" | "login" | "dashboard";

export const AdminPage = () => {
  const [state, setState] = useState<AdminState>("loading");
  const [adminUser, setAdminUser] = useState<{ id: number; username: string } | null>(null);

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(`${API_BASE}/admin/status/`);
        const data = await res.json();
        if (!data.configured) {
          setState("setup");
          return;
        }
        const meRes = await fetch(`${API_BASE}/admin/me/`, { credentials: "include" });
        if (meRes.ok) {
          const me = await meRes.json();
          setAdminUser(me);
          setState("dashboard");
        } else {
          setState("login");
        }
      } catch {
        setState("login");
      }
    };
    check();
  }, []);

  const onSetupSuccess = (user: { id: number; username: string }) => {
    setAdminUser(user);
    setState("dashboard");
  };

  const onLoginSuccess = (user: { id: number; username: string }) => {
    setAdminUser(user);
    setState("dashboard");
  };

  const onLogout = () => {
    setAdminUser(null);
    setState("login");
  };

  if (state === "loading") {
    return (
      <div className="admin-loading">
        <div className="spinner" />
      </div>
    );
  }
  if (state === "setup") {
    return <AdminSetup onSuccess={onSetupSuccess} />;
  }
  if (state === "login") {
    return <AdminLogin onSuccess={onLoginSuccess} />;
  }
  return <AdminDashboard adminUser={adminUser!} onLogout={onLogout} />;
};
