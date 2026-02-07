import { useState, useEffect } from "react";
import { AdminUsers } from "./AdminUsers";
import { AdminAudit } from "./AdminAudit";
import { AdminTraffic } from "./AdminTraffic";
import { AdminAttacks } from "./AdminAttacks";
import { AdminBannedIPs } from "./AdminBannedIPs";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

type Tab = "users" | "audit" | "traffic" | "attacks" | "banned";

interface Props {
  adminUser: { id: number; username: string };
  onLogout: () => void;
}

export const AdminDashboard = ({ adminUser, onLogout }: Props) => {
  const [tab, setTab] = useState<Tab>("users");

  const handleLogout = async () => {
    await fetch(`${API_BASE}/admin/logout/`, { method: "POST", credentials: "include" });
    onLogout();
  };

  return (
    <div className="admin-portal admin-dashboard">
      <header className="admin-header">
        <h1 className="admin-brand">Admin</h1>
        <div className="admin-header-right">
          <span className="admin-user-name">{adminUser.username}</span>
          <button className="btn-outline btn-small" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </header>
      <nav className="admin-tabs">
        {(["users", "audit", "traffic", "attacks", "banned"] as const).map((t) => (
          <button
            key={t}
            type="button"
            className={tab === t ? "admin-tab active" : "admin-tab"}
            onClick={() => setTab(t)}
          >
            {t === "users" && "Users"}
            {t === "audit" && "Audit"}
            {t === "traffic" && "Traffic"}
            {t === "attacks" && "Attacks"}
            {t === "banned" && "Banned IPs"}
          </button>
        ))}
      </nav>
      <main className="admin-main">
        {tab === "users" && <AdminUsers />}
        {tab === "audit" && <AdminAudit />}
        {tab === "traffic" && <AdminTraffic />}
        {tab === "attacks" && <AdminAttacks />}
        {tab === "banned" && <AdminBannedIPs />}
      </main>
    </div>
  );
};
