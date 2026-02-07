import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

interface Log {
  id: number;
  user: number | null;
  username: string | null;
  ip_address: string | null;
  path: string;
  method: string;
  action: string;
  details: Record<string, unknown>;
  created_at: string | null;
}

export const AdminAudit = () => {
  const [logs, setLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/admin/audit/?limit=100`, { credentials: "include" })
      .then((r) => r.ok ? r.json() : [])
      .then(setLogs)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="admin-loading"><div className="spinner" /></div>;

  return (
    <div className="admin-section">
      <h2>Audit log (user actions &amp; events)</h2>
      <div className="admin-table-wrap">
        <table className="admin-table">
          <thead>
            <tr><th>Time</th><th>User</th><th>IP</th><th>Action</th><th>Path</th><th>Details</th></tr>
          </thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id}>
                <td>{l.created_at ? new Date(l.created_at).toLocaleString() : "—"}</td>
                <td>{l.username ?? "—"}</td>
                <td>{l.ip_address ?? "—"}</td>
                <td>{l.action}</td>
                <td><code>{l.method} {l.path}</code></td>
                <td>{Object.keys(l.details || {}).length ? JSON.stringify(l.details) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
