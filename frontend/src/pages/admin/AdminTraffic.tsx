import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

interface Log {
  id: number;
  ip_address: string | null;
  path: string;
  method: string;
  status_code: number | null;
  user_agent: string;
  created_at: string | null;
}

export const AdminTraffic = () => {
  const [logs, setLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/admin/traffic/?limit=100`, { credentials: "include" })
      .then((r) => r.ok ? r.json() : [])
      .then(setLogs)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="admin-loading"><div className="spinner" /></div>;

  return (
    <div className="admin-section">
      <h2>Traffic (API requests)</h2>
      <div className="admin-table-wrap">
        <table className="admin-table">
          <thead>
            <tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th><th>User-Agent</th></tr>
          </thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id}>
                <td>{l.created_at ? new Date(l.created_at).toLocaleString() : "—"}</td>
                <td>{l.ip_address ?? "—"}</td>
                <td>{l.method}</td>
                <td><code>{l.path}</code></td>
                <td>{l.status_code ?? "—"}</td>
                <td className="muted">{l.user_agent || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
