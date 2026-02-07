import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

interface Log {
  id: number;
  ip_address: string | null;
  path: string;
  method: string;
  details: Record<string, unknown>;
  created_at: string | null;
}

export const AdminAttacks = () => {
  const [logs, setLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/admin/attacks/?limit=100`, { credentials: "include" })
      .then((r) => r.ok ? r.json() : [])
      .then(setLogs)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="admin-loading"><div className="spinner" /></div>;

  return (
    <div className="admin-section">
      <h2>Unauthorized / attack attempts</h2>
      <div className="admin-table-wrap">
        <table className="admin-table">
          <thead>
            <tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Details</th></tr>
          </thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id}>
                <td>{l.created_at ? new Date(l.created_at).toLocaleString() : "—"}</td>
                <td>{l.ip_address ?? "—"}</td>
                <td>{l.method}</td>
                <td><code>{l.path}</code></td>
                <td className="muted">{l.details && (l.details as { user_agent?: string }).user_agent ? String((l.details as { user_agent?: string }).user_agent).slice(0, 60) + "…" : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
