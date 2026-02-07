import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

interface Banned {
  id: number;
  ip_address: string;
  reason: string;
  created_at: string;
}

export const AdminBannedIPs = () => {
  const [list, setList] = useState<Banned[]>([]);
  const [loading, setLoading] = useState(true);
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const fetchList = async () => {
    const res = await fetch(`${API_BASE}/admin/banned-ips/`, { credentials: "include" });
    if (res.ok) setList(await res.json());
    setLoading(false);
  };

  useEffect(() => {
    fetchList();
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const res = await fetch(`${API_BASE}/admin/banned-ips/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ ip_address: ip.trim(), reason: reason.trim() }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setError(data.detail || "Failed");
      return;
    }
    setIp("");
    setReason("");
    fetchList();
  };

  const handleRemove = async (id: number) => {
    await fetch(`${API_BASE}/admin/banned-ips/${id}/`, { method: "DELETE", credentials: "include" });
    fetchList();
  };

  if (loading) return <div className="admin-loading"><div className="spinner" /></div>;

  return (
    <div className="admin-section">
      <h2>Banned IPs</h2>
      <div className="card admin-form-card">
        <form className="stack" onSubmit={handleAdd}>
          <label className="field"><span>IP address</span><input required value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 192.168.1.1" /></label>
          <label className="field"><span>Reason (optional)</span><input value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          {error && <div className="error">{error}</div>}
          <button type="submit" className="btn-primary">Block IP</button>
        </form>
      </div>
      <div className="admin-table-wrap">
        <table className="admin-table">
          <thead>
            <tr><th>IP</th><th>Reason</th><th>Added</th><th>Action</th></tr>
          </thead>
          <tbody>
            {list.map((b) => (
              <tr key={b.id}>
                <td><code>{b.ip_address}</code></td>
                <td>{b.reason || "—"}</td>
                <td>{new Date(b.created_at).toLocaleString()}</td>
                <td><button className="btn-small" onClick={() => handleRemove(b.id)}>Unblock</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
