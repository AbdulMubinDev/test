import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "/api";

interface User {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  date_joined: string | null;
}

export const AdminUsers = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<User | null>(null);
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const [createMode, setCreateMode] = useState(false);
  const [editForm, setEditForm] = useState({ email: "", password: "", is_active: true });
  const [error, setError] = useState<string | null>(null);

  const fetchUsers = async () => {
    const res = await fetch(`${API_BASE}/admin/users/`, { credentials: "include" });
    if (res.ok) setUsers(await res.json());
    setLoading(false);
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const res = await fetch(`${API_BASE}/admin/users/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username: form.username, email: form.email, password: form.password }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setError(data.detail || "Failed");
      return;
    }
    setCreateMode(false);
    setForm({ username: "", email: "", password: "" });
    fetchUsers();
  };

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editing) return;
    setError(null);
    const body: { email?: string; password?: string; is_active?: boolean } = { email: editForm.email, is_active: editForm.is_active };
    if (editForm.password) body.password = editForm.password;
    const res = await fetch(`${API_BASE}/admin/users/${editing.id}/`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setError(data.detail || "Failed");
      return;
    }
    setEditing(null);
    fetchUsers();
  };

  const handleBan = async (u: User) => {
    await fetch(`${API_BASE}/admin/users/${u.id}/ban/`, { method: "POST", credentials: "include" });
    fetchUsers();
  };
  const handleUnban = async (u: User) => {
    await fetch(`${API_BASE}/admin/users/${u.id}/unban/`, { method: "POST", credentials: "include" });
    fetchUsers();
  };
  const handleDelete = async (u: User) => {
    if (!confirm(`Remove user "${u.username}"?`)) return;
    await fetch(`${API_BASE}/admin/users/${u.id}/`, { method: "DELETE", credentials: "include" });
    setEditing(null);
    fetchUsers();
  };

  if (loading) return <div className="admin-loading"><div className="spinner" /></div>;

  return (
    <div className="admin-section">
      <div className="admin-section-header">
        <h2>Users</h2>
        <button className="btn-primary btn-small" onClick={() => { setCreateMode(true); setError(null); }}>
          Add user
        </button>
      </div>
      {createMode && (
        <div className="card admin-form-card">
          <h3>Create user</h3>
          <form className="stack" onSubmit={handleCreate}>
            <label className="field"><span>Username</span><input required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
            <label className="field"><span>Email</span><input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
            <label className="field"><span>Password</span><input type="password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
            {error && <div className="error">{error}</div>}
            <div className="admin-form-actions">
              <button type="submit" className="btn-primary">Create</button>
              <button type="button" className="btn-outline" onClick={() => setCreateMode(false)}>Cancel</button>
            </div>
          </form>
        </div>
      )}
      {editing && (
        <div className="card admin-form-card">
          <h3>Edit user: {editing.username}</h3>
          <form className="stack" onSubmit={handleUpdate}>
            <label className="field"><span>Email</span><input type="email" value={editForm.email} onChange={(e) => setEditForm({ ...editForm, email: e.target.value })} /></label>
            <label className="field"><span>New password (leave blank to keep)</span><input type="password" value={editForm.password} onChange={(e) => setEditForm({ ...editForm, password: e.target.value })} /></label>
            <label className="checkbox"><input type="checkbox" checked={editForm.is_active} onChange={(e) => setEditForm({ ...editForm, is_active: e.target.checked })} /><span>Active</span></label>
            {error && <div className="error">{error}</div>}
            <div className="admin-form-actions">
              <button type="submit" className="btn-primary">Save</button>
              <button type="button" className="btn-outline" onClick={() => setEditing(null)}>Cancel</button>
              <button type="button" className="btn-small" style={{ marginLeft: "auto", color: "#f87171" }} onClick={() => handleDelete(editing)}>Remove user</button>
            </div>
          </form>
        </div>
      )}
      <div className="admin-table-wrap">
        <table className="admin-table">
          <thead>
            <tr><th>ID</th><th>Username</th><th>Email</th><th>Active</th><th>Joined</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.id}</td>
                <td>{u.username}</td>
                <td>{u.email || "—"}</td>
                <td>{u.is_active ? "Yes" : "No"}</td>
                <td>{u.date_joined ? new Date(u.date_joined).toLocaleString() : "—"}</td>
                <td>
                  <button className="btn-small" onClick={() => { setEditing(u); setEditForm({ email: u.email, password: "", is_active: u.is_active }); setError(null); }}>Edit</button>
                  {u.is_active ? <button className="btn-small" onClick={() => handleBan(u)}>Ban</button> : <button className="btn-small" onClick={() => handleUnban(u)}>Unban</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
