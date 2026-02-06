import { Link, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import type { UserInfo } from "../App";

interface Props {
  children: ReactNode;
  user: UserInfo | null;
  onLogout: () => void;
}

export const Layout = ({ children, user, onLogout }: Props) => {
  const location = useLocation();

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">BG</span>
          <span className="brand-text">Blue &amp; Gold Blog</span>
        </div>
        <nav className="nav-links">
          <Link
            to="/"
            className={location.pathname === "/" ? "nav-link active" : "nav-link"}
          >
            Blogs
          </Link>
          <Link
            to="/auth"
            className={
              location.pathname.startsWith("/auth") ? "nav-link active" : "nav-link"
            }
          >
            Sign in / Sign up
          </Link>
          <Link
            to="/dashboard"
            className={
              location.pathname.startsWith("/dashboard")
                ? "nav-link active"
                : "nav-link"
            }
          >
            Dashboard
          </Link>
        </nav>
        <div className="user-area">
          {user ? (
            <>
              <span className="user-name">Hi, {user.username}</span>
              <button className="btn-outline" onClick={onLogout}>
                Logout
              </button>
            </>
          ) : (
            <span className="user-name subtle">Guest</span>
          )}
        </div>
      </header>
      <main className="app-main">{children}</main>
      <footer className="app-footer">
        Built with a blue &amp; gold palette · Demo blog platform
      </footer>
    </div>
  );
};

