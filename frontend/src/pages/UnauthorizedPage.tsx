import { useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";

export const UnauthorizedPage = () => {
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    // Auto-redirect to auth after 3 seconds
    const timer = setTimeout(() => {
      navigate("/auth", { state: { from: location.pathname } });
    }, 3000);

    return () => clearTimeout(timer);
  }, [navigate, location]);

  return (
    <section className="unauthorized-page">
      <div className="unauthorized-content">
        <h1 className="unauthorized-title">⛔ Access Denied</h1>
        <p className="unauthorized-message">You are not authorized to access this page.</p>
        <p className="unauthorized-subtitle">
          You will be redirected to the login page in 3 seconds...
        </p>
        <button
          className="btn-primary"
          onClick={() => navigate("/auth", { state: { from: location.pathname } })}
        >
          Go to Login
        </button>
      </div>
    </section>
  );
};
