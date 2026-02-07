import { Link } from "react-router-dom";

export const NotFoundPage = () => {
  return (
    <section className="notfound-page">
      <div className="notfound-content">
        <div className="notfound-code">404</div>
        <h1 className="notfound-title">Page not found</h1>
        <p className="notfound-message">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <Link to="/" className="btn-primary notfound-link">
          Go to homepage
        </Link>
      </div>
    </section>
  );
};
