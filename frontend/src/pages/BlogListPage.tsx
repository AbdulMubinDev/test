import { useEffect, useState } from "react";

interface BlogPost {
  id: number;
  title: string;
  content: string;
  author_username: string;
  created_at: string;
}

interface Props {
  apiBase: string;
}

export const BlogListPage = ({ apiBase }: Props) => {
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${apiBase}/posts/`);
        if (res.ok) {
          const data = await res.json();
          setPosts(data);
        }
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [apiBase]);

  return (
    <section>
      <h1 className="page-title">Latest published blogs</h1>
      <p className="page-subtitle">
        Curated posts in rich blues and warm gold tones.
      </p>
      {loading ? (
        <div className="card centered">
          <div className="spinner" />
        </div>
      ) : posts.length === 0 ? (
        <div className="card centered">No blogs published yet.</div>
      ) : (
        <div className="grid">
          {posts.map((post) => (
            <article key={post.id} className="card blog-card">
              <h2>{post.title}</h2>
              <p className="muted">by {post.author_username}</p>
              <p className="snippet">
                {post.content.length > 200
                  ? post.content.slice(0, 200) + "..."
                  : post.content}
              </p>
              <p className="meta">
                {new Date(post.created_at).toLocaleString(undefined, {
                  dateStyle: "medium",
                  timeStyle: "short",
                })}
              </p>
            </article>
          ))}
        </div>
      )}
    </section>
  );
};

