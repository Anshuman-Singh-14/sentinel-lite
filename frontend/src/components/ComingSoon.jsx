// Placeholder used by pages that are not built yet.
export default function ComingSoon({ title, children }) {
  return (
    <section>
      <h1>{title}</h1>
      {children}
      <p className="muted">This page is not built yet.</p>
    </section>
  );
}
