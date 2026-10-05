import ScanResult from "./ScanResult.jsx";

// Shared frame for the server-side tools: heading, intro, the tool's form, then
// either an error or the result. `request` comes from useRequest().
export default function ToolPage({ title, intro, request, children }) {
  return (
    <section>
      <h1>{title}</h1>
      <p className="muted">{intro}</p>
      {children}
      {request.busy && <p className="muted">Working… this can take a few seconds.</p>}
      {request.error && <p className="error card">{request.error}</p>}
      {request.data && <ScanResult scan={request.data} />}
    </section>
  );
}
