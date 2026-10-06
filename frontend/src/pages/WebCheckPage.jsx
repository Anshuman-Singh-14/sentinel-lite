import { useState } from "react";
import { api } from "../api.js";
import ToolPage from "../components/ToolPage.jsx";
import { useRequest } from "../useRequest.js";

export default function WebCheckPage() {
  const [target, setTarget] = useState("");
  const scan = useRequest();

  function submit(event) {
    event.preventDefault();
    scan.run(() => api("/api/tools/web-check", { method: "POST", body: { target } }));
  }

  return (
    <ToolPage
      title="Website check"
      intro="Checks that a website uses HTTPS, when its certificate expires, and whether it sends 6 key security headers. Only targets approved by an admin can be checked."
      request={scan}
    >
      <form className="card tool-form" onSubmit={submit}>
        <label>
          Website (hostname only, no https://)
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" required />
        </label>
        <button type="submit" disabled={scan.busy}>
          {scan.busy ? "Checking…" : "Check"}
        </button>
      </form>
    </ToolPage>
  );
}
