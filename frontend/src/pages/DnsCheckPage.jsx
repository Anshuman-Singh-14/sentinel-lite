import { useState } from "react";
import { api } from "../api.js";
import ToolPage from "../components/ToolPage.jsx";
import { useRequest } from "../useRequest.js";

export default function DnsCheckPage() {
  const [domain, setDomain] = useState("");
  const scan = useRequest();

  function submit(event) {
    event.preventDefault();
    scan.run(() => api("/api/tools/dns-check", { method: "POST", body: { domain } }));
  }

  return (
    <ToolPage
      title="DNS & email check"
      intro="Looks up a domain's address and mail records, and checks whether SPF and DMARC protect it against forged email."
      request={scan}
    >
      <form className="card tool-form" onSubmit={submit}>
        <label>
          Domain
          <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" required />
        </label>
        <button type="submit" disabled={scan.busy}>
          {scan.busy ? "Checking…" : "Check"}
        </button>
      </form>
    </ToolPage>
  );
}
