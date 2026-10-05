import { useState } from "react";
import { api } from "../api.js";
import ToolPage from "../components/ToolPage.jsx";
import { useRequest } from "../useRequest.js";

const MAX_BYTES = 5 * 1024 * 1024;

export default function LogAnalyzerPage() {
  const [file, setFile] = useState(null);
  const scan = useRequest();

  function submit(event) {
    event.preventDefault();
    scan.run(() => {
      // Checked here for a quick message; the server checks again (it can't trust the browser).
      if (file.size > MAX_BYTES) throw new Error("The file is larger than 5 MB.");
      const form = new FormData();
      form.append("file", file);
      return api("/api/tools/log-analyzer", { method: "POST", form });
    });
  }

  return (
    <ToolPage
      title="Log analyzer"
      intro="Upload an sshd auth log or an nginx access log to find password-guessing bursts and the most suspicious IP addresses. The file is analysed in memory and never saved."
      request={scan}
    >
      <form className="card tool-form" onSubmit={submit}>
        <label>
          Log file (.log or .txt, max 5 MB)
          <input type="file" accept=".log,.txt" onChange={(e) => setFile(e.target.files[0] ?? null)} required />
        </label>
        <button type="submit" disabled={scan.busy || !file}>
          {scan.busy ? "Analysing…" : "Analyse"}
        </button>
      </form>
    </ToolPage>
  );
}
