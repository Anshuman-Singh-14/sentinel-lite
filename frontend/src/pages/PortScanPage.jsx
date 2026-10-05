import { useState } from "react";
import { api } from "../api.js";
import ToolPage from "../components/ToolPage.jsx";
import { useRequest } from "../useRequest.js";

const MAX_PORTS = 100;

// "22, 80, 8000-8005" -> [22, 80, 8000, 8001, ..., 8005]. Throws an Error with a helpful message.
export function parsePorts(text) {
  const ports = new Set();
  for (const part of text.split(",").map((p) => p.trim()).filter(Boolean)) {
    const [start, end = start] = part.split("-").map((n) => Number(n.trim()));
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > 65535 || start > end) {
      throw new Error(`"${part}" is not a valid port or range (1-65535).`);
    }
    for (let port = start; port <= end && ports.size <= MAX_PORTS; port++) ports.add(port);
  }
  if (ports.size === 0) throw new Error("Enter at least one port.");
  if (ports.size > MAX_PORTS) throw new Error(`At most ${MAX_PORTS} ports per scan.`);
  return [...ports];
}

export default function PortScanPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("common");
  const [portText, setPortText] = useState("");
  const scan = useRequest();

  function submit(event) {
    event.preventDefault();
    scan.run(() => {
      const ports = mode === "common" ? null : parsePorts(portText);
      return api("/api/tools/port-scan", { method: "POST", body: { target, ports } });
    });
  }

  return (
    <ToolPage
      title="Port scan"
      intro="Checks which TCP ports accept connections. Only targets approved by an admin can be scanned."
      request={scan}
    >
      <form className="card tool-form" onSubmit={submit}>
        <label>
          Target (hostname or IPv4 address)
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" required />
        </label>
        <fieldset>
          <legend>Ports</legend>
          <label className="inline">
            <input type="radio" checked={mode === "common"} onChange={() => setMode("common")} />
            Common ports (about 20 well-known services)
          </label>
          <label className="inline">
            <input type="radio" checked={mode === "custom"} onChange={() => setMode("custom")} />
            My own list
          </label>
          {mode === "custom" && (
            <input
              value={portText}
              onChange={(e) => setPortText(e.target.value)}
              placeholder="22, 80, 443, 8000-8010 (max 100)"
              required
            />
          )}
        </fieldset>
        <button type="submit" disabled={scan.busy}>
          {scan.busy ? "Scanning…" : "Scan"}
        </button>
      </form>
    </ToolPage>
  );
}
