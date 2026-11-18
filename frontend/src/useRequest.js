import { useState } from "react";

// Tracks one API call for a page: is it running, what came back, what went wrong.
//   const scan = useRequest();
//   scan.run(() => api("/api/...", {...}));
//   scan.busy / scan.data / scan.error / scan.status (the HTTP status of an error, if any)
const IDLE = { busy: false, data: null, error: "", status: null };

export function useRequest() {
  const [state, setState] = useState(IDLE);

  async function run(call) {
    setState({ ...IDLE, busy: true });
    try {
      setState({ ...IDLE, data: await call() });
    } catch (err) {
      setState({ ...IDLE, error: err.message, status: err.status ?? null });
    }
  }

  return { ...state, run };
}
