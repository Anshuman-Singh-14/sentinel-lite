import { useState } from "react";

// Tracks one API call for a page: is it running, what came back, what went wrong.
//   const scan = useRequest();
//   scan.run(() => api("/api/...", {...}));
//   scan.busy / scan.data / scan.error
export function useRequest() {
  const [state, setState] = useState({ busy: false, data: null, error: "" });

  async function run(call) {
    setState({ busy: true, data: null, error: "" });
    try {
      setState({ busy: false, data: await call(), error: "" });
    } catch (err) {
      setState({ busy: false, data: null, error: err.message });
    }
  }

  return { ...state, run };
}
