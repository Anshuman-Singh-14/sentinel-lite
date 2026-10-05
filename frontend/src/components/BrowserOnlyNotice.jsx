// Shown on every browser-only tool so users know their input stays private.
export default function BrowserOnlyNotice() {
  return (
    <p className="notice">
      🔒 Runs only in your browser. What you type here is never sent to the server, saved or logged.
    </p>
  );
}
