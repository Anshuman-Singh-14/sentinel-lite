import { useEffect, useRef, useState } from "react";

// Cloudflare Turnstile, the "are you human" check. The script is loaded once, the first
// time a widget is shown, and the widget is drawn with turnstile.render (explicit mode).
// The token is single-use: to get a fresh widget after a failed submit, change its `key`.
const SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
let scriptPromise = null;

function loadTurnstile() {
  scriptPromise ??= new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = SCRIPT_URL;
    script.onload = () => resolve(window.turnstile);
    script.onerror = () => {
      scriptPromise = null; // let the next widget try again
      reject(new Error("The human check could not load"));
    };
    document.head.appendChild(script);
  });
  return scriptPromise;
}

// onToken(token) is called when the check passes, and onToken("") when it expires or fails.
export default function Turnstile({ siteKey, onToken }) {
  const box = useRef(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let widgetId;
    let cancelled = false;
    loadTurnstile()
      .then((turnstile) => {
        if (cancelled) return;
        widgetId = turnstile.render(box.current, {
          sitekey: siteKey,
          callback: onToken,
          "expired-callback": () => onToken(""),
          "error-callback": () => onToken(""),
        });
      })
      .catch((err) => setError(`${err.message}. Check your connection and reload the page.`));
    return () => {
      cancelled = true;
      if (widgetId !== undefined) window.turnstile.remove(widgetId);
    };
  }, [siteKey, onToken]);

  return (
    <div className="turnstile">
      <div ref={box} />
      {error && <p className="error small">{error}</p>}
    </div>
  );
}
