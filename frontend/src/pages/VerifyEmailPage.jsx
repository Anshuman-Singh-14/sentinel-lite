import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import { useRequest } from "../useRequest.js";

// Opened from the link in an email. Confirming takes a button press (a POST) because
// email security scanners open every link in an email automatically.
export default function VerifyEmailPage({ onVerified }) {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const verify = useRequest();

  async function confirm() {
    await verify.run(async () => {
      const result = await api("/api/email/verify", { method: "POST", body: { token } });
      onVerified?.();
      return result;
    });
  }

  const card = (
    <div className="card narrow">
      <h1>Confirm your email</h1>
      {!token && <p className="error">This link is incomplete. Open the whole link from the email.</p>}
      {token && !verify.data && (
        <>
          <p>Press the button to confirm this email address.</p>
          <button type="button" onClick={confirm} disabled={verify.busy}>
            {verify.busy ? "Confirming…" : "Confirm my email"}
          </button>
        </>
      )}
      {verify.data && <p>{verify.data.message}</p>}
      {verify.error && <p className="error">{verify.error}</p>}
      <p>
        <Link to="/">Go to Sentinel Lite</Link>
      </p>
    </div>
  );

  // Logged-in users (adding an email) see it inside the normal layout.
  return onVerified ? <section>{card}</section> : <div className="login">{card}</div>;
}
