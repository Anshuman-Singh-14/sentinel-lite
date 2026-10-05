import { useState } from "react";
import BrowserOnlyNotice from "../components/BrowserOnlyNotice.jsx";
import { checkPassword } from "../browser-tools/password.js";

export default function PasswordPage() {
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const result = password ? checkPassword(password) : null;

  return (
    <section>
      <h1>Password strength</h1>
      <p className="muted">See how long a password would survive a guessing attack, and how to make it stronger.</p>
      <BrowserOnlyNotice />
      <div className="card tool-form">
        <label>
          Password
          <input
            type={visible ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="inline">
          <input type="checkbox" checked={visible} onChange={(e) => setVisible(e.target.checked)} />
          Show password
        </label>
      </div>

      {result && (
        <div className="card">
          <div className="meter" aria-label={`Strength ${result.score} of 4`}>
            {[0, 1, 2, 3].map((step) => (
              <span key={step} className={step < result.score ? `filled score-${result.score}` : ""} />
            ))}
          </div>
          <h2>{result.label}</h2>
          <p>
            Rough time to crack with a fast offline attack: <strong>{result.crackTime}</strong>
            <span className="muted small"> (about {result.entropyBits} bits of randomness if chosen at random)</span>
          </p>
          <ul>
            {result.tips.map((tip) => (
              <li key={tip}>{tip}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
