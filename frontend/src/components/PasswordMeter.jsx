import { checkPassword } from "../browser-tools/password.js";

// A small strength bar under a "choose a password" field (same checker as the Password strength tool).
export default function PasswordMeter({ password }) {
  if (!password) return null;
  const result = checkPassword(password);
  return (
    <div className="password-meter">
      <div className="meter" aria-label={`Strength ${result.score} of 4`}>
        {[0, 1, 2, 3].map((step) => (
          <span key={step} className={step < result.score ? `filled score-${result.score}` : ""} />
        ))}
      </div>
      <p className="muted small">
        {result.label}. {result.tips[0]}
      </p>
    </div>
  );
}
