// Password strength checker. Runs only in the browser: never import api.js here.

// A few of the most common leaked passwords. A password containing one of these
// is guessed almost instantly, however many symbols are added around it.
export const COMMON_PASSWORDS = [
  "password", "123456", "12345678", "qwerty", "abc123", "111111", "iloveyou", "admin",
  "welcome", "letmein", "monkey", "dragon", "football", "sunshine", "princess", "master",
  "login", "passw0rd", "1q2w3e4r", "000000",
];

const LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
const SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
const GUESSES_PER_SECOND = 1e10; // a fast offline attack on a leaked, weakly hashed password

// Characters an attacker has to try for each kind of character the password uses.
function poolSize(password) {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;
  return pool;
}

function hasSequence(password) {
  const lower = password.toLowerCase();
  for (let i = 0; i + 3 <= lower.length; i++) {
    const chunk = lower.slice(i, i + 3);
    if (SEQUENCES.some((seq) => seq.includes(chunk))) return true;
  }
  return false;
}

export function describeSeconds(seconds) {
  const units = [
    ["year", 31_536_000], ["day", 86_400], ["hour", 3600], ["minute", 60], ["second", 1],
  ];
  if (seconds > 31_536_000 * 1e6) return "millions of years";
  for (const [name, size] of units) {
    if (seconds >= size) {
      const count = Math.floor(seconds / size);
      return `${count.toLocaleString()} ${name}${count === 1 ? "" : "s"}`;
    }
  }
  return "less than a second";
}

// Returns { score: 0-4, label, tips, entropyBits, crackTime }.
export function checkPassword(password) {
  const length = [...password].length; // counts emoji as one character
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  const entropyBits = length * Math.log2(poolSize(password) || 1);
  const tips = [];

  let score = 0;
  if (length >= 8) score++;
  if (length >= 12) score++;
  if (length >= 16) score++;
  if (kinds >= 3) score++;

  if (length < 12) tips.push("Use at least 12 characters. Length matters more than anything else.");
  if (kinds < 3) tips.push("Mix lowercase, uppercase, numbers and symbols.");
  if (/(.)\1\1/.test(password)) {
    score--;
    tips.push("Avoid repeating the same character (like \"aaa\").");
  }
  if (hasSequence(password)) {
    score--;
    tips.push("Avoid sequences like \"abc\", \"123\" or \"qwerty\".");
  }
  const lower = password.toLowerCase();
  const common = COMMON_PASSWORDS.find((word) => lower.includes(word));
  if (common) {
    score = 0;
    tips.unshift(`It contains "${common}", one of the most common passwords. Attackers try these first.`);
  }
  if (tips.length === 0) tips.push("Good password. Use a different one for every site; a password manager helps.");

  score = Math.max(0, Math.min(4, score));
  // Common passwords are in every attacker's list, so the entropy estimate doesn't apply to them.
  const seconds = common ? 0 : 2 ** entropyBits / 2 / GUESSES_PER_SECOND;
  return { score, label: LABELS[score], tips, entropyBits: Math.round(entropyBits), crackTime: describeSeconds(seconds) };
}
