import { useEffect, useState } from "react";
import BrowserOnlyNotice from "../components/BrowserOnlyNotice.jsx";
import { ALGORITHMS, hashText } from "../browser-tools/hash.js";

export default function HashPage() {
  const [text, setText] = useState("");
  const [hashes, setHashes] = useState({});

  // Recalculate every hash whenever the text changes.
  useEffect(() => {
    let current = true; // ignore results that arrive after the text changed again
    Promise.all(ALGORITHMS.map((algorithm) => hashText(text, algorithm))).then((digests) => {
      if (current) setHashes(Object.fromEntries(ALGORITHMS.map((algorithm, i) => [algorithm, digests[i]])));
    });
    return () => {
      current = false;
    };
  }, [text]);

  return (
    <section>
      <h1>Hash generator</h1>
      <p className="muted">
        A hash is a fixed-length fingerprint of some data: the same input always gives the same hash, and changing
        one character changes it completely. Use hashes to check that a downloaded file wasn't altered.
      </p>
      <BrowserOnlyNotice />
      <div className="card tool-form">
        <label>
          Text
          <textarea rows={4} value={text} onChange={(e) => setText(e.target.value)} />
        </label>
      </div>
      <table className="data hashes">
        <tbody>
          {ALGORITHMS.map((algorithm) => (
            <tr key={algorithm}>
              <th>{algorithm}</th>
              <td>
                <code>{hashes[algorithm]}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">
        SHA-1 is shown for comparison only; it is no longer safe for security uses. Plain hashes are also not suitable
        for storing passwords: use bcrypt or Argon2, which are deliberately slow (Sentinel Lite uses bcrypt).
      </p>
    </section>
  );
}
