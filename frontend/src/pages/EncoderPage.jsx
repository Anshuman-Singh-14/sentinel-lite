import { useState } from "react";
import BrowserOnlyNotice from "../components/BrowserOnlyNotice.jsx";
import { convert } from "../browser-tools/encoder.js";

export default function EncoderPage() {
  const [text, setText] = useState("");
  const [mode, setMode] = useState("base64");
  const [direction, setDirection] = useState("encode");

  let output = "";
  let error = "";
  try {
    output = convert(text, mode, direction);
  } catch (err) {
    error = err.message;
  }

  return (
    <section>
      <h1>Encoder / decoder</h1>
      <p className="muted">
        Base64 and URL encoding change how data is written so it can travel safely in emails, URLs or JSON. They are
        not encryption: anyone can decode them.
      </p>
      <BrowserOnlyNotice />
      <div className="card tool-form">
        <div className="row">
          <label>
            Format
            <select value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="base64">Base64</option>
              <option value="url">URL encoding</option>
            </select>
          </label>
          <label>
            Direction
            <select value={direction} onChange={(e) => setDirection(e.target.value)}>
              <option value="encode">Encode</option>
              <option value="decode">Decode</option>
            </select>
          </label>
        </div>
        <label>
          Input
          <textarea rows={4} value={text} onChange={(e) => setText(e.target.value)} />
        </label>
        <label>
          Output
          <textarea rows={4} value={output} readOnly />
        </label>
        {error && <p className="error">{error}</p>}
      </div>
    </section>
  );
}
