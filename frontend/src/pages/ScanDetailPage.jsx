import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api.js";
import ScanResult from "../components/ScanResult.jsx";

export default function ScanDetailPage() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api(`/api/scans/${scanId}`)
      .then(setScan)
      .catch((err) => setError(err.message));
  }, [scanId]);

  return (
    <section>
      <p>
        <Link to="/history">← Back to history</Link>
      </p>
      {error && <p className="error">{error}</p>}
      {scan && <ScanResult scan={scan} />}
    </section>
  );
}
