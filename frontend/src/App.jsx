import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api } from "./api.js";
import Layout from "./components/Layout.jsx";
import AdminPage from "./pages/AdminPage.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";
import DnsCheckPage from "./pages/DnsCheckPage.jsx";
import EncoderPage from "./pages/EncoderPage.jsx";
import HashPage from "./pages/HashPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import LogAnalyzerPage from "./pages/LogAnalyzerPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import NotFoundPage from "./pages/NotFoundPage.jsx";
import PasswordPage from "./pages/PasswordPage.jsx";
import PortScanPage from "./pages/PortScanPage.jsx";
import ScanDetailPage from "./pages/ScanDetailPage.jsx";
import WebCheckPage from "./pages/WebCheckPage.jsx";

export default function App() {
  // undefined = still checking, null = logged out, object = logged-in user
  const [user, setUser] = useState(undefined);

  useEffect(() => {
    api("/api/auth/me")
      .then(setUser)
      .catch(() => setUser(null));
  }, []);

  async function logout() {
    await api("/api/auth/logout", { method: "POST" });
    setUser(null);
  }

  if (user === undefined) return <p className="loading">Loading…</p>;
  if (user === null) return <LoginPage onLogin={setUser} />;

  return (
    <Layout user={user} onLogout={logout}>
      <Routes>
        <Route path="/" element={<DashboardPage user={user} />} />
        <Route path="/dns-check" element={<DnsCheckPage />} />
        <Route path="/port-scan" element={<PortScanPage />} />
        <Route path="/web-check" element={<WebCheckPage />} />
        <Route path="/log-analyzer" element={<LogAnalyzerPage />} />
        <Route path="/password" element={<PasswordPage />} />
        <Route path="/hash" element={<HashPage />} />
        <Route path="/encoder" element={<EncoderPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/history/:scanId" element={<ScanDetailPage />} />
        <Route
          path="/admin"
          element={user.role === "admin" ? <AdminPage user={user} /> : <Navigate to="/" />}
        />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Layout>
  );
}
