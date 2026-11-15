import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api } from "./api.js";
import Layout from "./components/Layout.jsx";
import ActivityPage from "./pages/ActivityPage.jsx";
import AdminPage from "./pages/AdminPage.jsx";
import ChangePasswordPage from "./pages/ChangePasswordPage.jsx";
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
import RequestAccessPage from "./pages/RequestAccessPage.jsx";
import ScanDetailPage from "./pages/ScanDetailPage.jsx";
import VerifyEmailPage from "./pages/VerifyEmailPage.jsx";
import WebCheckPage from "./pages/WebCheckPage.jsx";

export default function App() {
  // undefined = still checking, null = logged out, object = logged-in user
  const [user, setUser] = useState(undefined);

  const loadUser = useCallback(() => {
    api("/api/auth/me")
      .then(setUser)
      .catch(() => setUser(null));
  }, []);

  useEffect(loadUser, [loadUser]);

  async function logout() {
    await api("/api/auth/logout", { method: "POST" });
    setUser(null);
  }

  if (user === undefined) return <p className="loading">Loading…</p>;

  if (user === null) {
    // Logged out: only the account request pages are reachable; everything else is the login form.
    return (
      <Routes>
        <Route path="/request-access" element={<RequestAccessPage />} />
        <Route path="/verify-email" element={<VerifyEmailPage />} />
        <Route path="*" element={<LoginPage onLogin={setUser} />} />
      </Routes>
    );
  }

  // The server refuses everything else until the password is changed, so show nothing else.
  if (user.must_change_password) return <ChangePasswordPage forced onChanged={setUser} onLogout={logout} />;

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
        <Route path="/account/password" element={<ChangePasswordPage onChanged={setUser} />} />
        <Route path="/verify-email" element={<VerifyEmailPage onVerified={loadUser} />} />
        <Route
          path="/admin"
          element={user.role === "admin" ? <AdminPage user={user} /> : <Navigate to="/" />}
        />
        <Route
          path="/admin/activity"
          element={user.role === "admin" ? <ActivityPage /> : <Navigate to="/" />}
        />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Layout>
  );
}
