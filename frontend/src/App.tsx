import { Routes, Route, Link, useLocation } from "react-router-dom";
import ScanLauncher from "./views/ScanLauncher";
import RunProgress from "./views/RunProgress";
import RunResults from "./views/RunResults";
import RunHistory from "./views/RunHistory";
import Settings from "./views/Settings";

const NAV: { path: string; label: string }[] = [
  { path: "/", label: "סריקה חדשה" },
  { path: "/history", label: "היסטוריה" },
  { path: "/settings", label: "הגדרות" },
];

export default function App() {
  const loc = useLocation();

  return (
    <div className="min-h-screen flex flex-col">
      {/* ── Header ──────────────────────────────────────────────── */}
      <header className="bg-surface-panel border-b border-surface-border px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link to="/" className="text-xl font-bold text-accent-primary tracking-wide">
            מסרק
          </Link>
          <span className="text-xs text-text-muted font-mono">Masrek DevSecOps</span>
        </div>

        <nav className="flex gap-1" role="navigation" aria-label="ניווט ראשי">
          {NAV.map((n) => (
            <Link
              key={n.path}
              to={n.path}
              className={`px-3 py-1.5 rounded text-sm transition-colors ${
                loc.pathname === n.path
                  ? "bg-accent-primary/20 text-accent-primary"
                  : "text-text-secondary hover:text-text-primary hover:bg-surface-hover"
              }`}
            >
              {n.label}
            </Link>
          ))}
        </nav>
      </header>

      {/* ── Main ────────────────────────────────────────────────── */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full">
        <Routes>
          <Route path="/" element={<ScanLauncher />} />
          <Route path="/run/:id" element={<RunProgress />} />
          <Route path="/results/:id" element={<RunResults />} />
          <Route path="/history" element={<RunHistory />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
