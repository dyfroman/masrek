import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { api, type Run, ApiError } from "../api";
import StatusBadge from "../components/StatusBadge";
import ModeBadge from "../components/ModeBadge";
import Spinner from "../components/Spinner";

export default function RunHistory() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listRuns()
      .then(setRuns)
      .catch((e) => setError(e instanceof ApiError ? e.detail : "שגיאה"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="mt-16 flex justify-center"><Spinner /></div>;
  if (error) return <p className="text-accent-danger mt-8 text-center">{error}</p>;

  if (runs.length === 0) {
    return (
      <div className="text-center py-16 text-text-muted">
        <p className="text-lg">אין סריקות עדיין</p>
        <Link to="/" className="text-accent-primary hover:underline text-sm mt-2 inline-block">
          התחל סריקה ראשונה
        </Link>
      </div>
    );
  }

  // Group runs by target_host for sparklines
  const byHost: Record<string, Run[]> = {};
  for (const r of runs) {
    (byHost[r.target_host] ??= []).push(r);
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">היסטוריית סריקות</h1>

      {/* Per-target sparklines */}
      {Object.entries(byHost).map(([host, hostRuns]) => {
        const sorted = [...hostRuns].sort(
          (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
        );
        const totals = sorted.map((r) => r.summary?.total ?? 0);

        return (
          <div key={host} className="bg-surface-card border border-surface-border rounded p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="font-mono text-sm text-accent-primary" dir="ltr">{host}</span>
              <Sparkline values={totals} />
            </div>
          </div>
        );
      })}

      {/* Full table */}
      <div className="border border-surface-border rounded overflow-hidden">
        <table className="w-full text-sm" role="table">
          <thead>
            <tr className="bg-surface-panel text-text-secondary text-xs">
              <th className="px-4 py-3 text-right">יעד</th>
              <th className="px-4 py-3 text-right">זמן</th>
              <th className="px-4 py-3 text-right">מצב</th>
              <th className="px-4 py-3 text-right">סטטוס</th>
              <th className="px-4 py-3 text-right">ממצאים</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr
                key={r.run_id}
                className="border-t border-surface-border hover:bg-surface-hover transition-colors"
              >
                <td className="px-4 py-3">
                  <Link
                    to={`/results/${r.run_id}`}
                    className="text-accent-primary hover:underline font-mono text-xs"
                    dir="ltr"
                  >
                    {r.target_url}
                  </Link>
                </td>
                <td className="px-4 py-3 text-text-secondary text-xs" dir="ltr">
                  {new Date(r.created_at).toLocaleString("he-IL")}
                </td>
                <td className="px-4 py-3">
                  <ModeBadge mode={r.mode} />
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={r.status} />
                </td>
                <td className="px-4 py-3 font-mono text-sm">
                  {r.summary?.total ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Sparkline SVG ────────────────────────────────────────────────────────────

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return null;

  const w = 120;
  const h = 28;
  const max = Math.max(...values, 1);
  const step = w / (values.length - 1);

  const points = values.map((v, i) => `${i * step},${h - (v / max) * (h - 4)}`).join(" ");

  const lastVal = values[values.length - 1];
  const prevVal = values[values.length - 2];
  const trend = lastVal > prevVal ? "text-sev-high" : lastVal < prevVal ? "text-accent-success" : "text-text-muted";

  return (
    <div className="flex items-center gap-2">
      <svg
        width={w}
        height={h}
        viewBox={`0 0 ${w} ${h}`}
        className="text-accent-primary"
        aria-label={`מגמה: ${values.join(", ")}`}
        role="img"
      >
        <polyline
          points={points}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
      </svg>
      <span className={`text-xs font-mono ${trend}`}>{lastVal}</span>
    </div>
  );
}
