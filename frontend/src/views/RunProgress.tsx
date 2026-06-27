import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { api, type RunDetail, ApiError } from "../api";
import StatusBadge from "../components/StatusBadge";
import ModeBadge from "../components/ModeBadge";
import Spinner from "../components/Spinner";

const TERMINAL = new Set(["done", "failed", "timeout"]);

export default function RunProgress() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [run, setRun] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    const poll = async () => {
      try {
        const data = await api.getRun(id);
        if (cancelled) return;
        setRun(data);
        if (TERMINAL.has(data.status)) {
          if (data.status === "done") {
            navigate(`/results/${id}`, { replace: true });
          }
          return;
        }
        setTimeout(poll, 2000);
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError) setError(e.detail);
        else setError("שגיאה בלתי צפויה");
      }
    };

    poll();
    return () => { cancelled = true; };
  }, [id, navigate]);

  if (error) {
    return (
      <div className="max-w-xl mx-auto mt-16 text-center space-y-4">
        <p className="text-accent-danger">{error}</p>
        <button
          onClick={() => navigate("/")}
          className="text-accent-primary hover:underline"
        >
          חזרה לסריקה חדשה
        </button>
      </div>
    );
  }

  if (!run) return <div className="mt-16 flex justify-center"><Spinner label="טוען סריקה..." /></div>;

  return (
    <div className="max-w-xl mx-auto mt-8 space-y-6">
      <h1 className="text-2xl font-bold">מעקב סריקה</h1>

      <div className="bg-surface-card border border-surface-border rounded p-6 space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-text-secondary text-sm">סטטוס</span>
          <StatusBadge status={run.status} />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-text-secondary text-sm">יעד</span>
          <span className="font-mono text-sm" dir="ltr">{run.target_url}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-text-secondary text-sm">מצב</span>
          <ModeBadge mode={run.mode} />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-text-secondary text-sm">זמן התחלה</span>
          <span className="text-sm text-text-secondary" dir="ltr">
            {new Date(run.created_at).toLocaleString("he-IL")}
          </span>
        </div>

        {!TERMINAL.has(run.status) && (
          <div className="pt-2">
            <Spinner label="הסריקה רצה..." />
          </div>
        )}

        {run.error_message && (
          <div className="bg-accent-danger/10 border-2 border-accent-danger/40 rounded-lg p-4 space-y-2" role="alert">
            <p className="text-accent-danger font-bold text-sm">שגיאה:</p>
            <pre dir="ltr" className="text-xs font-mono text-accent-danger/90 whitespace-pre-wrap overflow-x-auto">
              {run.error_message}
            </pre>
          </div>
        )}

        {TERMINAL.has(run.status) && run.status !== "done" && (
          <div className="flex gap-3 pt-2">
            <button
              onClick={() => navigate("/")}
              className="px-4 py-2 bg-accent-primary text-surface-bg rounded font-bold hover:bg-accent-primary/80 transition-colors"
            >
              סריקה חדשה
            </button>
            {(run.summary?.total ?? 0) > 0 && (
              <button
                onClick={() => navigate(`/results/${id}`)}
                className="px-4 py-2 border border-surface-border text-text-secondary rounded hover:bg-surface-hover transition-colors"
              >
                הצג תוצאות חלקיות
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
