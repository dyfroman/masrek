import { useState, useEffect } from "react";
import { api, getApiKey, setApiKey, ApiError } from "../api";

export default function Settings() {
  const [key, setKey] = useState(getApiKey() ?? "");
  const [saved, setSaved] = useState(false);
  const [health, setHealth] = useState<string | null>(null);

  useEffect(() => {
    api
      .health()
      .then(() => setHealth("ok"))
      .catch((e) =>
        setHealth(e instanceof ApiError ? `שגיאה ${e.status}` : "לא זמין"),
      );
  }, []);

  const handleSave = () => {
    setApiKey(key.trim() || null);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="max-w-xl mx-auto space-y-8">
      <h1 className="text-2xl font-bold">הגדרות</h1>

      {/* Backend health */}
      <div className="bg-surface-card border border-surface-border rounded p-4 flex items-center justify-between">
        <span className="text-sm text-text-secondary">חיבור ל-Backend</span>
        <span
          className={`text-sm font-mono ${
            health === "ok" ? "text-accent-success" : "text-accent-danger"
          }`}
        >
          {health === "ok" ? "מחובר" : health ?? "בודק..."}
        </span>
      </div>

      {/* API key */}
      <div className="bg-surface-card border border-surface-border rounded p-4 space-y-3">
        <label htmlFor="api-key" className="block text-sm text-text-secondary">
          מפתח API (נדרש כאשר אימות מופעל)
        </label>
        <div className="flex gap-3">
          <input
            id="api-key"
            type="password"
            dir="ltr"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="Bearer token"
            className="flex-1 bg-surface-bg border border-surface-border rounded px-4 py-2 text-text-primary font-mono text-sm placeholder:text-text-muted focus:border-accent-primary focus:outline-none"
          />
          <button
            onClick={handleSave}
            className="px-4 py-2 bg-accent-primary text-surface-bg font-bold rounded hover:bg-accent-primary/80 transition-colors"
          >
            {saved ? "נשמר!" : "שמור"}
          </button>
        </div>
        <p className="text-xs text-text-muted">
          ב-compose לפיתוח (MASREK_AUTH_DISABLED=1) אין צורך במפתח.
          בסביבת production, הגדר MASREK_API_KEY והזן אותו כאן.
        </p>
      </div>
    </div>
  );
}
