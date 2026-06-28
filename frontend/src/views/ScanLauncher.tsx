import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError, type ScopeCheck } from "../api";
import {
  OWASP_CHECKS,
  OWASP_KEYS,
  ALL_CHECK_IDS,
  QUICK_CHECK_IDS,
} from "../owasp";

type Preset = "quick" | "full" | "manual" | "custom";

const DETECT_BADGE: Record<string, { label: string; color: string }> = {
  full: { label: "מלא", color: "text-accent-success" },
  partial: { label: "חלקי", color: "text-accent-warning" },
  none: { label: "לא ניתן", color: "text-text-muted" },
};

export default function ScanLauncher() {
  const [targetType, setTargetType] = useState<"url" | "source" | "combined">("url");
  const [url, setUrl] = useState("https://juice-shop.herokuapp.com");
  const [sourcePath, setSourcePath] = useState("/app/source");
  const [scope, setScope] = useState<ScopeCheck | null>(null);
  const [scopeLoading, setScopeLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedChecks, setSelectedChecks] = useState<Set<string>>(
    new Set(ALL_CHECK_IDS),
  );
  const [preset, setPreset] = useState<Preset>("full");
  const [scanType, setScanType] = useState<"baseline" | "full">("baseline");
  const navigate = useNavigate();

  const checkScope = useCallback(async (target: string) => {
    if (!target.trim()) {
      setScope(null);
      return;
    }
    setScopeLoading(true);
    try {
      const result = await api.checkScope(target.trim());
      setScope(result);
    } catch {
      setScope(null);
    } finally {
      setScopeLoading(false);
    }
  }, []);

  useEffect(() => {
    if (targetType === "url" || targetType === "combined") {
      const timer = setTimeout(() => checkScope(url), 400);
      return () => clearTimeout(timer);
    }
    setScope(null);
  }, [url, targetType, checkScope]);

  const applyPreset = (p: Preset) => {
    setPreset(p);
    if (p === "quick") setSelectedChecks(new Set(QUICK_CHECK_IDS));
    else if (p === "full") setSelectedChecks(new Set(ALL_CHECK_IDS));
    else if (p === "manual") setSelectedChecks(new Set());
  };

  const toggleCheck = (id: string) => {
    setSelectedChecks((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setPreset("custom");
  };

  const handleScan = async () => {
    setError(null);
    setScanning(true);
    try {
      const checks = [...selectedChecks].sort();
      let res;
      if (targetType === "combined") {
        res = await api.scanCombined(url.trim(), sourcePath.trim(), "auto", checks, scanType);
      } else if (targetType === "source") {
        res = await api.scanSource(sourcePath.trim(), checks);
      } else {
        res = await api.scan(url.trim(), "auto", checks, scanType);
      }
      navigate(`/run/${res.run_id}`);
    } catch (e) {
      if (e instanceof ApiError) {
        setError(e.detail);
      } else {
        setError("שגיאה בלתי צפויה");
      }
      setScanning(false);
    }
  };

  const isPassive = scope && !scope.in_scope;

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold">סריקה חדשה</h1>

      {/* Target type toggle */}
      <div className="flex gap-3">
        {([
          { key: "url" as const, label: "URL (DAST)", desc: "סריקת יעד חי" },
          { key: "source" as const, label: "קוד מקור (SAST/SCA)", desc: "סריקת קוד מקור" },
          { key: "combined" as const, label: "משולב (DAST+SAST)", desc: "כיסוי מלא — URL + קוד" },
        ]).map((opt) => (
          <button
            key={opt.key}
            onClick={() => setTargetType(opt.key)}
            className={`flex-1 text-start px-4 py-3 rounded border transition-colors ${
              targetType === opt.key
                ? "bg-accent-primary/20 border-accent-primary"
                : "border-surface-border hover:border-text-muted"
            }`}
          >
            <span className={`block text-sm font-bold ${
              targetType === opt.key ? "text-accent-primary" : "text-text-secondary"
            }`}>
              {opt.label}
            </span>
            <span className="block text-xs text-text-muted mt-0.5">{opt.desc}</span>
          </button>
        ))}
      </div>

      {/* Target input */}
      <div className="space-y-2">
        {targetType === "combined" ? (
          <>
            <label htmlFor="target-url" className="block text-sm text-text-secondary">כתובת יעד (DAST)</label>
            <input
              id="target-url"
              type="url"
              dir="ltr"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://localhost:3000"
              className="w-full bg-surface-card border border-surface-border rounded px-4 py-2.5 text-text-primary font-mono text-sm placeholder:text-text-muted focus:border-accent-primary focus:outline-none transition-colors"
              aria-describedby="scope-status"
            />
            <label htmlFor="target-source" className="block text-sm text-text-secondary mt-2">נתיב קוד מקור (SAST)</label>
            <div className="flex gap-3">
              <input
                id="target-source"
                type="text"
                dir="ltr"
                value={sourcePath}
                onChange={(e) => setSourcePath(e.target.value)}
                placeholder="/app/source/vulnerable-app"
                className="flex-1 bg-surface-card border border-surface-border rounded px-4 py-2.5 text-text-primary font-mono text-sm placeholder:text-text-muted focus:border-accent-primary focus:outline-none transition-colors"
              />
              <button
                onClick={handleScan}
                disabled={scanning || !url.trim() || !sourcePath.trim() || selectedChecks.size === 0}
                className="px-6 py-2.5 bg-accent-primary text-surface-bg font-bold rounded hover:bg-accent-primary/80 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                aria-label="התחל סריקה משולבת"
              >
                {scanning ? "מפעיל..." : "סרוק"}
              </button>
            </div>
          </>
        ) : (
          <>
            <label htmlFor="target-input" className="block text-sm text-text-secondary">
              {targetType === "url" ? "כתובת יעד" : "נתיב קוד מקור"}
            </label>
            <div className="flex gap-3">
              {targetType === "url" ? (
                <input
                  id="target-input"
                  type="url"
                  dir="ltr"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="http://localhost:3000"
                  className="flex-1 bg-surface-card border border-surface-border rounded px-4 py-2.5 text-text-primary font-mono text-sm placeholder:text-text-muted focus:border-accent-primary focus:outline-none transition-colors"
                  aria-describedby="scope-status"
                />
              ) : (
                <input
                  id="target-input"
                  type="text"
                  dir="ltr"
                  value={sourcePath}
                  onChange={(e) => setSourcePath(e.target.value)}
                  placeholder="/app/source"
                  className="flex-1 bg-surface-card border border-surface-border rounded px-4 py-2.5 text-text-primary font-mono text-sm placeholder:text-text-muted focus:border-accent-primary focus:outline-none transition-colors"
                />
              )}
              <button
                onClick={handleScan}
                disabled={scanning || (targetType === "url" ? !url.trim() : !sourcePath.trim()) || selectedChecks.size === 0}
                className="px-6 py-2.5 bg-accent-primary text-surface-bg font-bold rounded hover:bg-accent-primary/80 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                aria-label="התחל סריקה"
              >
                {scanning ? "מפעיל..." : "סרוק"}
              </button>
            </div>
          </>
        )}
      </div>

      {/* Scope badge — driven ONLY by GET /scope/check (URL and combined modes) */}
      {(targetType === "url" || targetType === "combined") && <div id="scope-status" aria-live="polite">
        {scopeLoading && (
          <span className="text-sm text-text-muted">בודק הרשאה...</span>
        )}
        {!scopeLoading && scope && (
          <div
            className={`flex items-center gap-2 px-3 py-2 rounded border text-sm ${
              scope.in_scope
                ? "bg-accent-success/10 border-accent-success/30 text-accent-success"
                : "bg-accent-warning/10 border-accent-warning/30 text-accent-warning"
            }`}
          >
            <span className="font-mono text-xs">
              {scope.in_scope ? "●" : "◐"}
            </span>
            <span>
              {scope.in_scope
                ? "סריקה פעילה (Active) — היעד מורשה ב-SCOPE.md"
                : "פסיבי בלבד — היעד אינו מורשה לסריקה פעילה"}
            </span>
          </div>
        )}
      </div>}

      {/* Source mode info */}
      {targetType === "source" && (
        <div className="bg-accent-primary/5 border border-accent-primary/20 rounded p-3 text-sm text-text-secondary">
          סריקת SAST/SCA — ניתוח קוד מקור בלבד. הנתיב חייב להיות מותר ב-SCOPE.md (קריאה בלבד, ללא הרצת קוד).
        </div>
      )}

      {/* Combined mode info */}
      {targetType === "combined" && (
        <div className="bg-accent-success/5 border border-accent-success/20 rounded p-3 text-sm text-text-secondary">
          סריקה משולבת DAST+SAST — כיסוי מלא של OWASP Top 10. הכתובת חייבת להיות ב-SCOPE.md והנתיב חייב להיות מותר.
        </div>
      )}

      {/* Check selector */}
      <div className="bg-surface-card border border-surface-border rounded p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-bold text-text-primary">
            בדיקות OWASP Top 10
          </span>
          <div className="flex gap-2">
            {(
              [
                { key: "quick" as Preset, label: "מהיר (A01,A02,A05)" },
                { key: "full" as Preset, label: "מלא" },
                { key: "manual" as Preset, label: "ידני" },
              ] as const
            ).map((p) => (
              <button
                key={p.key}
                onClick={() => applyPreset(p.key)}
                className={`px-3 py-1 text-xs rounded border transition-colors ${
                  preset === p.key
                    ? "bg-accent-primary/20 border-accent-primary text-accent-primary"
                    : "border-surface-border text-text-secondary hover:border-text-muted"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-1">
          {OWASP_KEYS.map((key) => {
            const check = OWASP_CHECKS[key];
            const id = check.id;
            const checked = selectedChecks.has(id);
            const effectiveDetect = targetType === "combined" ? check.combinedDetectability : targetType === "source" ? check.sastDetectability : check.detectability;
            const badge = DETECT_BADGE[effectiveDetect];
            return (
              <label
                key={key}
                className={`flex items-center gap-3 px-3 py-2 rounded cursor-pointer transition-colors ${
                  checked
                    ? "bg-surface-hover"
                    : "opacity-50 hover:opacity-75"
                }`}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => toggleCheck(id)}
                  className="accent-accent-primary"
                />
                <span className="font-mono text-xs text-text-muted w-8 shrink-0">
                  {id}
                </span>
                <span className="text-sm text-text-primary flex-1">
                  {check.nameHe}
                </span>
                <span className={`text-xs ${badge.color}`}>{badge.label}</span>
              </label>
            );
          })}
        </div>

        <p className="text-xs text-text-muted">
          {selectedChecks.size} מתוך 10 בדיקות נבחרו
          {selectedChecks.size === 0 && " — בחר לפחות בדיקה אחת"}
        </p>
        {preset === "manual" && selectedChecks.size > 0 && (
          <p className="text-xs text-accent-primary">
            מצב ידני — קטגוריות שלא נבחרו יסומנו כ״לא נבחר״ בתוצאות
          </p>
        )}
      </div>

      {/* Scan type toggle (URL/DAST and combined mode) */}
      {(targetType === "url" || targetType === "combined") && <div className="bg-surface-card border border-surface-border rounded p-4 space-y-2">
        <span className="text-sm font-bold text-text-primary">עומק סריקה</span>
        <div className="flex gap-3 mt-2">
          {(
            [
              {
                key: "baseline" as const,
                label: "Baseline (~2 דק׳)",
                desc: "Spider + סריקה פסיבית — מהיר ואמין",
              },
              {
                key: "full" as const,
                label: "Full Active (עמוק, איטי)",
                desc: "סריקה פעילה מלאה — 20-40 דק׳ ומעלה",
              },
            ] as const
          ).map((opt) => (
            <button
              key={opt.key}
              onClick={() => setScanType(opt.key)}
              className={`flex-1 text-start px-4 py-3 rounded border transition-colors ${
                scanType === opt.key
                  ? "bg-accent-primary/20 border-accent-primary"
                  : "border-surface-border hover:border-text-muted"
              }`}
            >
              <span
                className={`block text-sm font-bold ${
                  scanType === opt.key
                    ? "text-accent-primary"
                    : "text-text-secondary"
                }`}
              >
                {opt.label}
              </span>
              <span className="block text-xs text-text-muted mt-0.5">
                {opt.desc}
              </span>
            </button>
          ))}
        </div>
      </div>}

      {/* Passive-only banner */}
      {(targetType === "url" || targetType === "combined") && isPassive && (
        <div className="bg-surface-card border border-surface-border rounded p-4 space-y-2">
          <p className="text-sm text-text-secondary">
            רק בדיקות לא-פולשניות ירוצו (כותרות HTTP, TLS, robots.txt).
            לסריקה מלאה עם ZAP, nuclei ו-nikto, הפעל מופע מקומי:
          </p>
          <pre
            dir="ltr"
            className="bg-surface-bg border border-surface-border rounded p-3 text-xs font-mono text-accent-primary overflow-x-auto"
          >
            docker run --rm -d -p 3000:3000 bkimminich/juice-shop{"\n"}
            # ואז סרוק: http://localhost:3000
          </pre>
        </div>
      )}

      {/* Error */}
      {error && (
        <div
          className="bg-accent-danger/10 border border-accent-danger/30 text-accent-danger rounded p-3 text-sm"
          role="alert"
        >
          {error}
        </div>
      )}
    </div>
  );
}
