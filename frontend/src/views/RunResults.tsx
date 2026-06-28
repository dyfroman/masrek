import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { api, type RunDetail, type Finding, type DiffResponse, ApiError } from "../api";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import ModeBadge from "../components/ModeBadge";
import VerifiedBadge from "../components/VerifiedBadge";
import Spinner from "../components/Spinner";
import { OWASP_2025, OWASP_KEYS, OWASP_CHECKS } from "../owasp";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

type Tab = "findings" | "owasp" | "diff";

export default function RunResults() {
  const { id } = useParams<{ id: string }>();
  const [run, setRun] = useState<RunDetail | null>(null);
  const [diff, setDiff] = useState<DiffResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("findings");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [catFilter, setCatFilter] = useState<string>("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!id) return;
    api.getRun(id).then(setRun).catch((e) =>
      setError(e instanceof ApiError ? e.detail : "שגיאה"),
    );
    api.getDiff(id).then(setDiff).catch(() => {});
  }, [id]);

  if (error) return <p className="text-accent-danger mt-8 text-center">{error}</p>;
  if (!run) return <div className="mt-16 flex justify-center"><Spinner /></div>;

  const findings = run.findings ?? [];
  const summary = run.summary;

  // Filters
  const filtered = findings
    .filter((f) => sevFilter === "all" || f.severity === sevFilter)
    .filter((f) => catFilter === "all" || f.category === catFilter)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

  const toggle = (fid: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(fid)) next.delete(fid);
      else next.add(fid);
      return next;
    });
  };

  // OWASP breakdown
  const owaspCounts: Record<string, number> = {};
  for (const k of OWASP_KEYS) owaspCounts[k] = 0;
  for (const f of findings) {
    if (f.category in owaspCounts) owaspCounts[f.category]++;
  }

  const sevCounts: Record<string, number> = {};
  for (const f of findings) sevCounts[f.severity] = (sevCounts[f.severity] ?? 0) + 1;

  const isFailed = run.status === "failed" || run.status === "timeout";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold">תוצאות סריקה</h1>
          <p className="text-sm text-text-secondary font-mono mt-1" dir="ltr">
            {run.target_url}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={run.status} />
          <ModeBadge mode={run.mode} />
        </div>
      </div>

      {/* B1: Prominent error banner for failed/timeout runs */}
      {isFailed && (
        <div
          className="bg-accent-danger/10 border-2 border-accent-danger/40 rounded-lg p-5 space-y-2"
          role="alert"
        >
          <div className="flex items-center gap-2">
            <span className="text-accent-danger text-lg font-bold">
              {run.status === "timeout" ? "הסריקה חרגה מזמן המקסימום" : "הסריקה נכשלה"}
            </span>
          </div>
          {run.error_message && (
            <pre
              dir="ltr"
              className="text-sm font-mono text-accent-danger/90 whitespace-pre-wrap bg-surface-bg rounded p-3 border border-accent-danger/20 overflow-x-auto"
            >
              {run.error_message}
            </pre>
          )}
          <Link
            to="/"
            className="inline-block mt-2 px-4 py-2 bg-accent-primary text-surface-bg font-bold rounded hover:bg-accent-primary/80 transition-colors"
          >
            נסה שוב
          </Link>
        </div>
      )}

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
          <SummaryCard label="סה״כ" count={summary.total} color="text-text-primary" />
          <SummaryCard label="קריטי" count={summary.critical} color="text-sev-critical" />
          <SummaryCard label="גבוה" count={summary.high} color="text-sev-high" />
          <SummaryCard label="בינוני" count={summary.medium} color="text-sev-medium" />
          <SummaryCard label="נמוך" count={summary.low} color="text-sev-low" />
          <SummaryCard label="מידע" count={summary.info} color="text-sev-info" />
        </div>
      )}

      {/* Mapping confidence */}
      {findings.length > 0 && (() => {
        const fallbackCount = findings.filter(f => f.mapping === "fallback").length;
        const tagCount = findings.filter(f => f.mapping === "tag").length;
        if (fallbackCount === 0 && tagCount === 0) return null;
        return (
          <p className="text-xs text-text-muted">
            {fallbackCount > 0 && <span>{fallbackCount} ממצאים ללא מיפוי CWE מדויק (fallback) </span>}
            {tagCount > 0 && <span>{tagCount} ממופים לפי תגיות (tag) </span>}
          </p>
        );
      })()}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-surface-border" role="tablist">
        {([
          { key: "findings" as Tab, label: `ממצאים (${findings.length})` },
          { key: "owasp" as Tab, label: "OWASP Top 10" },
          { key: "diff" as Tab, label: "מה השתנה" },
        ]).map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-sm border-b-2 transition-colors ${
              tab === t.key
                ? "border-accent-primary text-accent-primary"
                : "border-transparent text-text-secondary hover:text-text-primary"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "findings" && (
        <FindingsTab
          findings={filtered}
          allFindings={findings}
          sevFilter={sevFilter}
          setSevFilter={setSevFilter}
          catFilter={catFilter}
          setCatFilter={setCatFilter}
          expanded={expanded}
          toggle={toggle}
          sevCounts={sevCounts}
        />
      )}

      {tab === "owasp" && (
        <OwaspTab
          counts={owaspCounts}
          selectedChecks={run.selected_checks}
          scanType={run.scan_type}
          runStatus={run.status}
          targetType={run.target_type}
        />
      )}

      {tab === "diff" && <DiffTab diff={diff} />}
    </div>
  );
}

// ── Summary card ─────────────────────────────────────────────────────────────

function SummaryCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="bg-surface-card border border-surface-border rounded p-4 text-center">
      <div className={`text-2xl font-bold font-mono ${color}`}>{count}</div>
      <div className="text-xs text-text-secondary mt-1">{label}</div>
    </div>
  );
}

// ── Findings tab ─────────────────────────────────────────────────────────────

function FindingsTab({
  findings,
  allFindings,
  sevFilter,
  setSevFilter,
  catFilter,
  setCatFilter,
  expanded,
  toggle,
  sevCounts,
}: {
  findings: Finding[];
  allFindings: Finding[];
  sevFilter: string;
  setSevFilter: (s: string) => void;
  catFilter: string;
  setCatFilter: (s: string) => void;
  expanded: Set<string>;
  toggle: (id: string) => void;
  sevCounts: Record<string, number>;
}) {
  const categories = [...new Set(allFindings.map((f) => f.category))].sort();

  if (allFindings.length === 0) {
    return (
      <div className="text-center py-16 text-text-muted">
        <p className="text-lg">לא נמצאו ממצאים</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-3 flex-wrap items-center">
        <label className="text-sm text-text-secondary">חומרה:</label>
        <select
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
          className="bg-surface-card border border-surface-border rounded px-3 py-1.5 text-sm text-text-primary"
          aria-label="סינון לפי חומרה"
        >
          <option value="all">הכל</option>
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
            <option key={s} value={s}>
              {s} ({sevCounts[s] ?? 0})
            </option>
          ))}
        </select>

        <label className="text-sm text-text-secondary">קטגוריה:</label>
        <select
          value={catFilter}
          onChange={(e) => setCatFilter(e.target.value)}
          className="bg-surface-card border border-surface-border rounded px-3 py-1.5 text-sm text-text-primary"
          aria-label="סינון לפי קטגוריית OWASP"
        >
          <option value="all">הכל</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c} — {OWASP_2025[c] ?? c}
            </option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="border border-surface-border rounded overflow-hidden">
        <table className="w-full text-sm" role="table">
          <thead>
            <tr className="bg-surface-panel text-text-secondary text-xs">
              <th className="px-4 py-3 text-right">חומרה</th>
              <th className="px-4 py-3 text-right">כותרת</th>
              <th className="px-4 py-3 text-right">קטגוריה</th>
              <th className="px-4 py-3 text-right hidden md:table-cell">מיקום</th>
              <th className="px-4 py-3 text-right hidden lg:table-cell">מקור</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <FindingRow
                key={f.id}
                finding={f}
                isExpanded={expanded.has(f.id)}
                onToggle={() => toggle(f.id)}
              />
            ))}
          </tbody>
        </table>
      </div>

      {findings.length === 0 && allFindings.length > 0 && (
        <p className="text-center text-text-muted text-sm py-4">
          אין תוצאות עבור הסינון הנוכחי
        </p>
      )}
    </div>
  );
}

function FindingRow({
  finding: f,
  isExpanded,
  onToggle,
}: {
  finding: Finding;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr
        className="border-t border-surface-border hover:bg-surface-hover cursor-pointer transition-colors"
        onClick={onToggle}
        tabIndex={0}
        onKeyDown={(e) => e.key === "Enter" && onToggle()}
        role="row"
        aria-expanded={isExpanded}
      >
        <td className="px-4 py-3">
          <SeverityBadge severity={f.severity} />
        </td>
        <td className="px-4 py-3 text-text-primary">{f.title}</td>
        <td className="px-4 py-3 font-mono text-xs text-text-secondary">{f.category}</td>
        <td className="px-4 py-3 hidden md:table-cell font-mono text-xs text-text-muted truncate max-w-[200px]" dir="ltr">
          {f.location}
        </td>
        <td className="px-4 py-3 hidden lg:table-cell font-mono text-xs text-text-muted">
          {f.source_tool}
        </td>
      </tr>
      {isExpanded && (
        <tr className="bg-surface-card">
          <td colSpan={5} className="px-6 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-text-muted text-xs block mb-1">מיקום</span>
                <code className="text-accent-primary text-xs font-mono break-all" dir="ltr">
                  {f.location}
                </code>
              </div>
              <div>
                <span className="text-text-muted text-xs block mb-1">אימות</span>
                <VerifiedBadge verified={f.verified} />
              </div>
              {f.evidence && (
                <div className="md:col-span-2">
                  <span className="text-text-muted text-xs block mb-1">עדות</span>
                  <pre
                    dir="ltr"
                    className="bg-surface-bg border border-surface-border rounded p-3 text-xs font-mono text-text-secondary overflow-x-auto whitespace-pre-wrap"
                  >
                    {f.evidence}
                  </pre>
                </div>
              )}
              {f.fix && (
                <div className="md:col-span-2">
                  <span className="text-text-muted text-xs block mb-1">תיקון מומלץ</span>
                  <div className="bg-accent-success/5 border border-accent-success/20 rounded p-3 text-xs text-accent-success">
                    {f.fix}
                  </div>
                </div>
              )}
              <div>
                <span className="text-text-muted text-xs block mb-1">כלי מקור</span>
                <span className="font-mono text-xs">{f.source_tool}</span>
              </div>
              <div>
                <span className="text-text-muted text-xs block mb-1">קטגוריה</span>
                <span className="text-xs">
                  {f.category} — {f.category_name}
                </span>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── OWASP tab ────────────────────────────────────────────────────────────────

const DETECT_LABELS: Record<string, { label: string; color: string }> = {
  full: { label: "כיסוי מלא", color: "text-accent-success" },
  partial: { label: "כיסוי חלקי", color: "text-accent-warning" },
  none: { label: "לא ניתן לבדיקה", color: "text-text-muted" },
};

function categoryStatus(
  count: number,
  detectability: string,
  isSelected: boolean,
  scanType: string | null,
  runStatus: string,
): { label: string; color: string } {
  if (!isSelected) return { label: "לא נבחר", color: "text-text-muted" };
  if (detectability === "none") return { label: "לא ניתן לבדיקה", color: "text-text-muted" };
  if (count > 0) return { label: `נמצאו ${count}`, color: "text-accent-danger" };
  if (runStatus === "timeout") return { label: "חלקי — חריגת זמן", color: "text-accent-warning" };
  if (scanType === "baseline") return { label: "חלקי — baseline", color: "text-accent-warning" };
  return { label: "נקי — נבדק", color: "text-accent-success" };
}

function OwaspTab({
  counts,
  selectedChecks,
  scanType,
  runStatus,
  targetType,
}: {
  counts: Record<string, number>;
  selectedChecks: string[] | null;
  scanType: string | null;
  runStatus: string;
  targetType: string;
}) {
  const maxCount = Math.max(...Object.values(counts), 1);
  const selectedSet = selectedChecks ? new Set(selectedChecks) : null;

  return (
    <div className="space-y-2">
      {OWASP_KEYS.map((key) => {
        const check = OWASP_CHECKS[key];
        const count = counts[key] ?? 0;
        const pct = (count / maxCount) * 100;
        const effectiveDetectability = targetType === "combined" ? check.combinedDetectability : targetType === "source" ? check.sastDetectability : check.detectability;
        const detect = DETECT_LABELS[effectiveDetectability];
        const isSelected = selectedSet ? selectedSet.has(check.id) : true;
        const status = categoryStatus(count, effectiveDetectability, isSelected, scanType, runStatus);

        return (
          <div key={key} className={`space-y-1 ${!isSelected ? "opacity-40" : ""}`}>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-text-muted w-20 shrink-0">
                {key}
              </span>
              <div className="flex-1 bg-surface-card rounded-full h-6 overflow-hidden border border-surface-border relative">
                <div
                  className={`h-full rounded-full transition-all ${
                    count > 0 ? "bg-accent-primary/60" : ""
                  }`}
                  style={{ width: `${pct}%` }}
                />
                <span className="absolute inset-0 flex items-center px-3 text-xs text-text-secondary">
                  {check.nameHe}
                </span>
              </div>
              <span className={`text-xs w-24 text-left ${status.color}`}>
                {status.label}
              </span>
              <span className={`text-xs w-20 text-left ${detect.color}`}>
                {isSelected ? detect.label : "—"}
              </span>
            </div>
            {isSelected && effectiveDetectability !== "full" && (
              <p className="text-xs text-text-muted mr-[5.5rem]">
                {targetType === "source" ? check.sastReasonHe : check.reasonHe}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Diff tab (D4) ────────────────────────────────────────────────────────────

function DiffTab({ diff }: { diff: DiffResponse | null }) {
  if (!diff) return <p className="text-text-muted text-sm py-8 text-center">טוען השוואה...</p>;

  if (diff.message || !diff.previous_run_id) {
    return (
      <p className="text-text-muted text-sm py-8 text-center">
        אין סריקה קודמת להשוואה עבור יעד זה.
      </p>
    );
  }

  const hasChanges = diff.new_findings.length > 0 || diff.resolved_findings.length > 0;

  return (
    <div className="space-y-6">
      {!hasChanges && (
        <p className="text-center text-text-muted py-8">
          לא זוהו שינויים. {diff.unchanged_count} ממצאים ללא שינוי.
        </p>
      )}

      {diff.new_findings.length > 0 && (
        <div>
          <h3 className="text-sm font-bold text-accent-danger mb-2">
            ממצאים חדשים ({diff.new_findings.length})
          </h3>
          <div className="space-y-1">
            {diff.new_findings.map((f, i) => (
              <div
                key={i}
                className="flex items-center gap-3 bg-accent-danger/5 border border-accent-danger/20 rounded px-4 py-2"
              >
                <span className="text-accent-danger text-xs">+</span>
                <SeverityBadge severity={f.severity} />
                <span className="text-sm">{f.title}</span>
                <span className="text-xs font-mono text-text-muted mr-auto" dir="ltr">
                  {f.location}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {diff.resolved_findings.length > 0 && (
        <div>
          <h3 className="text-sm font-bold text-accent-success mb-2">
            ממצאים שתוקנו ({diff.resolved_findings.length})
          </h3>
          <div className="space-y-1">
            {diff.resolved_findings.map((f, i) => (
              <div
                key={i}
                className="flex items-center gap-3 bg-accent-success/5 border border-accent-success/20 rounded px-4 py-2"
              >
                <span className="text-accent-success text-xs">-</span>
                <SeverityBadge severity={f.severity} />
                <span className="text-sm line-through opacity-60">{f.title}</span>
                <span className="text-xs font-mono text-text-muted mr-auto" dir="ltr">
                  {f.location}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {diff.unchanged_count > 0 && (
        <p className="text-text-muted text-sm text-center">
          {diff.unchanged_count} ממצאים ללא שינוי
        </p>
      )}
    </div>
  );
}
