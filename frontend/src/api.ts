const BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

let _apiKey: string | null = localStorage.getItem("masrek_api_key");

export function setApiKey(key: string | null) {
  _apiKey = key;
  if (key) localStorage.setItem("masrek_api_key", key);
  else localStorage.removeItem("masrek_api_key");
}

export function getApiKey(): string | null {
  return _apiKey;
}

// ── Error types ──────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
  }
}

// ── Core fetch wrapper ───────────────────────────────────────────────────────

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string>),
  };
  if (_apiKey) headers["Authorization"] = `Bearer ${_apiKey}`;

  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "לא ניתן להתחבר לשרת. ודא שה-backend פעיל.");
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? JSON.stringify(body);
    } catch { /* use statusText */ }
    throw new ApiError(res.status, detail);
  }

  return res.json() as Promise<T>;
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface RunSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Run {
  run_id: string;
  target_url: string;
  target_host: string;
  mode: string;
  status: "queued" | "running" | "done" | "failed" | "timeout";
  created_at: string;
  completed_at: string | null;
  summary: RunSummary | null;
  error_message: string | null;
  selected_checks: string[] | null;
  scan_type: string | null;
  target_type: string;
  source_path: string | null;
}

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  category: string;
  category_name: string;
  location: string;
  evidence: string | null;
  verified: "yes" | "no" | "needs-manual";
  fix: string | null;
  source_tool: string;
  run_id: string;
  mapping: "exact" | "tag" | "fallback";
}

export interface RunDetail extends Run {
  findings: Finding[];
}

export interface ScopeInfo {
  allowlist: string[];
  safety: Record<string, unknown>;
}

export interface ScopeCheck {
  host: string;
  in_scope: boolean;
  allowed_mode: "active" | "passive";
}

export interface ScanResponse {
  run_id: string;
  target_url: string;
  mode: string;
  status: string;
}

export interface DiffResponse {
  current_run_id: string;
  previous_run_id: string | null;
  new_findings: DiffFinding[];
  resolved_findings: DiffFinding[];
  unchanged_count: number;
  message?: string;
}

export interface DiffFinding {
  severity: string;
  title: string;
  category: string;
  location: string;
}

// ── Endpoints ────────────────────────────────────────────────────────────────

export const api = {
  health: () => req<{ status: string }>("/health"),
  getScope: () => req<ScopeInfo>("/scope"),
  checkScope: (url: string) =>
    req<ScopeCheck>(`/scope/check?url=${encodeURIComponent(url)}`),
  scan: (
    target_url: string,
    mode: string = "auto",
    checks?: string[],
    scan_type: "baseline" | "full" = "baseline",
  ) =>
    req<ScanResponse>("/scan", {
      method: "POST",
      body: JSON.stringify({
        target_url,
        mode,
        scan_type,
        ...(checks && checks.length > 0 ? { checks } : {}),
      }),
    }),
  scanSource: (
    source_path: string,
    checks?: string[],
  ) =>
    req<ScanResponse>("/scan", {
      method: "POST",
      body: JSON.stringify({
        target_type: "source",
        source_path,
        ...(checks && checks.length > 0 ? { checks } : {}),
      }),
    }),
  scanCombined: (
    target_url: string,
    source_path: string,
    mode: string = "auto",
    checks?: string[],
    scan_type: "baseline" | "full" = "baseline",
  ) =>
    req<ScanResponse>("/scan", {
      method: "POST",
      body: JSON.stringify({
        target_type: "combined",
        target_url,
        source_path,
        mode,
        scan_type,
        ...(checks && checks.length > 0 ? { checks } : {}),
      }),
    }),
  listRuns: () => req<Run[]>("/runs"),
  getRun: (id: string) => req<RunDetail>(`/runs/${id}`),
  getDiff: (id: string) => req<DiffResponse>(`/runs/${id}/diff`),
};
