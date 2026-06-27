const COLORS: Record<string, string> = {
  critical: "bg-sev-critical/20 text-sev-critical border-sev-critical/40",
  high: "bg-sev-high/20 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/20 text-sev-medium border-sev-medium/40",
  low: "bg-sev-low/20 text-sev-low border-sev-low/40",
  info: "bg-sev-info/20 text-sev-info border-sev-info/40",
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = COLORS[severity] ?? COLORS.info;
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded border text-xs font-mono uppercase ${cls}`}
      role="status"
      aria-label={`חומרה: ${severity}`}
    >
      {severity}
    </span>
  );
}
