const STATUS_MAP: Record<string, { label: string; cls: string }> = {
  queued: { label: "בתור", cls: "bg-sev-info/20 text-sev-info border-sev-info/40" },
  running: { label: "פעיל", cls: "bg-accent-primary/20 text-accent-primary border-accent-primary/40" },
  done: { label: "הושלם", cls: "bg-accent-success/20 text-accent-success border-accent-success/40" },
  failed: { label: "נכשל", cls: "bg-accent-danger/20 text-accent-danger border-accent-danger/40" },
  timeout: { label: "חריגת זמן", cls: "bg-accent-warning/20 text-accent-warning border-accent-warning/40" },
};

export default function StatusBadge({ status }: { status: string }) {
  const s = STATUS_MAP[status] ?? STATUS_MAP.failed;
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded border text-xs font-mono ${s.cls}`}
      role="status"
      aria-label={`סטטוס: ${s.label}`}
    >
      {s.label}
    </span>
  );
}
