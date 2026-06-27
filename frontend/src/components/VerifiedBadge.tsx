const MAP: Record<string, { label: string; cls: string }> = {
  yes: { label: "מאומת", cls: "text-accent-success" },
  no: { label: "לא מאומת", cls: "text-text-muted" },
  "needs-manual": { label: "דורש בדיקה ידנית", cls: "text-accent-warning" },
};

export default function VerifiedBadge({ verified }: { verified: string }) {
  const v = MAP[verified] ?? MAP.no;
  return (
    <span className={`text-xs font-mono ${v.cls}`} aria-label={v.label}>
      {v.label}
    </span>
  );
}
