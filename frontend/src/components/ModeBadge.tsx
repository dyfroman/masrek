export default function ModeBadge({ mode }: { mode: string }) {
  const isActive = mode === "active";
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded border text-xs font-mono ${
        isActive
          ? "bg-accent-success/20 text-accent-success border-accent-success/40"
          : "bg-accent-warning/20 text-accent-warning border-accent-warning/40"
      }`}
      role="status"
      aria-label={`מצב: ${isActive ? "פעיל" : "פסיבי"}`}
    >
      {isActive ? "active" : "passive"}
    </span>
  );
}
