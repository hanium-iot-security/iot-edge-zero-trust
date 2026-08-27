import "../styles/components/StatusBadge.scss";

const STATUS_LABELS = {
  normal: "정상",
  warning: "주의",
  danger: "위험",
  isolated: "격리",

  online: "ONLINE",
  stale: "STALE",
  offline: "OFFLINE",
  no_data: "NO DATA",
  api_error: "API ERROR",

  pending: "PENDING",
  applied: "APPLIED",
  failed: "FAILED",
  removed: "REMOVED",

  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  critical: "CRITICAL",

  eligible: "분석 가능",
  excluded: "분석 제외",
  degraded: "DEGRADED",

  processed: "PROCESSED",
  captured: "CAPTURED",

  scored: "감점 반영",
  unscored: "미반영",

  inbound: "INBOUND",
  outbound: "OUTBOUND",

  connected: "연결됨",
  down: "DOWN",
  missing: "미인식",

  rule: "RULE",
  ai: "AI",

  unknown: "UNKNOWN",
};

const DOT_STATUSES = new Set([
  "normal",
  "warning",
  "danger",
  "isolated",

  "online",
  "stale",
  "offline",
  "no_data",
  "api_error",

  "pending",
  "applied",
  "removed",

  "down",
  "missing",
]);

function normalizeStatus(status) {
  return String(status || "unknown")
    .trim()
    .toLowerCase()
    .replaceAll(" ", "_")
    .replaceAll("-", "_");
}

export default function StatusBadge({
  status,
  label,
  size = "medium",
  title,
}) {
  const normalizedStatus =
    normalizeStatus(status);

  const displayLabel =
    label ||
    STATUS_LABELS[normalizedStatus] ||
    String(status || "UNKNOWN");

  const showDot =
    DOT_STATUSES.has(normalizedStatus);

  return (
    <span
      className={[
        "status-badge",
        `status-${normalizedStatus}`,
        `size-${size}`,
      ].join(" ")}
      title={title}
    >
      {showDot && (
        <span
          className="dot"
          aria-hidden="true"
        />
      )}

      <span>{displayLabel}</span>
    </span>
  );
}
