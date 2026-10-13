import "../styles/components/SummaryCard.scss";

function normalizeStatus(status) {
  return String(status || "default")
    .trim()
    .toLowerCase()
    .replaceAll(" ", "_")
    .replaceAll("-", "_");
}

function formatUpdatedAt(value) {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

export default function SummaryCard({
  title,
  value,
  description,
  status = "default",
  icon,
  footer,
  onClick,
  unavailable = false,
  unavailableText = "확인 불가",
  updatedAt,
  stale = false,
}) {
  const interactive = typeof onClick === "function";
  const normalizedStatus = normalizeStatus(unavailable ? "unavailable" : status);
  const Element = interactive ? "button" : "article";
  const updatedLabel = formatUpdatedAt(updatedAt);

  return (
    <Element
      type={interactive ? "button" : undefined}
      className={[
        "summary-card",
        `status-${normalizedStatus}`,
        interactive ? "clickable" : "",
        stale ? "is-stale" : "",
      ]
        .filter(Boolean)
        .join(" ")}
      onClick={onClick}
    >
      <div className="card-header">
        <span className="card-title">{title}</span>
        <div className="card-header-meta">
          {stale && <span className="stale-badge">이전 값</span>}
          {icon && (
            <span className="card-icon" aria-hidden="true">
              {icon}
            </span>
          )}
        </div>
      </div>
      {unavailable ? (
        <span className="card-unavailable">{unavailableText}</span>
      ) : (
        <strong className="card-value">{value ?? "-"}</strong>
      )}
      {description && <p className="description">{description}</p>}
      {(footer || updatedLabel) && (
        <div className="footer">
          {footer}
          {updatedLabel && (
            <small className="last-success">
              최근 성공 {updatedLabel}
            </small>
          )}
        </div>
      )}
    </Element>
  );
}
