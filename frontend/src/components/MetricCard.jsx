import "../styles/components/MetricCard.scss";

function clampPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return 0;
  }
  return Math.min(Math.max(number, 0), 100);
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

export default function MetricCard({
  label,
  value,
  unit,
  description,
  percentage,
  status = "default",
  unavailableText = "확인 불가",
  unavailable = false,
  updatedAt,
  stale = false,
}) {
  const hasValue =
    !unavailable &&
    value !== null &&
    value !== undefined &&
    value !== "";
  const safePercentage =
    !hasValue || percentage === null || percentage === undefined
      ? null
      : clampPercent(percentage);
  const updatedLabel = formatUpdatedAt(updatedAt);

  return (
    <article
      className={[
        "metric-card",
        `status-${unavailable ? "unavailable" : status}`,
        stale ? "is-stale" : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <div className="card-header">
        <span className="card-label">{label}</span>
        {stale && <span className="stale-badge">이전 값</span>}
      </div>
      <div className="value-row">
        {hasValue ? (
          <>
            <strong className="card-value">{value}</strong>
            {unit && <span className="unit">{unit}</span>}
          </>
        ) : (
          <span className="unavailable">{unavailableText}</span>
        )}
      </div>
      {safePercentage !== null && (
        <div className="progress" aria-label={`${label} ${safePercentage}%`}>
          <div
            className="progress-value"
            style={{ width: `${safePercentage}%` }}
          />
        </div>
      )}
      {description && <p className="description">{description}</p>}
      {updatedLabel && (
        <small className="last-success">
          최근 성공 {updatedLabel}
        </small>
      )}
    </article>
  );
}
