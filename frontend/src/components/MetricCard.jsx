function clampPercent(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return 0;
  }

  return Math.min(
    Math.max(number, 0),
    100
  );
}

export default function MetricCard({
  label,
  value,
  unit,
  description,
  percentage,
  status = "default",
  unavailableText = "수집 정보 없음",
}) {
  const hasValue =
    value !== null &&
    value !== undefined &&
    value !== "";

  const safePercentage =
    percentage === null ||
    percentage === undefined
      ? null
      : clampPercent(percentage);

  return (
    <article
      className={[
        "metric-card",
        `metric-card-${status}`,
      ].join(" ")}
    >
      <div className="metric-card-header">
        <span className="metric-card-label">
          {label}
        </span>
      </div>

      <div className="metric-card-value-row">
        {hasValue ? (
          <>
            <strong className="metric-card-value">
              {value}
            </strong>

            {unit && (
              <span className="metric-card-unit">
                {unit}
              </span>
            )}
          </>
        ) : (
          <span className="metric-card-unavailable">
            {unavailableText}
          </span>
        )}
      </div>

      {safePercentage !== null && (
        <div
          className="metric-progress"
          aria-label={`${label} ${safePercentage}%`}
        >
          <div
            className="metric-progress-value"
            style={{
              width: `${safePercentage}%`,
            }}
          />
        </div>
      )}

      {description && (
        <p className="metric-card-description">
          {description}
        </p>
      )}
    </article>
  );
}