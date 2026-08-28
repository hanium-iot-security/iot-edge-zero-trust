import "../styles/components/MetricCard.scss";

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
        `status-${status}`,
      ].join(" ")}
    >
      <div className="card-header">
        <span className="card-label">
          {label}
        </span>
      </div>

      <div className="value-row">
        {hasValue ? (
          <>
            <strong className="card-value">
              {value}
            </strong>

            {unit && (
              <span className="unit">
                {unit}
              </span>
            )}
          </>
        ) : (
          <span className="unavailable">
            {unavailableText}
          </span>
        )}
      </div>

      {safePercentage !== null && (
        <div
          className="progress"
          aria-label={`${label} ${safePercentage}%`}
        >
          <div
            className="progress-value"
            style={{
              width: `${safePercentage}%`,
            }}
          />
        </div>
      )}

      {description && (
        <p className="description">
          {description}
        </p>
      )}
    </article>
  );
}
