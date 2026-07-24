export default function ErrorState({
  title = "데이터를 불러오지 못했습니다.",
  message = "잠시 후 다시 시도해 주세요.",
  onRetry,
  retryLabel = "다시 시도",
  compact = false,
}) {
  return (
    <div
      className={[
        "state-panel",
        "error-state",
        compact
          ? "state-panel-compact"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
      role="alert"
    >
      <div
        className="state-panel-icon"
        aria-hidden="true"
      >
        !
      </div>

      <div className="state-panel-content">
        <strong className="state-panel-title">
          {title}
        </strong>

        <p className="state-panel-description">
          {message}
        </p>

        {onRetry && (
          <button
            type="button"
            className="button button-danger-outline"
            onClick={onRetry}
          >
            {retryLabel}
          </button>
        )}
      </div>
    </div>
  );
}