import "../styles/components/ErrorState.scss";

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
        "error-state",
        compact
          ? "compact"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
      role="alert"
    >
      <div
        className="state-icon"
        aria-hidden="true"
      >
        !
      </div>

      <div className="state-content">
        <strong className="state-title">
          {title}
        </strong>

        <p className="state-description">
          {message}
        </p>

        {onRetry && (
          <button
            type="button"
            className="retry-button"
            onClick={onRetry}
          >
            {retryLabel}
          </button>
        )}
      </div>
    </div>
  );
}
