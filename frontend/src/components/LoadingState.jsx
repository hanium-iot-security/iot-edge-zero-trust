export default function LoadingState({
  title = "데이터를 불러오는 중입니다.",
  description = "잠시만 기다려 주세요.",
  compact = false,
}) {
  return (
    <div
      className={[
        "state-panel",
        "loading-state",
        compact
          ? "state-panel-compact"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
      role="status"
      aria-live="polite"
    >
      <div
        className="loading-spinner"
        aria-hidden="true"
      />

      <div className="state-panel-content">
        <strong className="state-panel-title">
          {title}
        </strong>

        {description && (
          <p className="state-panel-description">
            {description}
          </p>
        )}
      </div>
    </div>
  );
}