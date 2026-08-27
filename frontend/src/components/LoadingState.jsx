import "../styles/components/LoadingState.scss";

export default function LoadingState({
  title = "데이터를 불러오는 중입니다.",
  description = "잠시만 기다려 주세요.",
  compact = false,
}) {
  return (
    <div
      className={[
        "loading-state",
        compact
          ? "compact"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
      role="status"
      aria-live="polite"
    >
      <div
        className="spinner"
        aria-hidden="true"
      />

      <div className="state-content">
        <strong className="state-title">
          {title}
        </strong>

        {description && (
          <p className="state-description">
            {description}
          </p>
        )}
      </div>
    </div>
  );
}
