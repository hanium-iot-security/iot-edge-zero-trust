import "../styles/components/EmptyState.scss";

export default function EmptyState({
  title = "표시할 데이터가 없습니다.",
  description,
  actionLabel,
  onAction,
  compact = false,
}) {
  return (
    <div
      className={[
        "empty-state",
        compact
          ? "compact"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <div
        className="state-icon"
        aria-hidden="true"
      >
        —
      </div>

      <div className="state-content">
        <strong className="state-title">
          {title}
        </strong>

        {description && (
          <p className="state-description">
            {description}
          </p>
        )}

        {actionLabel && onAction && (
          <button
            type="button"
            className="button button-secondary"
            onClick={onAction}
          >
            {actionLabel}
          </button>
        )}
      </div>
    </div>
  );
}
