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
        "state-panel",
        "empty-state",
        compact
          ? "state-panel-compact"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <div
        className="state-panel-icon"
        aria-hidden="true"
      >
        —
      </div>

      <div className="state-panel-content">
        <strong className="state-panel-title">
          {title}
        </strong>

        {description && (
          <p className="state-panel-description">
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