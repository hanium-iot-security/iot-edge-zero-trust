import "../styles/components/PageHeader.scss";

export default function PageHeader({
  title,
  description,
  updatedAt,
  onRefresh,
  refreshing = false,
  actions,
}) {
  return (
    <header className="page-header">
      <div className="header-content">
        <div className="title-row">
          <h1 className="page-title">
            {title}
          </h1>

          {updatedAt && (
            <span className="updated-at">
              최근 업데이트: {updatedAt}
            </span>
          )}
        </div>

        {description && (
          <p className="description">
            {description}
          </p>
        )}
      </div>

      <div className="header-actions">
        {actions}

        {onRefresh && (
          <button
            type="button"
            className="button button-secondary"
            onClick={onRefresh}
            disabled={refreshing}
          >
            {refreshing
              ? "새로고침 중..."
              : "새로고침"}
          </button>
        )}
      </div>
    </header>
  );
}
